package store

import (
	"context"
	"database/sql"
	"errors"

	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

type User struct {
	ID         []byte
	Username   string
	AccountPub []byte
	Version    uint64
	Revoked    bool
	CanInvite  bool
	EntryRaw   []byte // serialized pb.Record of the current DIRECTORY_ENTRY
	// UsernameConflict: the user lost a replicated username clash; Username is "<original>#<hex>".
	UsernameConflict bool
}

type InviteState struct {
	Inviter   []byte
	ExpiresMs int64
	UsedBy    []byte
}

type MailboxEntry struct {
	Key []byte
	Raw []byte // serialized pb.Record
}

type PrekeyRows struct {
	RegistrationID uint32
	Signed, Kyber  *pb.SignedPreKey
	OneTime        *pb.OneTimePreKey
	RemainingOwn   int
}

// UserKey implements records.UserResolver.
func (s *Store) UserKey(id []byte) (records.UserKey, bool) {
	var pub []byte
	var revoked int
	if err := s.r.QueryRow(`SELECT account_pub, revoked FROM users WHERE user_id=?`, id).Scan(&pub, &revoked); err != nil {
		return records.UserKey{}, false
	}
	return records.UserKey{Pub: pub, Revoked: revoked != 0}, true
}

// UserByID returns nil, nil when the user does not exist.
func (s *Store) UserByID(ctx context.Context, id []byte) (*User, error) {
	u := &User{ID: id}
	var revoked, canInvite, conflict int
	err := s.r.QueryRowContext(ctx,
		`SELECT u.username, u.account_pub, u.version, u.revoked, u.can_invite, u.username_conflict, r.raw
		 FROM users u JOIN records r ON r.record_key=u.entry_key WHERE u.user_id=?`, id).
		Scan(&u.Username, &u.AccountPub, &u.Version, &revoked, &canInvite, &conflict, &u.EntryRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.Revoked, u.CanInvite, u.UsernameConflict = revoked != 0, canInvite != 0, conflict != 0
	return u, nil
}

// UsernameOwner returns nil, nil when the username is free.
func (s *Store) UsernameOwner(ctx context.Context, username string) ([]byte, error) {
	var id []byte
	err := s.r.QueryRowContext(ctx, `SELECT user_id FROM users WHERE username=?`, username).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return id, err
}

// DirectoryEntries returns current DIRECTORY_ENTRY records (serialized), oldest member first.
func (s *Store) DirectoryEntries(ctx context.Context) ([][]byte, error) {
	rows, err := s.r.QueryContext(ctx,
		`SELECT r.raw FROM users u JOIN records r ON r.record_key=u.entry_key ORDER BY u.created_ms, u.user_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}

func (s *Store) Invite(ctx context.Context, id []byte) (*InviteState, error) {
	var st InviteState
	err := s.r.QueryRowContext(ctx, `SELECT inviter, expires_ms, used_by FROM invites WHERE invite_id=?`, id).
		Scan(&st.Inviter, &st.ExpiresMs, &st.UsedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &st, err
}

// Mailbox returns pending envelopes for a device, oldest first. Envelopes whose record expires_ms has passed
// (short-lived call signaling, D78) are skipped; the janitor deletes them.
func (s *Store) Mailbox(ctx context.Context, user []byte, device uint32, limit int) ([]MailboxEntry, error) {
	return s.mailboxAt(ctx, user, device, limit, s.now().UnixMilli())
}

func (s *Store) mailboxAt(ctx context.Context, user []byte, device uint32, limit int, now int64) ([]MailboxEntry, error) {
	rows, err := s.r.QueryContext(ctx,
		`SELECT m.record_key, r.raw FROM mailbox m JOIN records r ON r.record_key=m.record_key
		 WHERE m.user_id=? AND m.device_id=? AND (r.expires_ms = 0 OR r.expires_ms > ?)
		 ORDER BY m.received_ms, m.record_key LIMIT ?`, user, device, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MailboxEntry
	for rows.Next() {
		var e MailboxEntry
		if err := rows.Scan(&e.Key, &e.Raw); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// TakePrekeys returns a bundle's key material and consumes one one-time key owned by node.
func (s *Store) TakePrekeys(ctx context.Context, user []byte, device uint32, node []byte) (*PrekeyRows, error) {
	out := &PrekeyRows{}
	err := s.write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `SELECT registration_id FROM devices WHERE user_id=? AND device_id=?`, user, device).
			Scan(&out.RegistrationID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		get := func(kind int) (*pb.SignedPreKey, error) {
			k := &pb.SignedPreKey{}
			err := tx.QueryRowContext(ctx, `SELECT key_id, public, signature FROM prekeys WHERE user_id=? AND device_id=? AND kind=?`,
				user, device, kind).Scan(&k.Id, &k.PublicKey, &k.Signature)
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrNotFound
			}
			return k, err
		}
		if out.Signed, err = get(PrekeySigned); err != nil {
			return err
		}
		if out.Kyber, err = get(PrekeyKyber); err != nil {
			return err
		}
		ot := &pb.OneTimePreKey{OwnerNode: node}
		err = tx.QueryRowContext(ctx,
			`SELECT key_id, public FROM prekeys WHERE user_id=? AND device_id=? AND kind=? AND owner_node=? AND consumed=0
			 ORDER BY key_id LIMIT 1`, user, device, PrekeyOneTime, node).Scan(&ot.Id, &ot.PublicKey)
		switch {
		case err == nil:
			if _, err := tx.ExecContext(ctx, `UPDATE prekeys SET consumed=1 WHERE user_id=? AND device_id=? AND kind=? AND key_id=?`,
				user, device, PrekeyOneTime, ot.Id); err != nil {
				return err
			}
			out.OneTime = ot
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
		return tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM prekeys WHERE user_id=? AND device_id=? AND kind=? AND owner_node=? AND consumed=0`,
			user, device, PrekeyOneTime, node).Scan(&out.RemainingOwn)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// LatestManifest returns ErrNotFound when no manifest has been imported.
func (s *Store) LatestManifest(ctx context.Context) (uint64, []byte, error) {
	var v uint64
	var raw []byte
	err := s.r.QueryRowContext(ctx, `SELECT version, raw FROM manifest ORDER BY version DESC LIMIT 1`).Scan(&v, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, ErrNotFound
	}
	return v, raw, err
}

// RecordKeys lists all stored record keys in order (for convergence checks in tests and diagnostics).
func (s *Store) RecordKeys(ctx context.Context) ([][]byte, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT record_key FROM records ORDER BY record_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var k []byte
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
