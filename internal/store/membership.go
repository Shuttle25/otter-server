package store

import (
	"context"
	"database/sql"
	"errors"

	pb "ottermsg/server/internal/proto/otterv1"
)

// ReasonDuplicateInvite is users.revoke_reason of an account that lost a double redemption (D102).
const ReasonDuplicateInvite = "duplicate invite"

// Admission is what the service derived from a new account's invite chain (D100). Invite rights are not part of it:
// every member may invite unless the admin withdrew it with INVITE_RIGHTS (D101 as changed by the owner, 2026-11-15).
type Admission struct {
	InviteID []byte // nil for founding members
	Rank     []byte // SHA-256(invite_proof): the lowest keeps a doubly redeemed invite (D102)
	RankMs   int64  // username clash rank: the INVITE's created_ms, or registered_ms of a founding member (D103)
}

// rightsNow is the user's current invite right: the newest INVITE_RIGHTS version ("no" wins a tie), else yes (D101).
const rightsNow = `COALESCE((SELECT can_invite FROM invite_rights WHERE user_id=?1
	ORDER BY version DESC, can_invite ASC LIMIT 1), 1)`

// revokeUser disables an account on this node: no login, no queued mail, no new sessions with it, no wake-ups.
func revokeUser(ctx context.Context, tx *sql.Tx, user []byte, reason string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE users SET revoked=1, revoke_reason=? WHERE user_id=? AND revoked=0`, reason, user); err != nil {
		return err
	}
	for _, q := range []string{`DELETE FROM mailbox WHERE user_id=?`, `DELETE FROM prekeys WHERE user_id=?`,
		`DELETE FROM push_tokens WHERE user_id=?`} {
		if _, err := tx.ExecContext(ctx, q, user); err != nil {
			return err
		}
	}
	return nil
}

// applyRevocation stores a network-signed REVOCATION (D99). Several revocations of one user: the earliest time (and
// its reason) counts, because it decides which of the user's invites still count. A user not known yet is revoked
// when the entry arrives (insertUser).
func applyRevocation(ctx context.Context, tx *sql.Tx, b *pb.RecordBody, r *pb.Revocation) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO revocations(user_id,created_ms,reason) VALUES(?,?,?)
		ON CONFLICT(user_id) DO UPDATE SET
		  reason=CASE WHEN excluded.created_ms < created_ms THEN excluded.reason ELSE reason END,
		  created_ms=MIN(created_ms, excluded.created_ms)`, r.UserId, b.CreatedMs, r.Reason); err != nil {
		return err
	}
	var reason string
	if err := tx.QueryRowContext(ctx, `SELECT reason FROM revocations WHERE user_id=?`, r.UserId).Scan(&reason); err != nil {
		return err
	}
	return revokeUser(ctx, tx, r.UserId, reason)
}

// applyInviteRights stores a network-signed INVITE_RIGHTS (D99, D101): the highest version wins in any arrival order;
// equal versions with different values resolve to "no". Rights for a user not known yet apply when the entry arrives.
func applyInviteRights(ctx context.Context, tx *sql.Tx, b *pb.RecordBody, r *pb.InviteRights) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO invite_rights(user_id,version,can_invite,created_ms) VALUES(?,?,?,?)
		ON CONFLICT(user_id,version,can_invite) DO UPDATE SET created_ms=MIN(created_ms, excluded.created_ms)`,
		r.UserId, r.Version, boolInt(r.CanInvite), b.CreatedMs); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE users SET can_invite=`+rightsNow+` WHERE user_id=?1`, r.UserId)
	return err
}

// RevokedAt returns the created_ms of the user's (earliest) revocation.
func (s *Store) RevokedAt(ctx context.Context, user []byte) (int64, bool, error) {
	var at int64
	err := s.r.QueryRowContext(ctx, `SELECT created_ms FROM revocations WHERE user_id=?`, user).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return at, err == nil, err
}

// CanInviteAt reports the user's invite rights as of atMs: the newest INVITE_RIGHTS version created at or before atMs
// ("no" wins a tie), else yes, the default of every member (D101). Unknown user: false. Revocation is not considered
// here (see RevokedAt).
func (s *Store) CanInviteAt(ctx context.Context, user []byte, atMs int64) (bool, error) {
	var v int
	err := s.r.QueryRowContext(ctx, `SELECT COALESCE(
		(SELECT can_invite FROM invite_rights WHERE user_id=?1 AND created_ms<=?2 ORDER BY version DESC, can_invite ASC LIMIT 1), 1)
		FROM users WHERE user_id=?1`, user, atMs).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return v != 0, err
}

// RevokedUsers lists every revoked or disabled account (TURN refusal, session closing).
func (s *Store) RevokedUsers(ctx context.Context) ([][]byte, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT user_id FROM users WHERE revoked=1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var id []byte
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// MembershipRecords returns every stored REVOCATION and INVITE_RIGHTS (serialized), oldest first, for directory.sync.
func (s *Store) MembershipRecords(ctx context.Context) ([][]byte, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT raw FROM records WHERE type IN (?,?) ORDER BY created_ms, record_key`,
		int32(pb.RecordType_REVOCATION), int32(pb.RecordType_INVITE_RIGHTS))
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

// insertUser creates the account row with the state the network-signed records give it (D99, D101): revoked if a
// REVOCATION arrived first, invite rights from INVITE_RIGHTS or the default, never from DirectoryEntry.can_invite (C6).
func insertUser(ctx context.Context, tx *sql.Tx, it item, e *pb.DirectoryEntry, name string, conflict int, rank, now int64) error {
	revoked, reason := false, ""
	err := tx.QueryRowContext(ctx, `SELECT reason FROM revocations WHERE user_id=?`, e.UserId).Scan(&reason)
	switch {
	case err == nil:
		revoked = true
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO users(user_id,username,account_pub,entry_key,version,can_invite,created_ms,entry_created_ms,username_conflict)
		 VALUES(?1,?2,?3,?4,?5,`+rightsNow+`,?6,?7,?8)`,
		e.UserId, name, e.AccountPub, it.key, e.Version, now, rank, conflict); err != nil {
		return err
	}
	if revoked {
		return revokeUser(ctx, tx, e.UserId, reason)
	}
	return nil
}
