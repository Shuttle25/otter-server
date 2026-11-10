package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
)

const (
	PrekeySigned  = 1
	PrekeyKyber   = 2
	PrekeyOneTime = 3
	tombstoneTTL  = 30 * 24 * time.Hour
)

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// applyTyped maintains derived tables. Runs inside the request savepoint.
// NOTE (M2): replicated records must apply leniently (e.g. INVITE_USED for an invite already used
// elsewhere); M2 introduces conflict rules — M1 has a single node.
func applyTyped(ctx context.Context, tx *sql.Tx, it item, now int64) error {
	b := it.body
	switch b.Type {
	case pb.RecordType_DIRECTORY_ENTRY:
		var e pb.DirectoryEntry
		if err := proto.Unmarshal(b.Payload, &e); err != nil {
			return err
		}
		var owner []byte
		err := tx.QueryRowContext(ctx, `SELECT user_id FROM users WHERE username=?`, e.Username).Scan(&owner)
		if err == nil && !bytes.Equal(owner, e.UserId) {
			return ErrUsernameTaken
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var cur uint64
		err = tx.QueryRowContext(ctx, `SELECT version FROM users WHERE user_id=?`, e.UserId).Scan(&cur)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			_, err = tx.ExecContext(ctx,
				`INSERT INTO users(user_id,username,account_pub,entry_key,version,can_invite,created_ms) VALUES(?,?,?,?,?,?,?)`,
				e.UserId, e.Username, e.AccountPub, it.key, e.Version, boolInt(e.CanInvite), now)
		case err != nil:
		case e.Version > cur:
			_, err = tx.ExecContext(ctx, `UPDATE users SET username=?, entry_key=?, version=? WHERE user_id=?`,
				e.Username, it.key, e.Version, e.UserId)
		}
		return err

	case pb.RecordType_INVITE:
		var i pb.Invite
		if err := proto.Unmarshal(b.Payload, &i); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO invites(invite_id,inviter,expires_ms) VALUES(?,?,?)`,
			i.InviteId, b.Author, i.ExpiresMs)
		return err

	case pb.RecordType_INVITE_USED:
		var u pb.InviteUsed
		if err := proto.Unmarshal(b.Payload, &u); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE invites SET used_by=? WHERE invite_id=? AND used_by IS NULL AND expires_ms>?`,
			u.UserId, u.InviteId, now)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrInviteUnavailable
		}
		return nil

	case pb.RecordType_PREKEYS:
		var p pb.PreKeys
		if err := proto.Unmarshal(b.Payload, &p); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO devices(user_id,device_id,registration_id) VALUES(?,?,?)
			 ON CONFLICT(user_id,device_id) DO UPDATE SET registration_id=excluded.registration_id`,
			b.Author, p.DeviceId, p.RegistrationId); err != nil {
			return err
		}
		put := func(kind int, k *pb.SignedPreKey) error {
			if k == nil {
				return nil
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM prekeys WHERE user_id=? AND device_id=? AND kind=?`, b.Author, p.DeviceId, kind); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx,
				`INSERT INTO prekeys(user_id,device_id,key_id,kind,owner_node,public,signature) VALUES(?,?,?,?,NULL,?,?)`,
				b.Author, p.DeviceId, k.Id, kind, k.PublicKey, k.Signature)
			return err
		}
		if err := put(PrekeySigned, p.SignedPrekey); err != nil {
			return err
		}
		if err := put(PrekeyKyber, p.KyberPrekey); err != nil {
			return err
		}
		for _, k := range p.OneTime {
			if _, err := tx.ExecContext(ctx,
				`INSERT OR IGNORE INTO prekeys(user_id,device_id,key_id,kind,owner_node,public) VALUES(?,?,?,?,?,?)`,
				b.Author, p.DeviceId, k.Id, PrekeyOneTime, k.OwnerNode, k.PublicKey); err != nil {
				return err
			}
		}
		return nil

	case pb.RecordType_ENVELOPE:
		var e pb.Envelope
		if err := proto.Unmarshal(b.Payload, &e); err != nil {
			return err
		}
		for _, r := range e.Recipients {
			var x int
			err := tx.QueryRowContext(ctx, `SELECT 1 FROM tombstones WHERE record_key=? AND user_id=? AND device_id=?`,
				it.key, r.User, r.Device).Scan(&x)
			if err == nil {
				continue
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT OR IGNORE INTO mailbox(user_id,device_id,record_key,origin_node,received_ms) VALUES(?,?,?,?,?)`,
				r.User, r.Device, it.key, it.origin, now); err != nil {
				return err
			}
		}
		return nil

	case pb.RecordType_ACK:
		var a pb.Ack
		if err := proto.Unmarshal(b.Payload, &a); err != nil {
			return err
		}
		dev := a.DeviceId
		if dev == 0 {
			dev = 1
		}
		until := now + tombstoneTTL.Milliseconds()
		for _, k := range a.EnvelopeIds {
			if _, err := tx.ExecContext(ctx, `DELETE FROM mailbox WHERE user_id=? AND device_id=? AND record_key=?`, b.Author, dev, k); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO tombstones(record_key,user_id,device_id,until_ms) VALUES(?,?,?,?)`,
				k, b.Author, dev, until); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx,
				`DELETE FROM records WHERE record_key=? AND type=? AND NOT EXISTS (SELECT 1 FROM mailbox WHERE record_key=?)`,
				k, int32(pb.RecordType_ENVELOPE), k); err != nil {
				return err
			}
		}
		return nil

	case pb.RecordType_MANIFEST:
		var m pb.Manifest
		if err := proto.Unmarshal(b.Payload, &m); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO manifest(version,raw) VALUES(?,?)`, m.Version, it.raw)
		return err
	}
	return nil
}
