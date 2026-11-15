package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
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

// raiseInstall applies an install time to a (user, device) (D52): a newer install deletes the device's prekeys and
// stores its registration id; an equal one updates the row; an older one changes nothing and returns false.
func raiseInstall(ctx context.Context, tx *sql.Tx, user []byte, device, rid uint32, inst int64) (bool, error) {
	var cur int64
	err := tx.QueryRowContext(ctx, `SELECT installed_ms FROM devices WHERE user_id=? AND device_id=?`, user, device).Scan(&cur)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	switch {
	case exists && inst < cur:
		return false, nil // an older install (a phone that was replaced): its keys must not be handed out
	case exists && inst > cur:
		if _, err := tx.ExecContext(ctx, `DELETE FROM prekeys WHERE user_id=? AND device_id=?`, user, device); err != nil {
			return false, err
		}
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO devices(user_id,device_id,registration_id,installed_ms) VALUES(?,?,?,?)
		 ON CONFLICT(user_id,device_id) DO UPDATE SET registration_id=excluded.registration_id, installed_ms=excluded.installed_ms`,
		user, device, rid, inst)
	return err == nil, err
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
		return applyDirectoryEntry(ctx, tx, it, &e, b.CreatedMs, now)

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
		if n, _ := res.RowsAffected(); n == 0 && !it.fromPeer {
			return ErrInviteUnavailable // replicated: the first used_by wins, the record is still stored
		}
		return nil

	case pb.RecordType_PREKEYS:
		var p pb.PreKeys
		if err := proto.Unmarshal(b.Payload, &p); err != nil {
			return err
		}
		if ok, err := raiseInstall(ctx, tx, b.Author, p.DeviceId, p.RegistrationId, p.InstalledMs); err != nil || !ok {
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

	case pb.RecordType_INSTALL: // C14: newest (installed_ms, registration_id) per user; raises device 1 like PREKEYS
		var in pb.Install
		if err := proto.Unmarshal(b.Payload, &in); err != nil {
			return err
		}
		var curKey []byte
		var curInst int64
		var curRid uint32
		err := tx.QueryRowContext(ctx, `SELECT record_key, installed_ms, registration_id FROM installs WHERE user_id=?`,
			b.Author).Scan(&curKey, &curInst, &curRid)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil && (in.InstalledMs < curInst || (in.InstalledMs == curInst && in.RegistrationId <= curRid)) {
			_, err := tx.ExecContext(ctx, `DELETE FROM records WHERE record_key=?`, it.key) // older or the same install
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR REPLACE INTO installs(user_id,record_key,installed_ms,registration_id) VALUES(?,?,?,?)`,
			b.Author, it.key, in.InstalledMs, in.RegistrationId); err != nil {
			return err
		}
		if curKey != nil {
			if _, err := tx.ExecContext(ctx, `DELETE FROM records WHERE record_key=?`, curKey); err != nil {
				return err
			}
		}
		_, err = raiseInstall(ctx, tx, b.Author, 1, in.RegistrationId, in.InstalledMs)
		return err

	case pb.RecordType_PUSH_TOKEN: // D60: newest created_ms per (user, device) wins, ties by record key
		var p pb.PushToken
		if err := proto.Unmarshal(b.Payload, &p); err != nil {
			return err
		}
		var curCreated int64
		var curKey []byte
		err := tx.QueryRowContext(ctx, `SELECT created_ms, record_key FROM push_tokens WHERE user_id=? AND device_id=?`,
			b.Author, p.DeviceId).Scan(&curCreated, &curKey)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil && (curCreated > b.CreatedMs || (curCreated == b.CreatedMs && bytes.Compare(curKey, it.key) >= 0)) {
			return nil // an older (or the same) token: record kept, row unchanged
		}
		// A withdrawn record (D94) has an empty token: the row keeps created_ms/record_key so an older token record
		// replicated later loses the ordering check above and cannot bring the token back.
		_, err = tx.ExecContext(ctx,
			`INSERT INTO push_tokens(user_id,device_id,kind,token,created_ms,record_key,messages_off) VALUES(?,?,?,?,?,?,?)
			 ON CONFLICT(user_id,device_id) DO UPDATE SET kind=excluded.kind, token=excluded.token,
			   created_ms=excluded.created_ms, record_key=excluded.record_key, messages_off=excluded.messages_off`,
			b.Author, p.DeviceId, int32(p.Kind), p.Token, b.CreatedMs, it.key, p.MessagesOff)
		return err

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

	case pb.RecordType_PREKEY_CONSUMED:
		var c pb.PrekeyConsumed
		if err := proto.Unmarshal(b.Payload, &c); err != nil {
			return err
		}
		for _, id := range c.KeyIds {
			if _, err := tx.ExecContext(ctx,
				`UPDATE prekeys SET consumed=1 WHERE user_id=? AND device_id=? AND kind=? AND key_id=? AND owner_node=?`,
				c.UserId, c.DeviceId, PrekeyOneTime, id, b.Author); err != nil {
				return err
			}
		}
		return nil

	case pb.RecordType_BLOB_META:
		var m pb.BlobMeta
		if err := proto.Unmarshal(b.Payload, &m); err != nil {
			return err
		}
		var x int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM blob_tombstones WHERE blob_key=?`, it.key).Scan(&x)
		if err == nil { // deleted earlier: a lagging peer must not resurrect it
			_, err = tx.ExecContext(ctx, `DELETE FROM records WHERE record_key=?`, it.key)
			return err
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO blobs(blob_key,owner,size,chunks,expires_ms,created_ms,persistent) VALUES(?,?,?,?,?,?,?)`,
			it.key, b.Author, m.Size, len(m.ChunkSha256), b.ExpiresMs, b.CreatedMs, m.Persistent); err != nil {
			return err
		}
		for _, r := range m.Readers {
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO blob_readers(blob_key,user_id) VALUES(?,?)`, it.key, r); err != nil {
				return err
			}
		}
		return gcBlob(ctx, tx, it.key, false, now) // fetches that arrived before the meta count

	case pb.RecordType_BLOB_FETCHED:
		var f pb.BlobFetched
		if err := proto.Unmarshal(b.Payload, &f); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO blob_fetched(blob_key,user_id,at_ms) VALUES(?,?,?)`,
			f.BlobKey, b.Author, now); err != nil {
			return err
		}
		return gcBlob(ctx, tx, f.BlobKey, false, now)

	case pb.RecordType_BACKUP_META:
		var m pb.BackupMeta
		if err := proto.Unmarshal(b.Payload, &m); err != nil {
			return err
		}
		var curKey, curBlob []byte
		var curVer, curCreated int64
		err := tx.QueryRowContext(ctx, `SELECT record_key, version, created_ms, blob_key FROM backups WHERE user_id=?`,
			b.Author).Scan(&curKey, &curVer, &curCreated, &curBlob)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		newer := errors.Is(err, sql.ErrNoRows) || int64(m.Version) > curVer ||
			(int64(m.Version) == curVer && (b.CreatedMs > curCreated || (b.CreatedMs == curCreated && bytes.Compare(it.key, curKey) > 0)))
		if !newer { // an older or equal-but-losing version (e.g. from a lagging peer): drop it again
			_, err := tx.ExecContext(ctx, `DELETE FROM records WHERE record_key=?`, it.key)
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO backups(user_id,record_key,version,created_ms,blob_key) VALUES(?,?,?,?,?)`,
			b.Author, it.key, m.Version, b.CreatedMs, m.BlobKey); err != nil {
			return err
		}
		if curKey != nil {
			if _, err := tx.ExecContext(ctx, `DELETE FROM records WHERE record_key=?`, curKey); err != nil {
				return err
			}
			if !bytes.Equal(curBlob, m.BlobKey) {
				return gcBlob(ctx, tx, curBlob, true, now)
			}
		}
		return nil

	case pb.RecordType_ANNOUNCEMENT: // D66: a deletion that arrived first wins
		var x int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM news_deleted WHERE target=?`, it.key).Scan(&x)
		if err == nil {
			_, err = tx.ExecContext(ctx, `DELETE FROM records WHERE record_key=?`, it.key)
			return err
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		return nil

	case pb.RecordType_ANNOUNCEMENT_DELETED: // D66: kept forever in news_deleted, no edit
		var d pb.AnnouncementDeleted
		if err := proto.Unmarshal(b.Payload, &d); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO news_deleted(target) VALUES(?)`, d.Target); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM records WHERE record_key=? AND type=?`, d.Target, int32(pb.RecordType_ANNOUNCEMENT))
		return err

	case pb.RecordType_REVOCATION: // network-signed (D99)
		var r pb.Revocation
		if err := proto.Unmarshal(b.Payload, &r); err != nil {
			return err
		}
		return applyRevocation(ctx, tx, b, &r)

	case pb.RecordType_INVITE_RIGHTS: // network-signed (D99, D101)
		var r pb.InviteRights
		if err := proto.Unmarshal(b.Payload, &r); err != nil {
			return err
		}
		return applyInviteRights(ctx, tx, b, &r)

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

// gcBlob deletes a blob whose readers all fetched it (or, with force, unconditionally) and tombstones its key until
// expiry + 1 day (D45); a persistent (backup) blob is only deleted with force and is tombstoned for 30 days (D50).
// Chunk files are removed later by service.SweepBlobFiles.
func gcBlob(ctx context.Context, tx *sql.Tx, key []byte, force bool, now int64) error {
	var expires int64
	var persistent bool
	err := tx.QueryRowContext(ctx, `SELECT expires_ms, persistent FROM blobs WHERE blob_key=?`, key).Scan(&expires, &persistent)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !force {
		if persistent {
			return nil // backups are deleted only when superseded or unreferenced (D50)
		}
		var waiting int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM blob_readers r WHERE r.blob_key=? AND NOT EXISTS
			(SELECT 1 FROM blob_fetched f WHERE f.blob_key=r.blob_key AND f.user_id=r.user_id)`, key).Scan(&waiting); err != nil {
			return err
		}
		if waiting > 0 {
			return nil
		}
	}
	for _, q := range []string{`DELETE FROM blobs WHERE blob_key=?`, `DELETE FROM blob_chunks WHERE blob_key=?`,
		`DELETE FROM blob_readers WHERE blob_key=?`, `DELETE FROM records WHERE record_key=?`} {
		if _, err := tx.ExecContext(ctx, q, key); err != nil {
			return err
		}
	}
	until := expires + 24*time.Hour.Milliseconds()
	if persistent {
		until = now + tombstoneTTL.Milliseconds()
	}
	_, err = tx.ExecContext(ctx, `INSERT OR REPLACE INTO blob_tombstones(blob_key,until_ms) VALUES(?,?)`, key, until)
	return err
}

func conflictName(name string, userID []byte) string {
	return name + "#" + hex.EncodeToString(userID[:4])
}

// wins reports whether (createdA, idA) beats (createdB, idB) for a username.
func wins(createdA int64, idA []byte, createdB int64, idB []byte) bool {
	if createdA != createdB {
		return createdA < createdB
	}
	return bytes.Compare(idA, idB) < 0
}

// applyDirectoryEntry upserts the users row. A username clash fails for local submissions; for replicated
// entries (and local updates of a user who already lost that clash) the lower (registration time, user_id) keeps the
// name and the other becomes name#<hex>. Registration time = registered_ms, or the entry's created_ms when 0 (D40).
func applyDirectoryEntry(ctx context.Context, tx *sql.Tx, it item, e *pb.DirectoryEntry, created, now int64) error {
	rank := created
	if e.RegisteredMs > 0 {
		rank = e.RegisteredMs
	}
	var cur uint64
	var curName string
	var curConflict int
	err := tx.QueryRowContext(ctx, `SELECT version, username, username_conflict FROM users WHERE user_id=?`, e.UserId).
		Scan(&cur, &curName, &curConflict)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if exists && e.Version <= cur {
		return nil // older or same version: stored as a record, users row unchanged
	}
	// an update by a user who already lost this clash is ranked like a replicated entry
	lostBefore := exists && curConflict != 0 && strings.HasPrefix(curName, e.Username+"#")
	name, conflict := e.Username, 0
	var owner []byte
	var ownerCreated int64
	err = tx.QueryRowContext(ctx, `SELECT user_id, entry_created_ms FROM users WHERE username=?`, e.Username).Scan(&owner, &ownerCreated)
	switch {
	case errors.Is(err, sql.ErrNoRows) || (err == nil && bytes.Equal(owner, e.UserId)):
	case err != nil:
		return err
	case !it.fromPeer && !lostBefore:
		return ErrUsernameTaken
	case wins(rank, e.UserId, ownerCreated, owner):
		if _, err := tx.ExecContext(ctx, `UPDATE users SET username=?, username_conflict=1 WHERE user_id=?`,
			conflictName(e.Username, owner), owner); err != nil {
			return err
		}
	default:
		name, conflict = conflictName(e.Username, e.UserId), 1
	}
	if !exists {
		return insertUser(ctx, tx, it, e, name, conflict, rank, now)
	}
	_, err = tx.ExecContext(ctx, `UPDATE users SET username=?, entry_key=?, version=?, entry_created_ms=?, username_conflict=? WHERE user_id=?`,
		name, it.key, e.Version, rank, conflict, e.UserId)
	return err
}
