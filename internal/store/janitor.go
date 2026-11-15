package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
)

const RetentionMs = int64(30 * 24 * 60 * 60 * 1000)

// OrphanBackupMs: a persistent blob no BACKUP_META references is deleted this long after its creation (D50).
const OrphanBackupMs = int64(7 * 24 * 60 * 60 * 1000)

// NetlogMaxAgeMs: connectivity-log lines not updated for this long are deleted; they hold source IPs of rejected
// peers (C25, D85).
const NetlogMaxAgeMs = int64(7 * 24 * 60 * 60 * 1000)

type ExpireStats struct{ Envelopes, Acks, Tombstones, Oplog, Blobs, Compacted int64 }

// Expire removes data past retention (docs/03 "Deletion & garbage collection").
func (s *Store) Expire(ctx context.Context, now int64) (ExpireStats, error) {
	var st ExpireStats
	cut := now - RetentionMs
	err := s.write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		exec := func(dst *int64, q string, args ...any) error {
			r, err := tx.ExecContext(ctx, q, args...)
			if err != nil {
				return err
			}
			n, _ := r.RowsAffected()
			*dst += n
			return nil
		}
		var ignore int64
		// short-lived envelopes (call signaling, D78): gone as soon as their record expiry passes
		if err := exec(&ignore, `DELETE FROM mailbox WHERE record_key IN
			(SELECT record_key FROM records WHERE type=? AND expires_ms > 0 AND expires_ms < ?)`,
			int32(pb.RecordType_ENVELOPE), now); err != nil {
			return err
		}
		if err := exec(&st.Envelopes, `DELETE FROM records WHERE type=? AND expires_ms > 0 AND expires_ms < ?`,
			int32(pb.RecordType_ENVELOPE), now); err != nil {
			return err
		}
		if err := exec(&ignore, `DELETE FROM mailbox WHERE received_ms < ?`, cut); err != nil {
			return err
		}
		if err := exec(&st.Envelopes, `DELETE FROM records WHERE type=? AND record_key IN
			(SELECT record_key FROM oplog WHERE type=? AND received_ms < ?)`, int32(pb.RecordType_ENVELOPE), int32(pb.RecordType_ENVELOPE), cut); err != nil {
			return err
		}
		if err := exec(&st.Acks, `DELETE FROM records WHERE type IN (?,?) AND record_key IN
			(SELECT record_key FROM oplog WHERE type IN (?,?) AND received_ms < ?)`,
			int32(pb.RecordType_ACK), int32(pb.RecordType_PREKEY_CONSUMED), int32(pb.RecordType_ACK), int32(pb.RecordType_PREKEY_CONSUMED), cut); err != nil {
			return err
		}
		// expired blobs go like fetched ones: rows, record and a tombstone (files: SweepBlobFiles)
		rows, err := tx.QueryContext(ctx, `SELECT blob_key FROM blobs WHERE persistent=0 AND expires_ms < ?`, now)
		if err != nil {
			return err
		}
		var expired [][]byte
		for rows.Next() {
			var k []byte
			if err := rows.Scan(&k); err != nil {
				rows.Close()
				return err
			}
			expired = append(expired, k)
		}
		rows.Close()
		// persistent (backup) blobs no BACKUP_META points at a week after creation: failed uploads, resurrected old ones (D50)
		rows, err = tx.QueryContext(ctx, `SELECT blob_key FROM blobs WHERE persistent=1 AND created_ms < ?
			AND blob_key NOT IN (SELECT blob_key FROM backups)`, now-OrphanBackupMs)
		if err != nil {
			return err
		}
		for rows.Next() {
			var k []byte
			if err := rows.Scan(&k); err != nil {
				rows.Close()
				return err
			}
			expired = append(expired, k)
		}
		rows.Close()
		for _, k := range expired {
			if err := gcBlob(ctx, tx, k, true, now); err != nil {
				return err
			}
			st.Blobs++
		}
		if err := exec(&ignore, `DELETE FROM auth_failures WHERE at_ms < ?`, now-24*time.Hour.Milliseconds()); err != nil {
			return err
		}
		if err := exec(&ignore, `DELETE FROM netlog WHERE last_ms < ?`, now-NetlogMaxAgeMs); err != nil {
			return err
		}
		if err := exec(&ignore, `DELETE FROM records WHERE type=? AND record_key IN
			(SELECT record_key FROM oplog WHERE type=? AND received_ms < ?)`,
			int32(pb.RecordType_BLOB_FETCHED), int32(pb.RecordType_BLOB_FETCHED), cut); err != nil {
			return err
		}
		if err := exec(&ignore, `DELETE FROM blob_fetched WHERE at_ms < ?`, cut); err != nil {
			return err
		}
		if err := exec(&ignore, `DELETE FROM blob_tombstones WHERE until_ms < ?`, now); err != nil {
			return err
		}
		if err := exec(&st.Tombstones, `DELETE FROM tombstones WHERE until_ms < ?`, now); err != nil {
			return err
		}
		n, err := compactPrekeys(ctx, tx, now)
		if err != nil {
			return err
		}
		st.Compacted += n
		if err := exec(&ignore, `DELETE FROM compacted WHERE until_ms < ?`, now); err != nil {
			return err
		}
		return exec(&st.Oplog, `DELETE FROM oplog WHERE record_key NOT IN (SELECT record_key FROM records)`)
	})
	if err != nil {
		// e.g. ctx cancelled: the writer may still be filling st, so it must not be read here
		return ExpireStats{}, err
	}
	return st, nil
}

// prekeyGrace: a PREKEYS record younger than this is never compacted (its keys may still be replicating).
const prekeyGrace = int64(60 * 60 * 1000)

// compact deletes a superseded record and remembers its key for RetentionMs, so a re-send is ignored (C8, D107).
func compact(ctx context.Context, tx *sql.Tx, key []byte, now int64) error {
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO compacted(record_key, until_ms) VALUES(?,?)`, key, now+RetentionMs); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM records WHERE record_key=?`, key)
	return err
}

// compactPrekeys deletes PREKEYS records that add nothing any more (C8, D107): a replaced install's, and those whose
// one-time keys are all consumed or dropped, except the newest record carrying the device's signed prekeys of the
// current install. Then it raises the per-owner floors and forgets consumed one-time rows below them.
//
// Anti-entropy still holds: only records whose effect is fully carried by records that stay (the base record,
// records with live keys, the newer install's record) are deleted, so Since(cursor) still yields the live set
// (docs/03). A consumed key's id is below its floor, so neither a lagging peer nor a hostile replay can make this
// node hand it out again; a legitimately late record with ids below the floor only loses one-time keys (Signal
// falls back to the signed prekey).
func compactPrekeys(ctx context.Context, tx *sql.Tx, now int64) (int64, error) {
	type rec struct {
		key, author []byte
		created     int64
		p           pb.PreKeys
	}
	rows, err := tx.QueryContext(ctx, `SELECT record_key, author, created_ms, raw FROM records WHERE type=? ORDER BY created_ms, record_key`,
		int32(pb.RecordType_PREKEYS))
	if err != nil {
		return 0, err
	}
	var all []*rec
	for rows.Next() {
		r := &rec{}
		var raw []byte
		if err := rows.Scan(&r.key, &r.author, &r.created, &raw); err != nil {
			rows.Close()
			return 0, err
		}
		var outer pb.Record
		var body pb.RecordBody
		if proto.Unmarshal(raw, &outer) != nil || proto.Unmarshal(outer.Body, &body) != nil || proto.Unmarshal(body.Payload, &r.p) != nil {
			continue // stored records were validated; skip rather than fail the janitor
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	type dev struct {
		author string
		id     uint32
	}
	installed := map[dev]int64{}
	base := map[dev]*rec{} // newest record with signed prekeys of the current install (ordered by created_ms above)
	for _, r := range all {
		d := dev{string(r.author), r.p.DeviceId}
		if _, ok := installed[d]; !ok {
			var inst int64
			err := tx.QueryRowContext(ctx, `SELECT installed_ms FROM devices WHERE user_id=? AND device_id=?`, r.author, r.p.DeviceId).Scan(&inst)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return 0, err
			}
			installed[d] = inst
		}
		if r.p.SignedPrekey != nil && r.p.InstalledMs == installed[d] {
			base[d] = r
		}
	}
	var n int64
	for _, r := range all {
		d := dev{string(r.author), r.p.DeviceId}
		if r.created >= now-prekeyGrace || base[d] == r {
			continue
		}
		drop := r.p.InstalledMs < installed[d]
		if !drop {
			lo, hi := uint32(1<<32-1), uint32(0)
			for _, k := range r.p.OneTime {
				lo, hi = min(lo, k.Id), max(hi, k.Id)
			}
			live := false
			if len(r.p.OneTime) > 0 { // ids are unique per (user, device): the record's range finds its live keys
				if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM prekeys WHERE user_id=? AND device_id=? AND kind=?
					AND consumed=0 AND key_id BETWEEN ? AND ?)`, r.author, r.p.DeviceId, PrekeyOneTime, lo, hi).Scan(&live); err != nil {
					return 0, err
				}
			}
			drop = !live
		}
		if drop {
			if err := compact(ctx, tx, r.key, now); err != nil {
				return 0, err
			}
			n++
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO prekey_floor(user_id, device_id, owner_node, floor_id)
		SELECT user_id, device_id, owner_node, MAX(key_id)+1 FROM prekeys WHERE kind=? AND consumed=1 AND owner_node IS NOT NULL
		GROUP BY user_id, device_id, owner_node
		ON CONFLICT(user_id, device_id, owner_node) DO UPDATE SET floor_id=MAX(floor_id, excluded.floor_id)`, PrekeyOneTime); err != nil {
		return 0, err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM prekeys WHERE kind=? AND consumed=1 AND key_id <
		(SELECT f.floor_id FROM prekey_floor f WHERE f.user_id=prekeys.user_id AND f.device_id=prekeys.device_id
		 AND f.owner_node=prekeys.owner_node)`, PrekeyOneTime)
	return n, err
}
