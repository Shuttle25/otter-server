package store

import (
	"context"
	"database/sql"

	pb "ottermsg/server/internal/proto/otterv1"
)

const RetentionMs = int64(30 * 24 * 60 * 60 * 1000)

type ExpireStats struct{ Envelopes, Acks, Tombstones, Oplog int64 }

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
		if err := exec(&st.Tombstones, `DELETE FROM tombstones WHERE until_ms < ?`, now); err != nil {
			return err
		}
		return exec(&st.Oplog, `DELETE FROM oplog WHERE record_key NOT IN (SELECT record_key FROM records)`)
	})
	return st, err
}
