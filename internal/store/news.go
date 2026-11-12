package store

import (
	"context"
	"database/sql"
	"strings"

	pb "ottermsg/server/internal/proto/otterv1"
)

// News returns every stored ANNOUNCEMENT and ANNOUNCEMENT_DELETED record (serialized pb.Record), oldest first (D67).
func (s *Store) News(ctx context.Context) ([][]byte, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT raw FROM records WHERE type IN (?,?) ORDER BY created_ms, record_key`,
		int32(pb.RecordType_ANNOUNCEMENT), int32(pb.RecordType_ANNOUNCEMENT_DELETED))
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

// DropNewsExcept deletes announcements and deletions whose author (ID16 of the news key) is not in keep, and returns
// how many it deleted (revoked news keys, D65). An empty keep deletes all of them. The oplog rows stay: Since joins
// records, so dropped records are no longer replicated, and a peer re-sending one is ignored as already seen.
func (s *Store) DropNewsExcept(ctx context.Context, keep [][]byte) (int, error) {
	n := 0
	err := s.write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		q := `DELETE FROM records WHERE type IN (?,?)`
		args := []any{int32(pb.RecordType_ANNOUNCEMENT), int32(pb.RecordType_ANNOUNCEMENT_DELETED)}
		if len(keep) > 0 {
			q += ` AND author NOT IN (` + strings.TrimSuffix(strings.Repeat("?,", len(keep)), ",") + `)`
			for _, k := range keep {
				args = append(args, k)
			}
		}
		res, err := tx.ExecContext(ctx, q, args...)
		if err != nil {
			return err
		}
		c, _ := res.RowsAffected()
		n = int(c)
		return nil
	})
	return n, err
}

// Target is a device that registered a push token.
type Target struct {
	User   []byte
	Device uint32
}

// PushTargets lists every (user, device) with a push token (announcement wake-ups, D67).
func (s *Store) PushTargets(ctx context.Context) ([]Target, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT user_id, device_id FROM push_tokens ORDER BY user_id, device_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.User, &t.Device); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
