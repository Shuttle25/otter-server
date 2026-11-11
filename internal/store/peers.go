package store

import (
	"context"
	"database/sql"
	"errors"
)

func (s *Store) PeerCursor(ctx context.Context, node []byte) (int64, error) {
	var c int64
	err := s.r.QueryRowContext(ctx, `SELECT cursor FROM peers WHERE node_id=?`, node).Scan(&c)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return c, err
}

func (s *Store) SetPeerCursor(ctx context.Context, node []byte, cursor int64) error {
	return s.write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO peers(node_id,cursor,last_seen_ms) VALUES(?,?,?)
			ON CONFLICT(node_id) DO UPDATE SET cursor=MAX(cursor, excluded.cursor), last_seen_ms=excluded.last_seen_ms`,
			node, cursor, s.now().UnixMilli())
		return err
	})
}

// PrekeyCounts returns unconsumed one-time prekeys per owner node.
func (s *Store) PrekeyCounts(ctx context.Context, user []byte, device uint32) (map[string]int, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT owner_node, COUNT(*) FROM prekeys
		WHERE user_id=? AND device_id=? AND kind=? AND consumed=0 GROUP BY owner_node`, user, device, PrekeyOneTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var owner []byte
		var n int
		if err := rows.Scan(&owner, &n); err != nil {
			return nil, err
		}
		out[string(owner)] = n
	}
	return out, rows.Err()
}
