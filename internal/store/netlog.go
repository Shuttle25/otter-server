package store

import (
	"context"
	"database/sql"
	"errors"
)

// NetlogMax is the most lines the connectivity log keeps (D74).
const NetlogMax = 200

type NetlogEntry struct {
	ID                                               int64
	Peer, Endpoint, Direction, Result, Class, Detail string
	Count                                            int64
	FirstMs, LastMs                                  int64
}

// NetlogAdd merges e into the newest line for the same peer/endpoint/direction if result and class match,
// otherwise adds a line; keeps the NetlogMax most recently updated lines (D74).
func (s *Store) NetlogAdd(ctx context.Context, e NetlogEntry) error {
	now := s.now().UnixMilli()
	return s.write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var id int64
		var result, class string
		err := tx.QueryRowContext(ctx, `SELECT id, result, class FROM netlog WHERE peer=? AND endpoint=? AND direction=?
			ORDER BY id DESC LIMIT 1`, e.Peer, e.Endpoint, e.Direction).Scan(&id, &result, &class)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil && result == e.Result && class == e.Class {
			_, err = tx.ExecContext(ctx, `UPDATE netlog SET count=count+1, last_ms=?, detail=? WHERE id=?`, now, e.Detail, id)
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO netlog(peer,endpoint,direction,result,class,detail,count,first_ms,last_ms)
			VALUES(?,?,?,?,?,?,1,?,?)`, e.Peer, e.Endpoint, e.Direction, e.Result, e.Class, e.Detail, now, now); err != nil {
			return err
		}
		// Trim by the same order Netlog shows, so a long-lived line that keeps merging is not dropped for its old id.
		_, err = tx.ExecContext(ctx, `DELETE FROM netlog WHERE id NOT IN
			(SELECT id FROM netlog ORDER BY last_ms DESC, id DESC LIMIT ?)`, NetlogMax)
		return err
	})
}

// Netlog returns up to limit lines, the most recently updated first.
func (s *Store) Netlog(ctx context.Context, limit int) ([]NetlogEntry, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id,peer,endpoint,direction,result,class,detail,count,first_ms,last_ms
		FROM netlog ORDER BY last_ms DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NetlogEntry
	for rows.Next() {
		var e NetlogEntry
		if err := rows.Scan(&e.ID, &e.Peer, &e.Endpoint, &e.Direction, &e.Result, &e.Class, &e.Detail, &e.Count, &e.FirstMs, &e.LastMs); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
