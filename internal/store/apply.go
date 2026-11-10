package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

const (
	maxBatch  = 256
	batchWait = 10 * time.Millisecond
)

type applyReq struct {
	key  []byte
	raw  []byte
	body *pb.RecordBody
	res  chan applyRes
}

type applyRes struct {
	seq     int64
	applied bool
	err     error
}

type LogEntry struct {
	Seq int64
	Raw []byte // serialized pb.Record
}

// Apply stores a validated record. Idempotent by author||id.
func (s *Store) Apply(ctx context.Context, rec *pb.Record, body *pb.RecordBody) (int64, bool, error) {
	key, err := keys.RecordKey(body.Author, body.Id)
	if err != nil {
		return 0, false, err
	}
	raw, err := proto.Marshal(rec)
	if err != nil {
		return 0, false, err
	}
	req := &applyReq{key: key, raw: raw, body: body, res: make(chan applyRes, 1)}
	select {
	case s.reqs <- req:
	case <-s.done:
		return 0, false, errClosed
	case <-ctx.Done():
		return 0, false, ctx.Err()
	}
	select {
	case r := <-req.res:
		return r.seq, r.applied, r.err
	case <-s.stopped:
		// The writer may have committed this request just before stopping.
		select {
		case r := <-req.res:
			return r.seq, r.applied, r.err
		default:
			return 0, false, errClosed
		}
	case <-ctx.Done():
		return 0, false, ctx.Err()
	}
}

func (s *Store) writer() {
	defer close(s.stopped)
	for {
		var batch []*applyReq
		select {
		case r := <-s.reqs:
			batch = append(batch, r)
		case <-s.done:
			return
		}
		timer := time.NewTimer(batchWait)
	fill:
		for len(batch) < maxBatch {
			select {
			case r := <-s.reqs:
				batch = append(batch, r)
			case <-timer.C:
				break fill
			}
		}
		timer.Stop()
		s.commit(batch)
	}
}

func (s *Store) commit(batch []*applyReq) {
	ctx := context.Background()
	results := make([]applyRes, len(batch))
	tx, err := s.w.BeginTx(ctx, nil)
	if err == nil {
		now := s.now().UnixMilli()
		for i, r := range batch {
			results[i] = applyOne(ctx, tx, r, now)
		}
		err = tx.Commit()
	}
	for i, r := range batch {
		if err != nil {
			results[i] = applyRes{err: err}
		}
		r.res <- results[i]
	}
}

func applyOne(ctx context.Context, tx *sql.Tx, r *applyReq, now int64) applyRes {
	var seq int64
	err := tx.QueryRowContext(ctx, `SELECT seq FROM oplog WHERE record_key=?`, r.key).Scan(&seq)
	if err == nil {
		return applyRes{seq: seq, applied: false}
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return applyRes{err: err}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO records(record_key,type,author,created_ms,expires_ms,raw) VALUES(?,?,?,?,?,?)`,
		r.key, int32(r.body.Type), r.body.Author, r.body.CreatedMs, r.body.ExpiresMs, r.raw); err != nil {
		return applyRes{err: err}
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO oplog(record_key,type,received_ms) VALUES(?,?,?)`, r.key, int32(r.body.Type), now)
	if err != nil {
		return applyRes{err: err}
	}
	seq, _ = res.LastInsertId()
	return applyRes{seq: seq, applied: true}
}

// Since returns log entries with seq > cursor, oldest first.
func (s *Store) Since(ctx context.Context, cursor int64, limit int) ([]LogEntry, error) {
	rows, err := s.r.QueryContext(ctx,
		`SELECT o.seq, r.raw FROM oplog o JOIN records r ON r.record_key=o.record_key WHERE o.seq>? ORDER BY o.seq LIMIT ?`,
		cursor, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogEntry
	for rows.Next() {
		var e LogEntry
		if err := rows.Scan(&e.Seq, &e.Raw); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Get returns the serialized record stored under key (author||id).
func (s *Store) Get(ctx context.Context, key []byte) ([]byte, error) {
	var raw []byte
	err := s.r.QueryRowContext(ctx, `SELECT raw FROM records WHERE record_key=?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return raw, err
}
