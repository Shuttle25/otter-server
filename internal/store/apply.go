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

// Item is a validated record with its parsed body.
type Item struct {
	Record *pb.Record
	Body   *pb.RecordBody
}

type item struct {
	key, raw []byte
	body     *pb.RecordBody
	origin   []byte
	fromPeer bool // replicated: business conflicts never fail
}

type applyReq struct {
	items []item
	fn    func(context.Context, *sql.Tx) error
	res   chan applyRes
}

type applyRes struct {
	seqs    []int64
	applied []bool
	err     error
}

type LogEntry struct {
	Seq int64
	Raw []byte // serialized pb.Record
}

func toItem(it Item, origin []byte) (item, error) {
	key, err := keys.RecordKey(it.Body.Author, it.Body.Id)
	if err != nil {
		return item{}, err
	}
	raw, err := proto.Marshal(it.Record)
	if err != nil {
		return item{}, err
	}
	return item{key: key, raw: raw, body: it.Body, origin: origin}, nil
}

// Apply stores a validated record. Idempotent by author||id.
func (s *Store) Apply(ctx context.Context, rec *pb.Record, body *pb.RecordBody) (int64, bool, error) {
	return s.ApplyFrom(ctx, rec, body, nil)
}

// ApplyFrom is Apply with the node that first accepted the record (mailbox origin).
func (s *Store) ApplyFrom(ctx context.Context, rec *pb.Record, body *pb.RecordBody, origin []byte) (int64, bool, error) {
	it, err := toItem(Item{rec, body}, origin)
	if err != nil {
		return 0, false, err
	}
	r, err := s.submit(ctx, &applyReq{items: []item{it}})
	if err != nil {
		return 0, false, err
	}
	return r.seqs[0], r.applied[0], nil
}

// ApplyReplicated applies a record received from peer `from`. Business conflicts never fail here.
func (s *Store) ApplyReplicated(ctx context.Context, rec *pb.Record, body *pb.RecordBody, from []byte) (int64, bool, error) {
	it, err := toItem(Item{rec, body}, from)
	if err != nil {
		return 0, false, err
	}
	it.fromPeer = true
	r, err := s.submit(ctx, &applyReq{items: []item{it}})
	if err != nil {
		return 0, false, err
	}
	return r.seqs[0], r.applied[0], nil
}

// ApplyAll applies all items atomically: either every record is stored or none.
func (s *Store) ApplyAll(ctx context.Context, origin []byte, items []Item) ([]int64, error) {
	req := &applyReq{}
	for _, in := range items {
		it, err := toItem(in, origin)
		if err != nil {
			return nil, err
		}
		req.items = append(req.items, it)
	}
	r, err := s.submit(ctx, req)
	return r.seqs, err
}

// write runs fn inside the writer's transaction (savepoint-isolated).
func (s *Store) write(ctx context.Context, fn func(context.Context, *sql.Tx) error) error {
	_, err := s.submit(ctx, &applyReq{fn: fn})
	return err
}

func (s *Store) submit(ctx context.Context, req *applyReq) (applyRes, error) {
	req.res = make(chan applyRes, 1)
	select {
	case s.reqs <- req:
	case <-s.done:
		return applyRes{}, errClosed
	case <-ctx.Done():
		return applyRes{}, ctx.Err()
	}
	select {
	case r := <-req.res:
		return r, r.err
	case <-s.stopped:
		// The writer may have committed this request just before stopping.
		select {
		case r := <-req.res:
			return r, r.err
		default:
			return applyRes{}, errClosed
		}
	case <-ctx.Done():
		return applyRes{}, ctx.Err()
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
			results[i] = runReq(ctx, tx, r, now)
		}
		err = tx.Commit()
	}
	if err == nil && anyApplied(results) {
		s.signalChanged()
	}
	for i, r := range batch {
		if err != nil {
			results[i] = applyRes{err: err}
		}
		r.res <- results[i]
	}
}

func anyApplied(results []applyRes) bool {
	for _, r := range results {
		if r.err != nil {
			continue
		}
		for _, a := range r.applied {
			if a {
				return true
			}
		}
	}
	return false
}

// expiring types leave the oplog after RetentionMs; a peer re-sending one must not resurrect it.
func expiring(t pb.RecordType) bool {
	return t == pb.RecordType_ENVELOPE || t == pb.RecordType_ACK || t == pb.RecordType_PREKEY_CONSUMED
}

// runReq executes one request inside SAVEPOINT req; any error rolls back only this request.
func runReq(ctx context.Context, tx *sql.Tx, r *applyReq, now int64) applyRes {
	if _, err := tx.ExecContext(ctx, `SAVEPOINT req`); err != nil {
		return applyRes{err: err}
	}
	var res applyRes
	var err error
	if r.fn != nil {
		err = r.fn(ctx, tx)
	} else {
		for _, it := range r.items {
			seq, applied, e := applyOne(ctx, tx, it, now)
			if e != nil {
				err = e
				break
			}
			res.seqs = append(res.seqs, seq)
			res.applied = append(res.applied, applied)
		}
	}
	if err != nil {
		tx.ExecContext(ctx, `ROLLBACK TO req`)
		tx.ExecContext(ctx, `RELEASE req`)
		return applyRes{err: err}
	}
	if _, err := tx.ExecContext(ctx, `RELEASE req`); err != nil {
		return applyRes{err: err}
	}
	return res
}

func applyOne(ctx context.Context, tx *sql.Tx, it item, now int64) (int64, bool, error) {
	var seq int64
	err := tx.QueryRowContext(ctx, `SELECT seq FROM oplog WHERE record_key=?`, it.key).Scan(&seq)
	if err == nil {
		return seq, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, false, err
	}
	if it.fromPeer && expiring(it.body.Type) && it.body.CreatedMs < now-RetentionMs {
		return 0, false, nil
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO records(record_key,type,author,created_ms,expires_ms,raw) VALUES(?,?,?,?,?,?)`,
		it.key, int32(it.body.Type), it.body.Author, it.body.CreatedMs, it.body.ExpiresMs, it.raw); err != nil {
		return 0, false, err
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO oplog(record_key,type,received_ms) VALUES(?,?,?)`, it.key, int32(it.body.Type), now)
	if err != nil {
		return 0, false, err
	}
	seq, _ = res.LastInsertId()
	if err := applyTyped(ctx, tx, it, now); err != nil {
		return 0, false, err
	}
	return seq, true, nil
}

// Since returns log entries with seq > cursor, oldest first. Deleted records are skipped.
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
