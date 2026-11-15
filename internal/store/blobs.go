package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
)

// Blob is a live blob as announced by its BLOB_META (D44).
type Blob struct {
	Key, Owner []byte
	Size       int64
	ExpiresMs  int64
	Hashes     [][]byte // per-chunk SHA-256 from the BLOB_META record
	Readers    [][]byte
}

// Blob returns a live blob or ErrNotFound.
func (s *Store) Blob(ctx context.Context, key []byte) (*Blob, error) {
	b := &Blob{Key: key}
	err := s.r.QueryRowContext(ctx, `SELECT owner, size, expires_ms FROM blobs WHERE blob_key=?`, key).Scan(&b.Owner, &b.Size, &b.ExpiresMs)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	raw, err := s.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	var rec pb.Record
	var body pb.RecordBody
	var m pb.BlobMeta
	if err := proto.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(rec.Body, &body); err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(body.Payload, &m); err != nil {
		return nil, err
	}
	b.Hashes = m.ChunkSha256
	rows, err := s.r.QueryContext(ctx, `SELECT user_id FROM blob_readers WHERE blob_key=?`, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var u []byte
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		b.Readers = append(b.Readers, u)
	}
	return b, rows.Err()
}

// ErrOverLimit: a per-author limit would be exceeded (blob quota, backup blobs).
var ErrOverLimit = errors.New("over the limit")

// BlobLimits are checked when a client creates a blob (D44, D50).
type BlobLimits struct {
	UserQuota     int64 // live blob bytes per author
	MaxPersistent int   // live persistent (backup) blobs per author
}

// ApplyBlobMeta stores a client's BLOB_META only if its author stays within lim, counted in the same write
// transaction as the insert, so parallel creates cannot overshoot (C9, D106). A meta already stored passes unchecked.
// Replicated metas do not come here: they are signed by the author and were checked by their origin node.
func (s *Store) ApplyBlobMeta(ctx context.Context, rec *pb.Record, body *pb.RecordBody, origin []byte,
	size int64, persistent bool, lim BlobLimits) (bool, error) {
	it, err := toItem(Item{Record: rec, Body: body}, origin)
	if err != nil {
		return false, err
	}
	check := func(ctx context.Context, tx *sql.Tx) error {
		var x int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM oplog WHERE record_key=?`, it.key).Scan(&x); err == nil {
			return nil // idempotent re-create
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if persistent {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM blobs WHERE owner=? AND persistent=1`, body.Author).Scan(&n); err != nil {
				return err
			}
			if n >= lim.MaxPersistent {
				return fmt.Errorf("%w: %d backup blobs in flight", ErrOverLimit, n)
			}
		}
		var used int64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(size),0) FROM blobs WHERE owner=?`, body.Author).Scan(&used); err != nil {
			return err
		}
		if used+size > lim.UserQuota {
			return fmt.Errorf("%w: %d of %d bytes in use", ErrOverLimit, used, lim.UserQuota)
		}
		return nil
	}
	r, err := s.submit(ctx, &applyReq{items: []item{it}, check: check})
	if err != nil {
		return false, err
	}
	return r.applied[0], nil
}

// BlobGone reports whether the blob was deleted (fetched by every reader or expired) and is tombstoned.
func (s *Store) BlobGone(ctx context.Context, key []byte) (bool, error) {
	var x int
	err := s.r.QueryRowContext(ctx, `SELECT 1 FROM blob_tombstones WHERE blob_key=?`, key).Scan(&x)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// BlobChunks returns the chunk indexes this node holds.
func (s *Store) BlobChunks(ctx context.Context, key []byte) (map[uint32]bool, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT idx FROM blob_chunks WHERE blob_key=?`, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uint32]bool{}
	for rows.Next() {
		var i uint32
		if err := rows.Scan(&i); err != nil {
			return nil, err
		}
		out[i] = true
	}
	return out, rows.Err()
}

// MarkChunk records that chunk idx is on disk; a deleted blob gets no row.
func (s *Store) MarkChunk(ctx context.Context, key []byte, idx uint32) error {
	return s.write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO blob_chunks(blob_key,idx)
			SELECT ?,? WHERE EXISTS(SELECT 1 FROM blobs WHERE blob_key=?)`, key, idx, key)
		return err
	})
}

// UserBlobBytes is the size of an author's live blobs (quota, D44).
func (s *Store) UserBlobBytes(ctx context.Context, owner []byte) (int64, error) {
	var n int64
	err := s.r.QueryRowContext(ctx, `SELECT COALESCE(SUM(size),0) FROM blobs WHERE owner=?`, owner).Scan(&n)
	return n, err
}

// BlobGap is a blob with chunks this node doesn't hold yet.
type BlobGap struct {
	Key     []byte
	Missing []uint32
}

// IncompleteBlobs lists blobs missing chunks on this node, oldest first.
func (s *Store) IncompleteBlobs(ctx context.Context, limit int) ([]BlobGap, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT b.blob_key, b.chunks FROM blobs b
		WHERE (SELECT COUNT(*) FROM blob_chunks c WHERE c.blob_key=b.blob_key) < b.chunks
		ORDER BY b.created_ms LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	type kc struct {
		key []byte
		n   uint32
	}
	var list []kc
	for rows.Next() {
		var x kc
		if err := rows.Scan(&x.key, &x.n); err != nil {
			rows.Close()
			return nil, err
		}
		list = append(list, x)
	}
	rows.Close()
	var out []BlobGap
	for _, x := range list {
		have, err := s.BlobChunks(ctx, x.key)
		if err != nil {
			return nil, err
		}
		g := BlobGap{Key: x.key}
		for i := uint32(0); i < x.n; i++ {
			if !have[i] {
				g.Missing = append(g.Missing, i)
			}
		}
		out = append(out, g)
	}
	return out, nil
}

// BlobKeys returns the hex keys of all live blobs.
func (s *Store) BlobKeys(ctx context.Context) (map[string]bool, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT blob_key FROM blobs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var k []byte
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out[hex.EncodeToString(k)] = true
	}
	return out, rows.Err()
}
