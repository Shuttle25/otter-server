package store

import (
	"context"
	"testing"
	"time"

	pb "ottermsg/server/internal/proto/otterv1"
)

func blobItem(t *testing.T, author []byte, readers [][]byte, chunks int, created, expires int64) Item {
	hashes := make([][]byte, chunks)
	for i := range hashes {
		hashes[i] = make([]byte, 32)
	}
	it := mkItemAt(t, pb.RecordType_BLOB_META, author,
		&pb.BlobMeta{Size: uint64(chunks) * 262144, ChunkSize: 262144, ChunkSha256: hashes, Readers: readers}, created)
	it.Body.ExpiresMs = expires
	return it
}

// t0 is "now" for these tests: replication drops expiring records older than the retention.
var t0 = time.Now().UnixMilli()

const day = int64(86_400_000)

func fetchedItem(t *testing.T, reader, key []byte) Item {
	return mkItemAt(t, pb.RecordType_BLOB_FETCHED, reader, &pb.BlobFetched{BlobKey: key}, t0)
}

func keyOf(it Item) []byte { return append(append([]byte{}, it.Body.Author...), it.Body.Id...) }

func assertGone(t *testing.T, s *Store, key []byte) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.Blob(ctx, key); err != ErrNotFound {
		t.Fatalf("blob row still there: %v", err)
	}
	if _, err := s.Get(ctx, key); err != ErrNotFound {
		t.Fatal("meta record still there")
	}
	if gone, _ := s.BlobGone(ctx, key); !gone {
		t.Fatal("no tombstone")
	}
}

func TestBlobLifecycle(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	anna, boris, vera := r16(), r16(), r16()
	meta := blobItem(t, anna, [][]byte{boris, vera}, 3, t0, t0+day)
	key := keyOf(meta)
	if err := apply(t, s, meta); err != nil {
		t.Fatal(err)
	}
	b, err := s.Blob(ctx, key)
	if err != nil || len(b.Readers) != 2 || len(b.Hashes) != 3 || b.Size != 3*262144 {
		t.Fatalf("blob %+v %v", b, err)
	}
	if n, _ := s.UserBlobBytes(ctx, anna); n != 3*262144 {
		t.Fatalf("bytes %d", n)
	}
	if err := s.MarkChunk(ctx, key, 1); err != nil {
		t.Fatal(err)
	}
	gaps, _ := s.IncompleteBlobs(ctx, 16)
	if len(gaps) != 1 || len(gaps[0].Missing) != 2 || gaps[0].Missing[0] != 0 || gaps[0].Missing[1] != 2 {
		t.Fatalf("gaps %+v", gaps)
	}
	if keys, _ := s.BlobKeys(ctx); len(keys) != 1 {
		t.Fatal("keys")
	}
	// a non-reader's fetch changes nothing; one of two readers keeps the blob
	if err := apply(t, s, fetchedItem(t, r16(), key)); err != nil {
		t.Fatal(err)
	}
	if err := apply(t, s, fetchedItem(t, boris, key)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Blob(ctx, key); err != nil {
		t.Fatal("deleted too early")
	}
	if err := apply(t, s, fetchedItem(t, vera, key)); err != nil {
		t.Fatal(err)
	}
	assertGone(t, s, key)
	if chunks, _ := s.BlobChunks(ctx, key); len(chunks) != 0 {
		t.Fatal("chunk rows left")
	}
	if err := s.MarkChunk(ctx, key, 0); err != nil {
		t.Fatal(err)
	}
	if chunks, _ := s.BlobChunks(ctx, key); len(chunks) != 0 {
		t.Fatal("MarkChunk on a deleted blob")
	}
	// the janitor drops oplog rows of deleted records; a peer re-sending the meta must not resurrect it
	if _, err := s.Expire(ctx, t0); err != nil {
		t.Fatal(err)
	}
	replicate(t, s, meta)
	assertGone(t, s, key)
	if n, _ := s.UserBlobBytes(ctx, anna); n != 0 {
		t.Fatal("quota still counts a deleted blob")
	}
}

func TestBlobFetchedBeforeMeta(t *testing.T) {
	s, _ := open(t)
	anna, boris := r16(), r16()
	meta := blobItem(t, anna, [][]byte{boris}, 1, t0, t0+day)
	key := keyOf(meta)
	replicate(t, s, fetchedItem(t, boris, key))
	replicate(t, s, meta)
	assertGone(t, s, key)
}

func TestBlobExpiry(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	anna, boris := r16(), r16()
	meta := blobItem(t, anna, [][]byte{boris}, 2, t0, t0+day)
	key := keyOf(meta)
	if err := apply(t, s, meta); err != nil {
		t.Fatal(err)
	}
	st, err := s.Expire(ctx, t0+day-1)
	if err != nil || st.Blobs != 0 {
		t.Fatalf("early expiry: %+v %v", st, err)
	}
	st, err = s.Expire(ctx, t0+day+1)
	if err != nil || st.Blobs != 1 {
		t.Fatalf("expire: %+v %v", st, err)
	}
	assertGone(t, s, key)
	// the tombstone itself goes one day after expiry
	if _, err := s.Expire(ctx, t0+2*day+2); err != nil {
		t.Fatal(err)
	}
	if gone, _ := s.BlobGone(ctx, key); gone {
		t.Fatal("tombstone kept forever")
	}
}
