package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/blobs"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

type fakeFetcher struct {
	answer []byte
	calls  int
}

func (f *fakeFetcher) FetchChunk(_ context.Context, _ []byte, _ uint32, ok func([]byte) bool) ([]byte, error) {
	f.calls++
	if f.answer == nil || !ok(f.answer) {
		return nil, errors.New("no peer has the chunk")
	}
	return f.answer, nil
}

// A blob whose meta replicated here but whose chunk is only on a peer: the reader's get proxies and keeps it.
func TestGetChunkProxies(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	bd, err := blobs.New(filepath.Join(t.TempDir(), "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	f.svc.Blobs = bd
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna")
	boris := f.mustRegister(f.invite(anna, time.Hour), "boris")
	data := make([]byte, 1000)
	rand.Read(data)
	h := sha256.Sum256(data)
	p, _ := proto.Marshal(&pb.BlobMeta{Size: 1000, ChunkSize: records.BlobChunkSize, ChunkSha256: [][]byte{h[:]}, Readers: [][]byte{boris.id}})
	id := r16()
	body := &pb.RecordBody{Id: id, Type: pb.RecordType_BLOB_META, Author: anna.id, CreatedMs: time.Now().UnixMilli(),
		ExpiresMs: time.Now().Add(time.Hour).UnixMilli(), Payload: p}
	rec, _ := records.Sign(body, anna.priv)
	if _, err := f.svc.CreateBlob(ctx, anna.id, rec); err != nil {
		t.Fatal(err)
	}
	key := append(append([]byte{}, anna.id...), id...)
	if _, err := f.svc.GetChunk(ctx, boris.id, key, 0); !errors.Is(err, ErrRetryLater) {
		t.Fatalf("no fetcher: %v", err)
	}
	bad := &fakeFetcher{answer: make([]byte, 1000)}
	f.svc.Fetcher = bad
	if _, err := f.svc.GetChunk(ctx, boris.id, key, 0); !errors.Is(err, ErrRetryLater) || bad.calls != 1 {
		t.Fatalf("garbage from a peer accepted: %v", err)
	}
	good := &fakeFetcher{answer: data}
	f.svc.Fetcher = good
	got, err := f.svc.GetChunk(ctx, boris.id, key, 0)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("proxy: %v", err)
	}
	if _, ok, _ := f.svc.LocalChunk(ctx, key, 0); !ok {
		t.Fatal("proxied chunk not kept")
	}
	if _, err := f.svc.GetChunk(ctx, boris.id, key, 0); err != nil || good.calls != 1 {
		t.Fatalf("second get should be local: %v calls=%d", err, good.calls)
	}
}

// blobMeta signs a one-chunk blob of size bytes for u (persistent: a backup blob).
func blobMeta(t *testing.T, u *user, size uint64, persistent bool) *pb.Record {
	h := sha256.Sum256([]byte("x"))
	m := &pb.BlobMeta{Size: size, ChunkSize: records.BlobChunkSize, ChunkSha256: [][]byte{h[:]}, Persistent: persistent}
	body := &pb.RecordBody{Id: r16(), Type: pb.RecordType_BLOB_META, Author: u.id, CreatedMs: time.Now().UnixMilli()}
	if !persistent {
		m.Readers = [][]byte{r16()} // any other member
		body.ExpiresMs = time.Now().Add(24 * time.Hour).UnixMilli()
	}
	body.Payload, _ = proto.Marshal(m)
	rec, err := records.Sign(body, u.priv)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// A client racing blob.create calls cannot overshoot its limits (C9, D106).
func TestCreateBlobLimitsHoldUnderParallelCreates(t *testing.T) {
	f := newFx(t)
	withBlobs(t, f)
	f.svc.Limits = Limits{UserQuota: 1000, MaxBlob: 1000}
	ctx := context.Background()
	u := f.mustRegister(f.invite(nil, time.Hour), "anna")
	race := func(persistent bool) (ok, quota int) {
		var wg sync.WaitGroup
		var mu sync.Mutex
		for i := 0; i < 10; i++ {
			rec := blobMeta(t, u, 300, persistent)
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := f.svc.CreateBlob(ctx, u.id, rec)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					ok++
				case errors.Is(err, ErrQuota):
					quota++
				default:
					t.Errorf("unexpected: %v", err)
				}
			}()
		}
		wg.Wait()
		return ok, quota
	}
	if ok, quota := race(false); ok != 3 || quota != 7 {
		t.Fatalf("bytes: %d created, %d refused", ok, quota)
	}
	if used, _ := f.svc.Store.UserBlobBytes(ctx, u.id); used > 1000 {
		t.Fatalf("quota overshot: %d", used)
	}
	f.svc.Limits.UserQuota = 1 << 30
	if ok, _ := race(true); ok != MaxPersistentBlobs {
		t.Fatalf("persistent: %d created", ok)
	}
	again := blobMeta(t, u, 300, true)
	if _, err := f.svc.CreateBlob(ctx, u.id, again); !errors.Is(err, ErrQuota) {
		t.Fatalf("4th backup blob: %v", err)
	}
}

// Re-creating a blob already stored answers its status even when the author is at the quota.
func TestCreateBlobIdempotentAtTheLimit(t *testing.T) {
	f := newFx(t)
	withBlobs(t, f)
	f.svc.Limits = Limits{UserQuota: 300, MaxBlob: 1000}
	u := f.mustRegister(f.invite(nil, time.Hour), "anna")
	rec := blobMeta(t, u, 300, false)
	for i := 0; i < 2; i++ {
		if _, err := f.svc.CreateBlob(context.Background(), u.id, rec); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
}
