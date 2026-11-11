package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"path/filepath"
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
