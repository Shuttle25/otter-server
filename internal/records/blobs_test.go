package records

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

func TestBlobRecords(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	author := keys.ID16(pub)
	v := &Validator{Users: fakeUsers{string(author): {Pub: pub}}, Now: func() time.Time { return now }}
	reader := func(b byte) []byte { r := make([]byte, 16); r[0] = b; return r }
	valid := func() *pb.BlobMeta {
		h := func() []byte { return make([]byte, 32) }
		return &pb.BlobMeta{Size: 600 << 10, ChunkSize: BlobChunkSize, ChunkSha256: [][]byte{h(), h(), h()}, Readers: [][]byte{reader(1), reader(2)}}
	}
	created := now.UnixMilli()
	rec := func(m *pb.BlobMeta, expires int64) *pb.Record {
		return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_BLOB_META, Author: author, CreatedMs: created,
			ExpiresMs: expires, Payload: payload(m)}, priv)
	}
	day := 24 * time.Hour.Milliseconds()
	cases := []struct {
		name    string
		mod     func(*pb.BlobMeta)
		expires int64
		ok      bool
	}{
		{"valid", func(*pb.BlobMeta) {}, created + 30*day, true},
		{"one byte", func(m *pb.BlobMeta) { m.Size = 1; m.ChunkSha256 = m.ChunkSha256[:1] }, created + day, true},
		{"exact chunk multiple", func(m *pb.BlobMeta) { m.Size = 2 * BlobChunkSize; m.ChunkSha256 = m.ChunkSha256[:2] }, created + day, true},
		{"max ttl", func(*pb.BlobMeta) {}, created + 31*day, true},
		{"zero size", func(m *pb.BlobMeta) { m.Size = 0; m.ChunkSha256 = nil }, created + day, false},
		{"too big", func(m *pb.BlobMeta) { m.Size = MaxBlobSize + 1 }, created + day, false},
		{"wrong chunk size", func(m *pb.BlobMeta) { m.ChunkSize = 1 << 20 }, created + day, false},
		{"hash count", func(m *pb.BlobMeta) { m.ChunkSha256 = m.ChunkSha256[:2] }, created + day, false},
		{"short hash", func(m *pb.BlobMeta) { m.ChunkSha256[1] = make([]byte, 31) }, created + day, false},
		{"no readers", func(m *pb.BlobMeta) { m.Readers = nil }, created + day, false},
		{"too many readers", func(m *pb.BlobMeta) {
			m.Readers = nil
			for i := 0; i <= MaxBlobReaders; i++ {
				r := make([]byte, 16)
				r[0], r[1] = byte(i), byte(i>>8)
				r[2] = 9
				m.Readers = append(m.Readers, r)
			}
		}, created + day, false},
		{"bad reader length", func(m *pb.BlobMeta) { m.Readers[0] = make([]byte, 15) }, created + day, false},
		{"duplicate reader", func(m *pb.BlobMeta) { m.Readers[1] = m.Readers[0] }, created + day, false},
		{"author as reader", func(m *pb.BlobMeta) { m.Readers[0] = author }, created + day, false},
		{"no expiry", func(*pb.BlobMeta) {}, 0, false},
		{"expiry too far", func(*pb.BlobMeta) {}, created + 31*day + 1, false},
	}
	for _, c := range cases {
		m := valid()
		c.mod(m)
		_, err := v.Validate(rec(m, c.expires))
		if c.ok != (err == nil) {
			t.Errorf("%s: err=%v", c.name, err)
		}
		if !c.ok && err != nil && !errors.Is(err, ErrBadPayload) {
			t.Errorf("%s: want ErrBadPayload, got %v", c.name, err)
		}
	}

	fetched := func(key []byte) *pb.Record {
		return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_BLOB_FETCHED, Author: author, CreatedMs: created,
			Payload: payload(&pb.BlobFetched{BlobKey: key})}, priv)
	}
	if _, err := v.Validate(fetched(make([]byte, 32))); err != nil {
		t.Fatalf("fetched: %v", err)
	}
	if _, err := v.Validate(fetched(make([]byte, 16))); !errors.Is(err, ErrBadPayload) {
		t.Fatalf("short key: %v", err)
	}
}
