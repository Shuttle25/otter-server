package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

const chunk = 256 << 10

// blobMeta signs a BLOB_META for data and returns it with its blob key.
func blobMeta(t *testing.T, a *acct, data []byte, readers ...*acct) (*pb.Record, []byte) {
	m := &pb.BlobMeta{Size: uint64(len(data)), ChunkSize: chunk}
	for off := 0; off < len(data); off += chunk {
		h := sha256.Sum256(data[off:min(off+chunk, len(data))])
		m.ChunkSha256 = append(m.ChunkSha256, h[:])
	}
	for _, r := range readers {
		m.Readers = append(m.Readers, r.id)
	}
	p, _ := proto.Marshal(m)
	id := r16()
	now := time.Now()
	rec, err := records.Sign(&pb.RecordBody{Id: id, Type: pb.RecordType_BLOB_META, Author: a.id, CreatedMs: now.UnixMilli(),
		ExpiresMs: now.Add(24 * time.Hour).UnixMilli(), Payload: p}, a.priv)
	if err != nil {
		t.Fatal(err)
	}
	return rec, append(append([]byte{}, a.id...), id...)
}

func members(t *testing.T, n *node, names ...string) ([]*acct, []*client) {
	var as []*acct
	var cs []*client
	for _, name := range names {
		secret := netInvite(t, n)
		c := dial(t, n)
		a, req := registerReq(t, n, secret, name)
		if st, msg := c.call("register", req, nil); st != pb.Status_STATUS_OK {
			t.Fatalf("register %s: %v %s", name, st, msg)
		}
		login(t, c, a)
		as, cs = append(as, a), append(cs, c)
	}
	return as, cs
}

func TestBlobEndToEnd(t *testing.T) {
	n := startNode(t)
	as, cs := members(t, n, "anna", "boris", "carol")
	anna, boris := as[0], as[1]
	ca, cb, cc := cs[0], cs[1], cs[2]
	data := make([]byte, 600<<10)
	rand.Read(data)
	meta, key := blobMeta(t, anna, data, boris)

	var st pb.BlobStatus
	if s, msg := ca.call("blob.create", &pb.RecordRequest{Record: meta}, &st); s != pb.Status_STATUS_OK || st.Chunks != 3 || len(st.Missing) != 3 {
		t.Fatalf("create: %v %s %+v", s, msg, &st)
	}
	// a reader can't download a chunk that isn't uploaded yet (single node: retry later)
	if s, _ := cb.call("blob.get", &pb.BlobGetRequest{BlobKey: key, Index: 0}, nil); s != pb.Status_STATUS_RETRY_LATER {
		t.Fatalf("get before put: %v", s)
	}
	bad := append([]byte{}, data[:chunk]...)
	bad[0] ^= 1
	if s, _ := ca.call("blob.put", &pb.BlobPutRequest{BlobKey: key, Index: 0, Data: bad}, nil); s != pb.Status_STATUS_INVALID {
		t.Fatalf("bad hash: %v", s)
	}
	if s, _ := ca.call("blob.put", &pb.BlobPutRequest{BlobKey: key, Index: 3, Data: data[:10]}, nil); s != pb.Status_STATUS_INVALID {
		t.Fatalf("index out of range: %v", s)
	}
	if s, _ := cb.call("blob.put", &pb.BlobPutRequest{BlobKey: key, Index: 0, Data: data[:chunk]}, nil); s != pb.Status_STATUS_UNAUTHORIZED {
		t.Fatalf("put by a reader: %v", s)
	}
	for i := 0; i < 3; i++ {
		part := data[i*chunk : min((i+1)*chunk, len(data))]
		if s, msg := ca.call("blob.put", &pb.BlobPutRequest{BlobKey: key, Index: uint32(i), Data: part}, nil); s != pb.Status_STATUS_OK {
			t.Fatalf("put %d: %v %s", i, s, msg)
		}
	}
	if s, _ := ca.call("blob.put", &pb.BlobPutRequest{BlobKey: key, Index: 2, Data: data[2*chunk:]}, nil); s != pb.Status_STATUS_OK {
		t.Fatalf("re-put: %v", s)
	}
	// re-creating is idempotent and reports nothing missing
	if s, _ := ca.call("blob.create", &pb.RecordRequest{Record: meta}, &st); s != pb.Status_STATUS_OK || len(st.Missing) != 0 {
		t.Fatalf("re-create: %v %+v", s, &st)
	}
	var got []byte
	for i := 0; i < 3; i++ {
		var c pb.BlobChunk
		if s, msg := cb.call("blob.get", &pb.BlobGetRequest{BlobKey: key, Index: uint32(i)}, &c); s != pb.Status_STATUS_OK {
			t.Fatalf("get %d: %v %s", i, s, msg)
		}
		got = append(got, c.Data...)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("downloaded bytes differ")
	}
	if s, _ := cc.call("blob.get", &pb.BlobGetRequest{BlobKey: key, Index: 0}, nil); s != pb.Status_STATUS_UNAUTHORIZED {
		t.Fatalf("non-reader: %v", s)
	}
	if s, _ := cb.call("blob.get", &pb.BlobGetRequest{BlobKey: append(r16(), r16()...), Index: 0}, nil); s != pb.Status_STATUS_RETRY_LATER {
		t.Fatalf("unknown blob: %v", s)
	}
	ack := sign(t, pb.RecordType_BLOB_FETCHED, boris.id, &pb.BlobFetched{BlobKey: key}, boris.priv)
	if s, msg := cb.call("blob.ack", &pb.RecordRequest{Record: ack}, nil); s != pb.Status_STATUS_OK {
		t.Fatalf("ack: %v %s", s, msg)
	}
	if s, _ := cb.call("blob.get", &pb.BlobGetRequest{BlobKey: key, Index: 0}, nil); s != pb.Status_STATUS_NOT_FOUND {
		t.Fatalf("after ack: %v", s)
	}
	if removed, err := n.svc.SweepBlobFiles(context.Background()); err != nil || removed != 1 {
		t.Fatalf("sweep: %d %v", removed, err)
	}
	if keys, _ := n.svc.Blobs.Keys(); len(keys) != 0 {
		t.Fatal("files left")
	}
	if s, _ := ca.call("blob.create", &pb.RecordRequest{Record: meta}, nil); s != pb.Status_STATUS_NOT_FOUND {
		t.Fatalf("re-create after deletion: %v", s)
	}
}

func TestBlobQuota(t *testing.T) {
	n := startNode(t)
	n.svc.Limits.UserQuota = 1 << 20
	as, cs := members(t, n, "anna", "boris")
	data := make([]byte, 600<<10)
	m1, _ := blobMeta(t, as[0], data, as[1])
	m2, _ := blobMeta(t, as[0], data, as[1])
	if s, msg := cs[0].call("blob.create", &pb.RecordRequest{Record: m1}, nil); s != pb.Status_STATUS_OK {
		t.Fatalf("first: %v %s", s, msg)
	}
	if s, _ := cs[0].call("blob.create", &pb.RecordRequest{Record: m1}, nil); s != pb.Status_STATUS_OK {
		t.Fatalf("idempotent create counted twice: %v", s)
	}
	if s, _ := cs[0].call("blob.create", &pb.RecordRequest{Record: m2}, nil); s != pb.Status_STATUS_QUOTA {
		t.Fatalf("second: %v", s)
	}
	n.svc.Limits.MaxBlob = 100 << 10
	m3, _ := blobMeta(t, as[1], data, as[0])
	if s, _ := cs[1].call("blob.create", &pb.RecordRequest{Record: m3}, nil); s != pb.Status_STATUS_QUOTA {
		t.Fatalf("max_blob: %v", s)
	}
	// someone else's meta
	if s, _ := cs[1].call("blob.create", &pb.RecordRequest{Record: m2}, nil); s != pb.Status_STATUS_UNAUTHORIZED {
		t.Fatalf("foreign meta: %v", s)
	}
}

func TestBlobNeedsLogin(t *testing.T) {
	n := startNode(t)
	c := dial(t, n)
	if s, _ := c.call("blob.get", &pb.BlobGetRequest{BlobKey: make([]byte, 32)}, nil); s != pb.Status_STATUS_UNAUTHORIZED {
		t.Fatalf("pre-login get: %v", s)
	}
}
