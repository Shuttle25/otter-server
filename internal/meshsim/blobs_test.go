package meshsim

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

// putBlob signs a BLOB_META for data, creates it through c and uploads every chunk; returns the blob key.
func (s *sim) putBlob(c *client, a *account, data []byte, readers ...*account) []byte {
	m := &pb.BlobMeta{Size: uint64(len(data)), ChunkSize: chunk}
	for off := 0; off < len(data); off += chunk {
		h := sha256.Sum256(data[off:min(off+chunk, len(data))])
		m.ChunkSha256 = append(m.ChunkSha256, h[:])
	}
	for _, r := range readers {
		m.Readers = append(m.Readers, r.id)
	}
	p, _ := proto.Marshal(m)
	id := make([]byte, 16)
	rand.Read(id)
	now := time.Now()
	rec, err := records.Sign(&pb.RecordBody{Id: id, Type: pb.RecordType_BLOB_META, Author: a.id, CreatedMs: now.UnixMilli(),
		ExpiresMs: now.Add(24 * time.Hour).UnixMilli(), Payload: p}, a.priv)
	if err != nil {
		s.t.Fatal(err)
	}
	var st pb.BlobStatus
	c.mustCall("blob.create", &pb.RecordRequest{Record: rec}, &st)
	key := append(append([]byte{}, a.id...), id...)
	for _, i := range st.Missing {
		c.mustCall("blob.put", &pb.BlobPutRequest{BlobKey: key, Index: i, Data: data[int(i)*chunk : min((int(i)+1)*chunk, len(data))]}, nil)
	}
	return key
}

// getBlob downloads every chunk through c; returns the bytes or the first non-OK status.
func (s *sim) getBlob(c *client, key []byte, chunks int) ([]byte, pb.Status) {
	var out []byte
	for i := 0; i < chunks; i++ {
		var b pb.BlobChunk
		if st, _ := c.call("blob.get", &pb.BlobGetRequest{BlobKey: key, Index: uint32(i)}, &b); st != pb.Status_STATUS_OK {
			return nil, st
		}
		out = append(out, b.Data...)
	}
	return out, pb.Status_STATUS_OK
}

func (s *sim) ackBlob(c *client, a *account, key []byte) {
	c.mustCall("blob.ack", &pb.RecordRequest{Record: s.signAs(a, pb.RecordType_BLOB_FETCHED, &pb.BlobFetched{BlobKey: key})}, nil)
}

func (n *simNode) hasChunks(key []byte, want int) bool {
	have, err := n.st.BlobChunks(context.Background(), key)
	return err == nil && len(have) == want
}

// blobGone: no blob row, no meta record, a tombstone, and (after a sweep) no files.
func (n *simNode) blobGone(key []byte) bool {
	ctx := context.Background()
	if _, err := n.st.Blob(ctx, key); err == nil {
		return false
	}
	if _, err := n.st.Get(ctx, key); err == nil {
		return false
	}
	if gone, _ := n.st.BlobGone(ctx, key); !gone {
		return false
	}
	if _, err := n.svc.SweepBlobFiles(ctx); err != nil {
		return false
	}
	ks, _ := n.svc.Blobs.Keys()
	for _, k := range ks {
		if bytes.Equal(k, key) {
			return false
		}
	}
	return true
}

func randomBytes(n int) []byte { b := make([]byte, n); rand.Read(b); return b }

// Acceptance (M4): a 20 MiB blob uploaded via A reaches its reader on C while A is down; afterwards it is gone everywhere.
func TestBlob20MiBWithUploadNodeDown(t *testing.T) {
	s := newSim(t, "a", "b", "c")
	a, b, c := s.node("a"), s.node("b"), s.node("c")
	anna := s.register(a, "anna")
	boris := s.register(a, "boris")
	eventually(t, "accounts everywhere", func() bool { return c.knows(anna) && c.knows(boris) && b.knows(boris) })
	data := randomBytes(20 << 20)
	ca := s.login(a, anna)
	key := s.putBlob(ca, anna, data, boris)
	ca.close()
	eventuallyWithin(t, time.Minute, "B and C pull all 80 chunks", func() bool { return b.hasChunks(key, 80) && c.hasChunks(key, 80) })
	s.stop(a)
	cb := s.login(c, boris)
	got, st := s.getBlob(cb, key, 80)
	if st != pb.Status_STATUS_OK || !bytes.Equal(got, data) {
		t.Fatalf("download via C with A down: %v", st)
	}
	s.ackBlob(cb, boris, key)
	s.start(a)
	eventuallyWithin(t, time.Minute, "blob gone on every node", func() bool { return a.blobGone(key) && b.blobGone(key) && c.blobGone(key) })
}

// Proxy: C has no puller; a reader on C gets the chunks at once (C fetches them from a peer) and C keeps them.
func TestBlobProxy(t *testing.T) {
	s := newSim(t, "a", "b", "c")
	a, c := s.node("a"), s.node("c")
	s.stop(c)
	c.noPull = true
	s.start(c)
	anna := s.register(a, "anna")
	boris := s.register(a, "boris")
	eventually(t, "accounts on C", func() bool { return c.knows(anna) && c.knows(boris) })
	data := randomBytes(600 << 10)
	key := s.putBlob(s.login(a, anna), anna, data, boris)
	eventually(t, "meta on C", func() bool { _, err := c.st.Blob(context.Background(), key); return err == nil })
	if c.hasChunks(key, 3) {
		t.Fatal("C pulled without a puller")
	}
	got, st := s.getBlob(s.login(c, boris), key, 3)
	if st != pb.Status_STATUS_OK || !bytes.Equal(got, data) {
		t.Fatalf("proxied download: %v", st)
	}
	if !c.hasChunks(key, 3) {
		t.Fatal("C did not keep the proxied chunks")
	}
}

// Not replicated yet: a reader on C asks before the meta arrives → RETRY_LATER; after healing it works.
func TestBlobNotReplicatedYet(t *testing.T) {
	s := newSim(t, "a", "b", "c")
	a, b, c := s.node("a"), s.node("b"), s.node("c")
	anna := s.register(a, "anna")
	boris := s.register(a, "boris")
	eventually(t, "accounts on C", func() bool { return c.knows(anna) && c.knows(boris) && b.knows(boris) })
	s.part.Block(a, b)
	s.part.Block(a, c)
	data := randomBytes(300 << 10)
	key := s.putBlob(s.login(a, anna), anna, data, boris)
	cb := s.login(c, boris)
	if _, st := s.getBlob(cb, key, 2); st != pb.Status_STATUS_RETRY_LATER {
		t.Fatalf("before replication: %v", st)
	}
	s.part.Heal(a, b)
	s.part.Heal(a, c)
	eventuallyWithin(t, time.Minute, "download after healing", func() bool {
		got, st := s.getBlob(cb, key, 2)
		return st == pb.Status_STATUS_OK && bytes.Equal(got, data)
	})
}

// Partition A↔C: the upload via A reaches C through B.
func TestBlobAcrossPartition(t *testing.T) {
	s := newSim(t, "a", "b", "c")
	a, b, c := s.node("a"), s.node("b"), s.node("c")
	anna := s.register(a, "anna")
	boris := s.register(a, "boris")
	eventually(t, "accounts on C", func() bool { return c.knows(anna) && c.knows(boris) && b.knows(boris) })
	s.part.Block(a, c)
	data := randomBytes(700 << 10)
	key := s.putBlob(s.login(a, anna), anna, data, boris)
	eventuallyWithin(t, time.Minute, "C pulls from B", func() bool { return c.hasChunks(key, 3) })
	got, st := s.getBlob(s.login(c, boris), key, 3)
	if st != pb.Status_STATUS_OK || !bytes.Equal(got, data) {
		t.Fatalf("download on C: %v", st)
	}
}
