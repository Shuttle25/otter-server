package replication

import (
	"bytes"
	"context"
	"crypto/sha256"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/blobs"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

// Node b is marked no_backups (D113). Even with its real node key it gets no backup chunk from a, while a still
// answers its PeerHoldsQuery; a vouches only for what it holds completely.
func TestNoBackupsPeerGetsNoBackupChunks(t *testing.T) {
	m := newMesh(t, 2, false)
	a, b := m.nodes[0], m.nodes[1]
	bd, err := blobs.New(filepath.Join(t.TempDir(), "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	a.svc.Blobs = bd
	man := a.svc.CurrentManifest()
	nodes := make([]*pb.NodeInfo, 0, len(man.Nodes))
	var aInfo *pb.NodeInfo
	for _, n := range man.Nodes {
		n = proto.Clone(n).(*pb.NodeInfo)
		if bytes.Equal(n.NodeId, b.id) {
			n.NoBackups = true
		}
		if bytes.Equal(n.NodeId, a.id) {
			aInfo = n
		}
		nodes = append(nodes, n)
	}
	man2 := m.sign(pb.RecordType_MANIFEST, keys.ID16(m.netPub), &pb.Manifest{Version: 2, NetworkPub: m.netPub, Nodes: nodes}, m.netPriv)
	for _, nd := range m.nodes {
		if _, err := nd.svc.ImportRecord(context.Background(), man2); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	anna := m.register(0, "anna")
	blob := func(persistent bool, data []byte) []byte {
		h := sha256.Sum256(data)
		bm := &pb.BlobMeta{Size: uint64(len(data)), ChunkSize: records.BlobChunkSize, ChunkSha256: [][]byte{h[:]}, Persistent: persistent}
		body := &pb.RecordBody{Id: make([]byte, 16), Type: pb.RecordType_BLOB_META, Author: anna.id, CreatedMs: time.Now().UnixMilli()}
		copy(body.Id, data)
		if !persistent {
			bm.Readers = [][]byte{bytes.Repeat([]byte{9}, 16)}
			body.ExpiresMs = time.Now().Add(time.Hour).UnixMilli()
		}
		body.Payload, _ = proto.Marshal(bm)
		rec, err := records.Sign(body, anna.priv)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.svc.CreateBlob(ctx, anna.id, rec); err != nil {
			t.Fatal(err)
		}
		key := append(append([]byte{}, anna.id...), body.Id...)
		if err := a.svc.PutChunk(ctx, anna.id, key, 0, data); err != nil {
			t.Fatal(err)
		}
		return key
	}
	backup := blob(true, bytes.Repeat([]byte{1}, 1000))
	chat := blob(false, bytes.Repeat([]byte{2}, 1000))

	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(a.srv.URL, "http")+"/x/peer", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	c.SetReadLimit(maxFrame)
	if err := b.repl.dialHandshake(ctx, c, aInfo); err != nil {
		t.Fatal(err)
	}
	next := func(match func(*pb.PeerFrame) bool) *pb.PeerFrame {
		t.Helper()
		for {
			f, _, err := readFrame(ctx, c)
			if err != nil {
				t.Fatalf("session closed: %v", err)
			}
			if match(f) {
				return f
			}
		}
	}
	get := func(req uint64, key []byte) *pb.PeerBlobChunk {
		t.Helper()
		writeFrame(ctx, c, &pb.PeerFrame{Kind: &pb.PeerFrame_BlobGet{BlobGet: &pb.PeerBlobGet{Req: req, BlobKey: key}}})
		return next(func(f *pb.PeerFrame) bool { return f.GetBlobChunk() != nil && f.GetBlobChunk().Req == req }).GetBlobChunk()
	}
	holds := func(req uint64, key []byte) bool {
		t.Helper()
		writeFrame(ctx, c, &pb.PeerFrame{Kind: &pb.PeerFrame_HoldsQuery{HoldsQuery: &pb.PeerHoldsQuery{Req: req, RecordKey: key}}})
		return next(func(f *pb.PeerFrame) bool { return f.GetHolds() != nil && f.GetHolds().Req == req }).GetHolds().Held
	}
	if ch := get(1, backup); !ch.Missing || ch.Data != nil {
		t.Fatalf("backup chunk served to a node with no_backups: %d bytes", len(ch.Data))
	}
	if ch := get(2, chat); ch.Missing || len(ch.Data) != 1000 {
		t.Fatalf("chat chunk not served: missing=%v", ch.Missing)
	}
	if !holds(3, backup) {
		t.Fatal("a does not vouch for a complete blob it holds")
	}
	if holds(4, bytes.Repeat([]byte{7}, 32)) {
		t.Fatal("a vouched for an unknown key")
	}
}
