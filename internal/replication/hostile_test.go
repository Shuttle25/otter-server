package replication

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"ottermsg/server/internal/blobs"
	pb "ottermsg/server/internal/proto/otterv1"
)

// A member node turned hostile (it holds b's real node key) asks node a for blob chunks with malformed keys.
// Before the fix an empty key panicked a's chunk goroutine and stopped the whole node (C11).
func TestHostilePeerMalformedBlobKeys(t *testing.T) {
	m := newMesh(t, 2, false)
	a, b := m.nodes[0], m.nodes[1]
	bd, err := blobs.New(filepath.Join(t.TempDir(), "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	a.svc.Blobs = bd
	var aInfo *pb.NodeInfo
	for _, n := range b.svc.CurrentManifest().Nodes {
		if bytes.Equal(n.NodeId, a.id) {
			aInfo = n
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(a.srv.URL, "http")+"/x/peer", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	c.SetReadLimit(maxFrame)
	if err := b.repl.dialHandshake(ctx, c, aInfo); err != nil {
		t.Fatal(err)
	}
	ask := func(req uint64, key []byte) *pb.PeerBlobChunk {
		t.Helper()
		if err := writeFrame(ctx, c, &pb.PeerFrame{Kind: &pb.PeerFrame_BlobGet{BlobGet: &pb.PeerBlobGet{Req: req, BlobKey: key}}}); err != nil {
			t.Fatalf("req %d: send: %v", req, err)
		}
		for {
			f, _, err := readFrame(ctx, c)
			if err != nil {
				t.Fatalf("req %d (%d-byte key): session closed: %v", req, len(key), err)
			}
			if ch := f.GetBlobChunk(); ch != nil && ch.Req == req {
				return ch
			}
		}
	}
	for i, k := range [][]byte{nil, {0xab}, make([]byte, 31), make([]byte, 33)} {
		if ch := ask(uint64(i+1), k); !ch.Missing || ch.Data != nil {
			t.Fatalf("%d-byte key answered %+v", len(k), ch)
		}
	}
	// the same session still serves a well-formed request (unknown blob → missing)
	if ch := ask(99, make([]byte, 32)); !ch.Missing {
		t.Fatalf("valid key: %+v", ch)
	}
	if !a.repl.reg.has(b.id) {
		t.Fatal("session dropped")
	}
}
