package replication

import (
	"bytes"
	"context"
	"crypto/sha256"
	"math"
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

func head(nd *tnode) int64 { st, _ := nd.st.Stats(context.Background()); return st.OplogSeq }

// peerStatus is nd's view of the peer labelled label.
func peerStatus(t *testing.T, nd *tnode, label string) PeerStatus {
	t.Helper()
	for _, p := range nd.repl.Status() {
		if p.Label == label {
			return p
		}
	}
	t.Fatalf("no peer %s in %+v", label, nd.repl.Status())
	return PeerStatus{}
}

func backlog(t *testing.T, nd *tnode, label string) (int64, int64) {
	t.Helper()
	n, lag, err := nd.repl.Backlog(context.Background(), peerStatus(t, nd, label), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return n, lag
}

// Two converged nodes see backlog 0 for each other, whichever of them dialed (D119, D132).
func TestPeerBacklogTracked(t *testing.T) {
	m := newMesh(t, 2, false)
	m.start()
	m.register(0, "anna")
	m.register(1, "boris")
	for i, other := range []string{"n1", "n0"} {
		nd := m.nodes[i]
		eventually(t, other+" confirmed everything of n"+string(rune('0'+i)), func() bool {
			p := peerStatus(t, nd, other)
			n, _, err := nd.repl.Backlog(context.Background(), p, time.Now())
			return err == nil && p.Connected && p.AckKnown && p.Acked >= head(nd) && p.LastUpMs > 0 && n == 0
		})
	}
	// the session goes away: still "last up" a moment ago, not connected
	m.cancel()
	m.nodes[0].repl.DropPeer(m.nodes[1].id)
	eventually(t, "n1 down at n0", func() bool { return !peerStatus(t, m.nodes[0], "n1").Connected })
	if p := peerStatus(t, m.nodes[0], "n1"); time.Since(time.UnixMilli(p.LastUpMs)) > 5*time.Second {
		t.Fatalf("last up: %+v", p)
	}
}

// A peer that subscribed with cursor 0 and never acks: backlog = everything we have, lag = age of the oldest.
func TestPeerThatNeverAcksShowsBacklog(t *testing.T) {
	m := newMesh(t, 2, false) // not started
	m.register(0, "anna")
	if n, _ := backlog(t, m.nodes[0], "n1"); n != -1 {
		t.Fatalf("before any subscribe: %d", n)
	}
	m.nodes[0].repl.noteSubscribed(m.nodes[1].id, 0)
	p := peerStatus(t, m.nodes[0], "n1")
	if !p.AckKnown || p.Acked != 0 || p.Connected || p.LastUpMs != 0 {
		t.Fatalf("%+v", p)
	}
	time.Sleep(1100 * time.Millisecond)
	n, lag := backlog(t, m.nodes[0], "n1")
	if n < 3 || lag < 1 {
		t.Fatalf("backlog %d lag %ds", n, lag)
	}
}

// A hostile member node (it holds b's real key) lies in its subscribe cursor and its acks. That moves only b's own
// backlog number: the honest-but-behind peer c still shows its backlog, and a's session with b survives.
func TestHostilePeerAckLiesOnlyChangeItsOwnBacklog(t *testing.T) {
	m := newMesh(t, 3, false) // not started: c (n2) is "subscribed" at 0 and silent
	a, b, c := m.nodes[0], m.nodes[1], m.nodes[2]
	m.register(0, "anna")
	m.register(0, "boris")
	a.repl.noteSubscribed(c.id, 0)
	want, _ := backlog(t, a, "n2")
	if want < 6 {
		t.Fatalf("c's backlog %d", want)
	}
	var aInfo *pb.NodeInfo
	for _, n := range b.svc.CurrentManifest().Nodes {
		if bytes.Equal(n.NodeId, a.id) {
			aInfo = n
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(a.srv.URL, "http")+"/x/peer", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	conn.SetReadLimit(maxFrame)
	if err := b.repl.dialHandshake(ctx, conn, aInfo); err != nil {
		t.Fatal(err)
	}
	go func() { // drain a's frames so its writer never blocks
		for {
			if _, _, err := readFrame(ctx, conn); err != nil {
				return
			}
		}
	}()
	send := func(f *pb.PeerFrame) {
		t.Helper()
		if err := writeFrame(ctx, conn, f); err != nil {
			t.Fatal(err)
		}
	}
	check := func(what string, ok func(n int64) bool) {
		t.Helper()
		eventually(t, what, func() bool {
			n, _ := backlog(t, a, "n1")
			return ok(n)
		})
		if n, lag := backlog(t, a, "n2"); n != want || lag < 0 {
			t.Fatalf("%s: honest peer's backlog changed: %d (want %d), lag %d", what, n, want, lag)
		}
		if !a.repl.reg.has(b.id) {
			t.Fatalf("%s: session dropped", what)
		}
	}
	send(&pb.PeerFrame{Kind: &pb.PeerFrame_Subscribe{Subscribe: &pb.PeerSubscribe{Cursor: math.MinInt64}}})
	check("absurd negative cursor = all of ours", func(n int64) bool { return n == want })
	send(&pb.PeerFrame{Kind: &pb.PeerFrame_BatchAck{BatchAck: &pb.PeerBatchAck{Seq: math.MaxInt64}}})
	check("ack beyond our head = nothing pending", func(n int64) bool { return n == 0 })
	send(&pb.PeerFrame{Kind: &pb.PeerFrame_BatchAck{BatchAck: &pb.PeerBatchAck{Seq: -5}}})
	check("a lower ack never moves it back", func(n int64) bool { return n == 0 })
	send(&pb.PeerFrame{Kind: &pb.PeerFrame_Subscribe{Subscribe: &pb.PeerSubscribe{Cursor: math.MaxInt64}}})
	check("absurd high cursor", func(n int64) bool { return n == 0 })
	if p := peerStatus(t, a, "n1"); p.Acked < 0 {
		t.Fatalf("negative ack kept: %+v", p)
	}
}

// A no_backups peer (D113) never gets backup records, so it never acks them: when they are the newest entries the
// backlog must still drop to 0 once everything else is confirmed (no false "lag" alarm on ru-1).
func TestNoBackupsPeerBacklogClears(t *testing.T) {
	m := newMesh(t, 2, false)
	a, b := m.nodes[0], m.nodes[1]
	bd, err := blobs.New(filepath.Join(t.TempDir(), "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	a.svc.Blobs = bd
	man := a.svc.CurrentManifest()
	nodes := make([]*pb.NodeInfo, 0, len(man.Nodes))
	for _, n := range man.Nodes {
		n = proto.Clone(n).(*pb.NodeInfo)
		n.NoBackups = bytes.Equal(n.NodeId, b.id)
		nodes = append(nodes, n)
	}
	man2 := m.sign(pb.RecordType_MANIFEST, keys.ID16(m.netPub), &pb.Manifest{Version: 2, NetworkPub: m.netPub, Nodes: nodes}, m.netPriv)
	for _, nd := range m.nodes {
		if _, err := nd.svc.ImportRecord(context.Background(), man2); err != nil {
			t.Fatal(err)
		}
	}
	m.start()
	anna := m.register(0, "anna")
	clear := func(what string) {
		eventually(t, what, func() bool {
			n, _, err := a.repl.Backlog(context.Background(), peerStatus(t, a, "n1"), time.Now())
			return err == nil && n == 0
		})
	}
	clear("b confirmed the registration")
	data := bytes.Repeat([]byte{1}, 1000)
	h := sha256.Sum256(data)
	bm := &pb.BlobMeta{Size: uint64(len(data)), ChunkSize: records.BlobChunkSize, ChunkSha256: [][]byte{h[:]}, Persistent: true}
	body := &pb.RecordBody{Id: bytes.Repeat([]byte{7}, 16), Type: pb.RecordType_BLOB_META, Author: anna.id, CreatedMs: time.Now().UnixMilli()}
	body.Payload, _ = proto.Marshal(bm)
	rec, err := records.Sign(body, anna.priv)
	if err != nil {
		t.Fatal(err)
	}
	before := head(a)
	if _, err := a.svc.CreateBlob(context.Background(), anna.id, rec); err != nil {
		t.Fatal(err)
	}
	if head(a) <= before {
		t.Fatal("backup blob not in the oplog")
	}
	clear("the backup-only tail is not counted against b")
}
