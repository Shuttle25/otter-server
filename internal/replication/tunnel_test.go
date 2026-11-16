package replication

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

// markNoBackups publishes manifest v2 in which the given nodes are marked no_backups.
func (m *mesh) markNoBackups(idx ...int) {
	man := m.nodes[0].svc.CurrentManifest()
	var nodes []*pb.NodeInfo
	for _, n := range man.Nodes {
		n = proto.Clone(n).(*pb.NodeInfo)
		for _, i := range idx {
			if bytes.Equal(n.NodeId, m.nodes[i].id) {
				n.NoBackups = true
			}
		}
		nodes = append(nodes, n)
	}
	man2 := m.sign(pb.RecordType_MANIFEST, keys.ID16(m.netPub), &pb.Manifest{Version: man.Version + 1, NetworkPub: m.netPub, Nodes: nodes}, m.netPriv)
	for _, nd := range m.nodes {
		if _, err := nd.svc.ImportRecord(context.Background(), man2); err != nil {
			m.t.Fatal(err)
		}
	}
}

func (m *mesh) session(from, to int) *session {
	var s *session
	eventually(m.t, "session up", func() bool { s = m.nodes[from].repl.reg.get(m.nodes[to].id); return s != nil })
	return s
}

func closedWithin(tn *tunnel, d time.Duration) bool {
	select {
	case <-tn.done:
		return true
	case <-time.After(d):
		return false
	}
}

// acceptOne reports a connection the listener yields within d.
func acceptOne(ln net.Listener) chan net.Conn {
	got := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			got <- c
		}
	}()
	return got
}

// D114: a node accepts a tunnel only from a peer marked no_backups and only while it serves its tunnel listener.
func TestTunnelRefusedFromPeerWithoutNoBackups(t *testing.T) {
	m := newMesh(t, 2, false)
	m.start()
	ln := m.nodes[1].repl.TunnelListener()
	got := acceptOne(ln)
	tn, err := m.session(0, 1).openTunnel()
	if err != nil {
		t.Fatal(err)
	}
	if !closedWithin(tn, 2*time.Second) {
		t.Fatal("open from a peer without no_backups not refused")
	}
	select {
	case <-got:
		t.Fatal("a refused tunnel reached the listener")
	case <-time.After(time.Second):
	}
}

func TestTunnelRefusedWithoutListener(t *testing.T) {
	m := newMesh(t, 2, false)
	m.markNoBackups(0)
	m.start()
	tn, err := m.session(0, 1).openTunnel()
	if err != nil {
		t.Fatal(err)
	}
	if !closedWithin(tn, 2*time.Second) {
		t.Fatal("a node without a tunnel listener accepted a tunnel")
	}
}

// Bytes flow both ways through the peer session, with flow control, whichever side dialed it.
func TestTunnelRelaysBothWays(t *testing.T) {
	m := newMesh(t, 2, false)
	m.markNoBackups(0)
	m.start()
	ln := m.nodes[1].repl.TunnelListener()
	got := acceptOne(ln)
	s := m.session(0, 1)
	tn, err := s.openTunnel()
	if err != nil {
		t.Fatal(err)
	}
	phone, relay := net.Pipe()
	go s.runTunnel(tn, relay, false)
	var far net.Conn
	select {
	case far = <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("tunnel never reached the listener")
	}
	if got := far.RemoteAddr().String(); got != "tunnel:"+hex.EncodeToString(m.nodes[0].id) {
		t.Fatalf("tunnel source %q", got)
	}
	up, down := make([]byte, 2<<20), make([]byte, 1<<20) // ≫ window × chunk: needs acks
	rand.Read(up)
	rand.Read(down)
	errc := make(chan error, 2)
	go func() { _, err := phone.Write(up); errc <- err }()
	go func() { _, err := far.Write(down); errc <- err }()
	gotUp, gotDown := make([]byte, len(up)), make([]byte, len(down))
	go func() { _, err := io.ReadFull(phone, gotDown); errc <- err }()
	if _, err := io.ReadFull(far, gotUp); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(gotUp, up) || !bytes.Equal(gotDown, down) {
		t.Fatal("bytes changed in the tunnel")
	}
	far.Close()
	if !closedWithin(tn, 2*time.Second) {
		t.Fatal("closing the far end did not end the tunnel")
	}
}

// Hostile no_backups peer: ignoring the window, oversized frames and too many streams cost it its streams, never
// unbounded memory on the receiving node.
func TestTunnelHostilePeerFlood(t *testing.T) {
	m := newMesh(t, 2, false)
	m.markNoBackups(0)
	m.start()
	m.nodes[1].repl.TunnelListener() // served, but nobody accepts: the far side never reads
	s := m.session(0, 1)
	data := func(id uint64, n int) *pb.PeerFrame {
		return &pb.PeerFrame{Kind: &pb.PeerFrame_TunnelData{TunnelData: &pb.PeerTunnelData{Stream: id, Data: make([]byte, n)}}}
	}

	tn, err := s.openTunnel()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3*tunnelWindow; i++ { // no acks awaited
		s.send(data(tn.id, tunnelChunk))
	}
	if !closedWithin(tn, 2*time.Second) {
		t.Fatal("a peer ignoring the window kept its stream")
	}

	tn, err = s.openTunnel()
	if err != nil {
		t.Fatal(err)
	}
	s.send(data(tn.id, tunnelChunk+1))
	if !closedWithin(tn, 2*time.Second) {
		t.Fatal("an oversized data frame was accepted")
	}

	for i := uint64(0); i < 3*maxTunnelsPerPeer; i++ { // raw opens, past this node's own limit
		s.send(&pb.PeerFrame{Kind: &pb.PeerFrame_TunnelOpen{TunnelOpen: &pb.PeerTunnelOpen{Stream: 1000 + i}}})
	}
	far := m.session(1, 0)
	eventually(t, "streams opened", func() bool { far.tmu.Lock(); defer far.tmu.Unlock(); return len(far.tunnels) > 0 })
	time.Sleep(300 * time.Millisecond)
	far.tmu.Lock()
	n := len(far.tunnels)
	far.tmu.Unlock()
	if n > maxTunnelsPerPeer {
		t.Fatalf("%d streams from one peer", n)
	}

	// acks cannot raise the window above 32
	tn = newTunnel(1)
	tn.addCredit(1 << 20)
	if tn.credit.Load() != tunnelWindow {
		t.Fatalf("credit %d", tn.credit.Load())
	}
}

// ServeTunnel: only a no_backups node serves it; unknown, self and no_backups targets are 404; no session → 503.
func TestServeTunnelRules(t *testing.T) {
	m := newMesh(t, 3, true) // gated: no sessions yet
	m.markNoBackups(0, 2)
	m.start()
	code := func(n int, to []byte) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/x/tunnel?to="+hex.EncodeToString(to), nil)
		m.nodes[n].repl.ServeTunnel(rec, req)
		return rec.Code
	}
	cases := []struct {
		name string
		node int
		to   []byte
		want int
	}{
		{"self", 0, m.nodes[0].id, http.StatusNotFound},
		{"unknown", 0, bytes.Repeat([]byte{7}, 16), http.StatusNotFound},
		{"no_backups target", 0, m.nodes[2].id, http.StatusNotFound},
		{"served by a node without no_backups", 1, m.nodes[0].id, http.StatusNotFound},
		{"no session", 0, m.nodes[1].id, http.StatusServiceUnavailable},
	}
	for _, c := range cases {
		if got := code(c.node, c.to); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
	var l tunnelLimits
	for i := 0; i < maxTunnelsPerIP; i++ {
		if !l.acquire("a") {
			t.Fatal("refused under the per-IP limit")
		}
	}
	if l.acquire("a") {
		t.Fatal("per-IP limit not enforced")
	}
	l.release("a")
	for i := 0; i < maxTunnels-maxTunnelsPerIP+1; i++ {
		l.acquire(strconv.Itoa(i))
	}
	if l.acquire("zz") {
		t.Fatal("per-node limit not enforced")
	}
}
