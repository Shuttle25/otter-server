// Package meshsim runs several in-process nodes with real peer sessions and simulated partitions.
package meshsim

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/blobs"
	"ottermsg/server/internal/gateway"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
	"ottermsg/server/internal/replication"
	"ottermsg/server/internal/service"
	"ottermsg/server/internal/store"
	"ottermsg/server/internal/transport/wss"
)

func TestMain(m *testing.M) {
	replication.SetTestTimings(50*time.Millisecond, 100*time.Millisecond)
	os.Exit(m.Run())
}

var quiet = slog.New(slog.DiscardHandler)

const path = "/x"

type simNode struct {
	label  string
	key    ed25519.PrivateKey
	id     []byte
	dbPath string
	addr   string
	noPull bool // test knob: no background chunk puller (proxy scenario)

	mu     sync.Mutex
	st     *store.Store
	svc    *service.Service
	repl   *replication.Replicator
	srv    *httptest.Server
	cancel context.CancelFunc
}

type sim struct {
	t        *testing.T
	netPub   ed25519.PublicKey
	netPriv  ed25519.PrivateKey
	nodes    []*simNode
	manifest *pb.Record
	part     *partition
}

func newSim(t *testing.T, labels ...string) *sim {
	pub, priv, _ := ed25519.GenerateKey(nil)
	s := &sim{t: t, netPub: pub, netPriv: priv, part: newPartition()}
	var infos []*pb.NodeInfo
	for _, l := range labels {
		_, k, _ := ed25519.GenerateKey(nil)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		ln.Close()
		n := &simNode{label: l, key: k, id: keys.ID16(k.Public().(ed25519.PublicKey)), dbPath: filepath.Join(t.TempDir(), l+".db"), addr: addr}
		_, port, _ := net.SplitHostPort(addr)
		p, _ := strconv.Atoi(port)
		infos = append(infos, &pb.NodeInfo{NodeId: n.id, NodePub: k.Public().(ed25519.PublicKey), Label: l,
			Endpoints: []*pb.Endpoint{{Kind: pb.Endpoint_WS_PLAIN, Host: "127.0.0.1", Port: uint32(p), Path: path}}})
		s.nodes = append(s.nodes, n)
	}
	s.manifest = s.signManifest(1, infos)
	for _, n := range s.nodes {
		s.start(n)
		if _, err := n.svc.ImportRecord(context.Background(), s.manifest); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, n := range s.nodes {
			s.stop(n)
		}
	})
	return s
}

func (s *sim) node(label string) *simNode {
	for _, n := range s.nodes {
		if n.label == label {
			return n
		}
	}
	s.t.Fatalf("no node %s", label)
	return nil
}

func (s *sim) signManifest(version uint64, nodes []*pb.NodeInfo) *pb.Record {
	return s.sign(pb.RecordType_MANIFEST, keys.ID16(s.netPub), &pb.Manifest{Version: version, IssuedMs: time.Now().UnixMilli(),
		NetworkPub: s.netPub, Nodes: nodes}, s.netPriv)
}

func (s *sim) sign(typ pb.RecordType, author []byte, payload proto.Message, k ed25519.PrivateKey) *pb.Record {
	p, _ := proto.Marshal(payload)
	id := make([]byte, 16)
	rand.Read(id)
	r, err := records.Sign(&pb.RecordBody{Id: id, Type: typ, Author: author, CreatedMs: time.Now().UnixMilli(), Payload: p}, k)
	if err != nil {
		s.t.Fatal(err)
	}
	return r
}

// start (re)starts a node on its address and database file.
func (s *sim) start(n *simNode) {
	st, err := store.Open(n.dbPath)
	if err != nil {
		s.t.Fatal(err)
	}
	svc := service.New(st, n.key, s.netPub)
	svc.Log = quiet
	bd, err := blobs.New(filepath.Join(filepath.Dir(n.dbPath), "blobs-"+n.label))
	if err != nil {
		s.t.Fatal(err)
	}
	svc.Blobs = bd
	if _, err := svc.LoadManifest(context.Background()); err != nil {
		s.t.Fatal(err)
	}
	gw := gateway.New(svc, quiet)
	repl := replication.New(svc, s.part.dialer(n.id), quiet)
	ctx, cancel := context.WithCancel(context.Background())
	go repl.Run(ctx)
	svc.Fetcher = repl
	if !n.noPull {
		go repl.RunPuller(ctx, 0)
	}
	var ln net.Listener
	for i := 0; i < 50; i++ { // the port may linger briefly after a stop
		if ln, err = net.Listen("tcp", n.addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		s.t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(wss.NewServer(wss.Config{Path: path}, gw, repl).Handler)
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	n.mu.Lock()
	n.st, n.svc, n.repl, n.srv, n.cancel = st, svc, repl, srv, cancel
	n.mu.Unlock()
	s.part.register(n.id, repl)
}

// stop shuts a node down: peer sessions end (run context), clients are disconnected by the caller.
func (s *sim) stop(n *simNode) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.srv == nil {
		return
	}
	n.cancel()
	n.srv.CloseClientConnections()
	n.srv.Close()
	n.st.Close()
	n.srv = nil
}

func (s *sim) url(n *simNode) string { return "ws://" + n.addr + path }

// invite imports a network-signed bootstrap invite on node n and returns its secret.
func (s *sim) invite(n *simNode) []byte {
	secret := make([]byte, 32)
	rand.Read(secret)
	sum := sha256.Sum256(secret)
	inv := s.sign(pb.RecordType_INVITE, keys.ID16(s.netPub), &pb.Invite{InviteId: sum[:], ExpiresMs: time.Now().Add(time.Hour).UnixMilli()}, s.netPriv)
	if _, err := n.svc.ImportRecord(context.Background(), inv); err != nil {
		s.t.Fatal(err)
	}
	return secret
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	eventuallyWithin(t, 10*time.Second, what, cond)
}

// eventuallyWithin is eventually with a longer budget (blob copies of many MiB under -race and a loaded machine).
func eventuallyWithin(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for: %s", d, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (n *simNode) knows(u *account) bool {
	x, _ := n.st.UserByID(context.Background(), u.id)
	return x != nil
}

func (n *simNode) mailbox(u *account) int {
	b, _ := n.st.Mailbox(context.Background(), u.id, 1, 1000)
	return len(b)
}

func (n *simNode) has(key []byte) bool {
	_, err := n.st.Get(context.Background(), key)
	return err == nil
}

func (n *simNode) recordKeys() string {
	ks, _ := n.st.RecordKeys(context.Background())
	return fmt.Sprintf("%x", ks)
}
