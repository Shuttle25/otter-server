// Package meshsim runs several in-process nodes with real peer sessions and simulated partitions.
package meshsim

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
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
	"ottermsg/server/internal/netlog"
	"ottermsg/server/internal/pinning"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/push"
	"ottermsg/server/internal/reality"
	"ottermsg/server/internal/records"
	"ottermsg/server/internal/replication"
	"ottermsg/server/internal/service"
	"ottermsg/server/internal/store"
	"ottermsg/server/internal/transport/wss"
	"ottermsg/server/internal/turnsrv"
)

func TestMain(m *testing.M) {
	replication.SetTestTimings(50*time.Millisecond, 100*time.Millisecond)
	reality.SetLogger(quiet)
	os.Exit(m.Run())
}

var quiet = slog.New(slog.DiscardHandler)

const path = "/x"

type simNode struct {
	label   string
	key     ed25519.PrivateKey
	id      []byte
	dbPath  string
	addr    string
	noPull  bool         // test knob: no background chunk puller (proxy scenario)
	sender  *recSender   // non-nil: the node has an FCM key (push_test.go)
	clock   *fakeClock   // drives the pusher's coalescing window
	reality *realityInfo // non-nil: the node also serves a REALITY endpoint (reality_test.go)
	turnOn  bool         // the node runs the embedded TURN relay (turn_test.go)
	turnKey []byte       // its TURN-REST secret, kept across restarts

	mu     sync.Mutex
	st     *store.Store
	svc    *service.Service
	repl   *replication.Replicator
	srv    *httptest.Server
	cancel context.CancelFunc
	pusher *push.Pusher
	rsrv   *reality.Server  // running REALITY inbound
	isrv   *httptest.Server // internal plain-HTTP listener behind it
	turn   *turnsrv.Server
	// turnAddr serves UDP and TCP on the same port, turnTLSAddr TLS; both are re-picked on every start
	turnAddr, turnTLSAddr string
}

// realityInfo is a node's REALITY endpoint, its private key and the camouflage site it forwards probes to.
type realityInfo struct {
	ep   *pb.Endpoint
	priv string
	camo *httptest.Server
}

// nodeOpts are per-node knobs for newSimWith.
type nodeOpts struct{ reality, dialOutOnly, turn bool }

const (
	realityUUID = "d6a3f0b2-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
	realitySID  = "a1b2c3d4"
)

// newReality starts a camouflage TLS 1.3 site and describes a REALITY endpoint on a free local port.
func newReality(t *testing.T) *realityInfo {
	camo := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "camouflage") }))
	camo.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	camo.Config.ErrorLog = log.New(io.Discard, "", 0) // REALITY's own probes of the site end with handshake errors
	camo.StartTLS()
	t.Cleanup(camo.Close)
	priv, pub, err := reality.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(pub)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return &realityInfo{priv: priv, camo: camo, ep: &pb.Endpoint{Kind: pb.Endpoint_REALITY, Host: "127.0.0.1", Port: uint32(port),
		VlessUuid: realityUUID, RealityPub: raw, ShortIds: []string{realitySID}, ServerNames: []string{"camo.test"},
		Fingerprint: "chrome", Path: path}}
}

type sim struct {
	t        *testing.T
	netPub   ed25519.PublicKey
	netPriv  ed25519.PrivateKey
	nodes    []*simNode
	manifest *pb.Record
	part     *partition
}

func newSim(t *testing.T, labels ...string) *sim { return newSimWith(t, nil, labels...) }

// newSimWith is newSim with per-label options (REALITY endpoint, dial_out_only).
func newSimWith(t *testing.T, opts map[string]nodeOpts, labels ...string) *sim {
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
		n := &simNode{label: l, key: k, id: keys.ID16(k.Public().(ed25519.PublicKey)), dbPath: filepath.Join(t.TempDir(), l+".db"), addr: addr,
			turnOn: opts[l].turn}
		_, port, _ := net.SplitHostPort(addr)
		p, _ := strconv.Atoi(port)
		info := &pb.NodeInfo{NodeId: n.id, NodePub: k.Public().(ed25519.PublicKey), Label: l, DialOutOnly: opts[l].dialOutOnly,
			Endpoints: []*pb.Endpoint{{Kind: pb.Endpoint_WS_PLAIN, Host: "127.0.0.1", Port: uint32(p), Path: path}}}
		if opts[l].reality {
			n.reality = newReality(t)
			info.Endpoints = append(info.Endpoints, n.reality.ep) // after WS_PLAIN, as `otter-admin node add-reality` does
		}
		infos = append(infos, info)
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
			s.part.mu.Lock()
			rc := s.part.reality[string(n.id)]
			s.part.mu.Unlock()
			if rc != nil {
				rc.(*reality.Client).Close()
			}
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

// nodeInfos returns a copy of the current manifest's nodes.
func (s *sim) nodeInfos() []*pb.NodeInfo {
	var m pb.Manifest
	var body pb.RecordBody
	proto.Unmarshal(s.manifest.Body, &body)
	proto.Unmarshal(body.Payload, &m)
	var out []*pb.NodeInfo
	for _, n := range m.Nodes {
		out = append(out, proto.Clone(n).(*pb.NodeInfo))
	}
	return out
}

// publishManifest signs manifest version v with infos and loads it on every running node.
func (s *sim) publishManifest(v uint64, infos []*pb.NodeInfo) {
	s.manifest = s.signManifest(v, infos)
	for _, n := range s.nodes {
		n.mu.Lock()
		up := n.srv != nil
		n.mu.Unlock()
		if !up {
			continue
		}
		if _, err := n.svc.ImportRecord(context.Background(), s.manifest); err != nil {
			s.t.Fatal(err)
		}
		eventually(s.t, n.label+" loads manifest", func() bool { return n.svc.CurrentManifest().GetVersion() == v })
	}
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
	if n.sender != nil {
		p := push.New(n.sender, st, quiet)
		if n.clock != nil {
			p.Now = n.clock.now
		}
		svc.Waker = p
		n.pusher = p
	}
	if _, err := svc.LoadManifest(context.Background()); err != nil {
		s.t.Fatal(err)
	}
	var ts *turnsrv.Server
	var turnAddr, turnTLSAddr string
	if n.turnOn { // before serving: sessions read svc.Turn without a lock (as otter-node run)
		var iss turnsrv.Issuer
		ts, iss, turnAddr, turnTLSAddr = s.startTurn(n)
		svc.Turn = iss
	}
	gw := gateway.New(svc, quiet)
	s.part.ensureReality(n.id) // before the replicator's first dial
	rank, nl := replication.NewRanker(time.Now), netlog.StoreLogger{S: st}
	repl := replication.New(svc, s.part.dialer(n.id, rank, nl), quiet, replication.WithNetlog(nl, rank))
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
	var isrv *httptest.Server
	var rsrv *reality.Server
	if n.reality != nil {
		isrv = httptest.NewServer(wss.NewServer(wss.Config{Path: path}, gw, replication.WithListener(repl, "reality")).Handler)
		r := n.reality
		for i := 0; i < 50; i++ { // the REALITY port may linger briefly after a stop
			if rsrv, err = reality.StartServer(reality.ServerConfig{Listen: net.JoinHostPort(r.ep.Host, strconv.Itoa(int(r.ep.Port))),
				PrivateKey: r.priv, Dest: r.camo.Listener.Addr().String(), ServerNames: r.ep.ServerNames, ShortIDs: r.ep.ShortIds,
				VlessUUID: r.ep.VlessUuid, Forward: isrv.Listener.Addr().String()}); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			s.t.Fatal(err)
		}
	}
	n.mu.Lock()
	n.st, n.svc, n.repl, n.srv, n.cancel, n.isrv, n.rsrv = st, svc, repl, srv, cancel, isrv, rsrv
	n.turn, n.turnAddr, n.turnTLSAddr = ts, turnAddr, turnTLSAddr
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
	if n.rsrv != nil {
		n.rsrv.Close()
		n.isrv.CloseClientConnections()
		n.isrv.Close()
		n.rsrv, n.isrv = nil, nil
	}
	if n.turn != nil {
		n.turn.Close()
		n.turn = nil
	}
	n.srv.CloseClientConnections()
	n.srv.Close()
	n.st.Close()
	n.srv = nil
}

// Relay ports shared by every node of a sim. On one host all relays have the same IP (127.0.0.1), and a relay drops
// writes to its own address unless the port is one of its relay ports, so one shared range stands in for "another
// node's public IP" (on real nodes the ranges are per host). pion retries a busy port.
const simRelayMin, simRelayMax = 53000, 53040

// startTurn starts n's relay on fresh loopback ports (UDP and TCP on one port, TLS on another) with a self-signed
// certificate and returns it with the issuer for svc.Turn.
func (s *sim) startTurn(n *simNode) (*turnsrv.Server, turnsrv.Issuer, string, string) {
	if n.turnKey == nil {
		n.turnKey = make([]byte, turnsrv.SecretLen)
		rand.Read(n.turnKey)
	}
	certPEM, keyPEM, _, err := pinning.GenerateCert([]string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, time.Hour)
	if err != nil {
		s.t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		s.t.Fatal(err)
	}
	for i := 0; i < 20; i++ { // a free TCP port may be taken for UDP (or by now): pick again
		p, tp := freeTCPPort(s.t), freeTCPPort(s.t)
		addr, tlsAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(p)), net.JoinHostPort("127.0.0.1", strconv.Itoa(tp))
		srv, err := turnsrv.Start(turnsrv.Config{UDPListen: addr, TCPListen: addr, TLSListen: tlsAddr,
			TLS:     &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
			RelayIP: net.IPv4(127, 0, 0, 1), PortMin: simRelayMin, PortMax: simRelayMax, Secret: n.turnKey, Realm: "otter",
			MaxPerUser: 4, MaxTotal: 16, RelayKbps: 2000, AllowPrivatePeers: true, Log: quiet})
		if err != nil {
			continue
		}
		return srv, turnsrv.Issuer{Secret: n.turnKey, RelayIP: "127.0.0.1", TLS: true, UDPPort: p, TCPPort: p, TLSPort: tp},
			addr, tlsAddr
	}
	s.t.Fatal("turn: no free ports")
	return nil, turnsrv.Issuer{}, "", ""
}

func freeTCPPort(t *testing.T) int {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
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
