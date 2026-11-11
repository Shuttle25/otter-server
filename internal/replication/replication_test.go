package replication

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
	"ottermsg/server/internal/service"
	"ottermsg/server/internal/store"
)

func TestMain(m *testing.M) {
	SetTestTimings(100*time.Millisecond, 200*time.Millisecond)
	os.Exit(m.Run())
}

var quiet = slog.New(slog.DiscardHandler)

// gate lets tests decide which node pairs can dial each other.
type gate struct {
	mu    sync.Mutex
	allow map[string]bool
	inner Dialer
	self  []byte
}

func pairKey(a, b []byte) string {
	if bytes.Compare(a, b) > 0 {
		a, b = b, a
	}
	return string(a) + string(b)
}

func (g *gate) Dial(ctx context.Context, n *pb.NodeInfo) (*websocket.Conn, error) {
	g.mu.Lock()
	ok := g.allow == nil || g.allow[pairKey(g.self, n.NodeId)]
	g.mu.Unlock()
	if !ok {
		return nil, errors.New("blocked by test")
	}
	return g.inner.Dial(ctx, n)
}

type tnode struct {
	key  ed25519.PrivateKey
	id   []byte
	st   *store.Store
	svc  *service.Service
	repl *Replicator
	srv  *httptest.Server
	gate *gate
}

type mesh struct {
	t       *testing.T
	netPub  ed25519.PublicKey
	netPriv ed25519.PrivateKey
	nodes   []*tnode
	allow   map[string]bool
	cancel  context.CancelFunc
}

func newMesh(t *testing.T, n int, gated bool) *mesh {
	pub, priv, _ := ed25519.GenerateKey(nil)
	m := &mesh{t: t, netPub: pub, netPriv: priv}
	if gated {
		m.allow = map[string]bool{}
	}
	var infos []*pb.NodeInfo
	for i := 0; i < n; i++ {
		_, k, _ := ed25519.GenerateKey(nil)
		st, err := store.Open(filepath.Join(t.TempDir(), fmt.Sprintf("n%d.db", i)))
		if err != nil {
			t.Fatal(err)
		}
		svc := service.New(st, k, pub)
		svc.Log = quiet
		nd := &tnode{key: k, id: svc.NodeID, st: st, svc: svc}
		nd.gate = &gate{allow: m.allow, inner: NetDialer{AllowPlain: true}, self: nd.id}
		nd.repl = New(svc, nd.gate, quiet)
		mux := http.NewServeMux()
		mux.Handle("/x/peer", nd.repl)
		nd.srv = httptest.NewServer(mux)
		u, _ := url.Parse(nd.srv.URL)
		port, _ := strconv.Atoi(u.Port())
		infos = append(infos, &pb.NodeInfo{NodeId: nd.id, NodePub: k.Public().(ed25519.PublicKey), Label: fmt.Sprintf("n%d", i),
			Endpoints: []*pb.Endpoint{{Kind: pb.Endpoint_WS_PLAIN, Host: "127.0.0.1", Port: uint32(port), Path: "/x"}}})
		m.nodes = append(m.nodes, nd)
	}
	man := m.sign(pb.RecordType_MANIFEST, keys.ID16(pub), &pb.Manifest{Version: 1, NetworkPub: pub, Nodes: infos}, priv)
	for _, nd := range m.nodes {
		if _, err := nd.svc.ImportRecord(context.Background(), man); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if m.cancel != nil {
			m.cancel()
		}
		for _, nd := range m.nodes {
			nd.srv.Close()
			nd.st.Close()
		}
	})
	return m
}

func (m *mesh) start() {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	for _, nd := range m.nodes {
		go nd.repl.Run(ctx)
	}
}

func (m *mesh) link(a, b int, on bool) {
	g := m.nodes[a].gate
	g.mu.Lock()
	m.allow[pairKey(m.nodes[a].id, m.nodes[b].id)] = on
	g.mu.Unlock()
}

func (m *mesh) sign(typ pb.RecordType, author []byte, payload proto.Message, k ed25519.PrivateKey) *pb.Record {
	p, _ := proto.Marshal(payload)
	id := make([]byte, 16)
	rand.Read(id)
	r, err := records.Sign(&pb.RecordBody{Id: id, Type: typ, Author: author, CreatedMs: time.Now().UnixMilli(), Payload: p}, k)
	if err != nil {
		m.t.Fatal(err)
	}
	return r
}

type user struct {
	id   []byte
	priv ed25519.PrivateKey
}

func (m *mesh) entry(name string) (*user, *pb.Record) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	id := keys.ID16(pub)
	e := &pb.DirectoryEntry{UserId: id, Username: name, DisplayName: name, AccountPub: pub,
		IdentityPub: make([]byte, 33), IdentitySig: make([]byte, 64), Version: 1, CanInvite: true}
	return &user{id, priv}, m.sign(pb.RecordType_DIRECTORY_ENTRY, id, e, priv)
}

// register creates an account on node i through the service (bootstrap invite → Register).
func (m *mesh) register(i int, name string) *user {
	ctx := context.Background()
	nd := m.nodes[i]
	secret := make([]byte, 32)
	rand.Read(secret)
	sum := sha256.Sum256(secret)
	inv := m.sign(pb.RecordType_INVITE, keys.ID16(m.netPub), &pb.Invite{InviteId: sum[:], ExpiresMs: time.Now().Add(time.Hour).UnixMilli()}, m.netPriv)
	if _, err := nd.svc.ImportRecord(ctx, inv); err != nil {
		m.t.Fatal(err)
	}
	u, dir := m.entry(name)
	pk := &pb.PreKeys{DeviceId: 1, RegistrationId: 3,
		SignedPrekey: &pb.SignedPreKey{Id: 1, PublicKey: make([]byte, 33), Signature: make([]byte, 64)},
		KyberPrekey:  &pb.SignedPreKey{Id: 1, PublicKey: make([]byte, 1569), Signature: make([]byte, 64)}}
	req := &pb.RegisterRequest{InviteSecret: secret, DirectoryEntry: dir,
		Prekeys:    m.sign(pb.RecordType_PREKEYS, u.id, pk, u.priv),
		InviteUsed: m.sign(pb.RecordType_INVITE_USED, u.id, &pb.InviteUsed{InviteId: sum[:], UserId: u.id}, u.priv)}
	if _, err := nd.svc.Register(ctx, req); err != nil {
		m.t.Fatal(err)
	}
	return u
}

func (m *mesh) envelope(from, to *user) *pb.Record {
	return m.sign(pb.RecordType_ENVELOPE, from.id, &pb.Envelope{SenderUser: from.id, SenderDevice: 1, Kind: pb.Envelope_SIGNAL,
		Recipients: []*pb.Recipient{{User: to.id, Device: 1, Content: []byte("hi")}}}, from.priv)
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func known(nd *tnode, u *user) bool {
	x, _ := nd.st.UserByID(context.Background(), u.id)
	return x != nil
}
func boxLen(nd *tnode, u *user) int {
	b, _ := nd.st.Mailbox(context.Background(), u.id, 1, 100)
	return len(b)
}

func TestTwoNodesConverge(t *testing.T) {
	m := newMesh(t, 2, false)
	m.start()
	a, b := m.nodes[0], m.nodes[1]
	anna := m.register(0, "anna")
	eventually(t, "anna on B", func() bool { return known(b, anna) })
	boris := m.register(1, "boris")
	eventually(t, "boris on A", func() bool { return known(a, boris) })
	if _, err := b.svc.Submit(context.Background(), boris.id, m.envelope(boris, anna), pb.RecordType_ENVELOPE); err != nil {
		t.Fatal(err)
	}
	eventually(t, "envelope in A's mailbox", func() bool { return boxLen(a, anna) == 1 })
	eventually(t, "both caught up", func() bool {
		for _, nd := range m.nodes {
			s := nd.repl.Status()
			if len(s) != 1 || !s[0].Connected || !s[0].CaughtUp {
				return false
			}
		}
		return true
	})
}

func TestRejectUnknownNode(t *testing.T) {
	m := newMesh(t, 1, false)
	a := m.nodes[0]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(a.srv.URL, "http")+"/x/peer", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	f, err := readFrame(ctx, c)
	if err != nil || f.GetHello() == nil {
		t.Fatalf("hello: %v %v", f, err)
	}
	_, stranger, _ := ed25519.GenerateKey(nil)
	sid := keys.ID16(stranger.Public().(ed25519.PublicKey))
	ts := time.Now().UnixMilli()
	writeFrame(ctx, c, &pb.PeerFrame{Kind: &pb.PeerFrame_Auth{Auth: &pb.PeerAuth{NodeId: sid, TsMs: ts, Nonce: nonce(),
		Signature: ed25519.Sign(stranger, keys.PeerAuthMessage(a.id, f.GetHello().Nonce, ts))}}})
	f, err = readFrame(ctx, c)
	if err == nil && f.GetError() == nil {
		t.Fatalf("stranger accepted: %v", f)
	}
	if len(a.repl.Status()) != 0 || a.repl.reg.has(sid) {
		t.Fatal("registry must stay empty")
	}
}

func TestBadSignatureRejected(t *testing.T) {
	m := newMesh(t, 2, false)
	a, b := m.nodes[0], m.nodes[1]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(a.srv.URL, "http")+"/x/peer", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	f, _ := readFrame(ctx, c)
	ts := time.Now().UnixMilli()
	// B's id, but signed over the wrong nonce
	writeFrame(ctx, c, &pb.PeerFrame{Kind: &pb.PeerFrame_Auth{Auth: &pb.PeerAuth{NodeId: b.id, TsMs: ts, Nonce: nonce(),
		Signature: ed25519.Sign(b.key, keys.PeerAuthMessage(a.id, nonce(), ts))}}})
	f, err = readFrame(ctx, c)
	if err == nil && f.GetError() == nil {
		t.Fatalf("bad signature accepted: %v", f)
	}
	if a.repl.reg.has(b.id) {
		t.Fatal("session registered")
	}
}

func TestTieBreak(t *testing.T) {
	m := newMesh(t, 2, false)
	m.start() // both dial each other
	lower := m.nodes[0].id
	if bytes.Compare(m.nodes[1].id, lower) < 0 {
		lower = m.nodes[1].id
	}
	eventually(t, "one session each, dialed by the lower id", func() bool {
		for _, nd := range m.nodes {
			nd.repl.reg.mu.Lock()
			n := len(nd.repl.reg.byPeer)
			var dialer []byte
			for _, s := range nd.repl.reg.byPeer {
				dialer = s.dialer
			}
			nd.repl.reg.mu.Unlock()
			if n != 1 || !bytes.Equal(dialer, lower) {
				return false
			}
		}
		return true
	})
	time.Sleep(500 * time.Millisecond) // several dial ticks later it is still one stable session
	for _, nd := range m.nodes {
		if s := nd.repl.Status(); len(s) != 1 || !s[0].Connected {
			t.Fatalf("status %+v", s)
		}
	}
}

func TestRetryLaterDoesNotLoseRecords(t *testing.T) {
	m := newMesh(t, 3, true)
	a, b, c := m.nodes[0], m.nodes[1], m.nodes[2]
	ctx := context.Background()
	x, xEntry := m.entry("xenia")
	if _, err := c.svc.ImportRecord(ctx, xEntry); err != nil { // X's entry exists only on C
		t.Fatal(err)
	}
	y, yEntry := m.entry("yuri")
	for _, nd := range m.nodes {
		nd.svc.ImportRecord(ctx, yEntry)
	}
	env := m.envelope(x, y)
	var body pb.RecordBody
	proto.Unmarshal(env.Body, &body)
	if _, _, err := a.st.ApplyFrom(ctx, env, &body, a.id); err != nil { // injected on A without validation
		t.Fatal(err)
	}
	m.link(0, 1, true) // A↔B only
	m.start()
	eventually(t, "B connected to A", func() bool { return b.repl.reg.has(a.id) || a.repl.reg.has(b.id) })
	time.Sleep(300 * time.Millisecond)
	if boxLen(b, y) != 0 || known(b, x) {
		t.Fatal("B must not have the envelope or X yet")
	}
	m.link(1, 2, true) // now C↔B: X's entry reaches B, then A's envelope can be applied
	eventually(t, "X known on B", func() bool { return known(b, x) })
	eventually(t, "envelope on B", func() bool { return boxLen(b, y) == 1 })
	if known(a, x) == false {
		eventually(t, "X reaches A via B", func() bool { return known(a, x) })
	}
}
