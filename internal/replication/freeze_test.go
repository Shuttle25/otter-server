package replication

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	"ottermsg/server/internal/netlog"
	pb "ottermsg/server/internal/proto/otterv1"
)

// dpiDialer plays the Russian freeze seen on ru-1 (2026-11-15): connections to a frozen endpoint open, then go
// silent after `after` (or right after the WebSocket upgrade when after == 0); other endpoints work normally.
type dpiDialer struct {
	frozen map[string]bool // EndpointName → frozen
	after  time.Duration
}

func (d *dpiDialer) DialEndpoint(ctx context.Context, n *pb.NodeInfo, ep *pb.Endpoint) (*websocket.Conn, error) {
	url := "ws://" + net.JoinHostPort(ep.Host, strconv.Itoa(int(ep.Port))) + ep.Path + "/peer"
	frozen := d.frozen[EndpointName(ep)]
	var fc *freezeConn
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		fc = newFreezeConn(c)
		if frozen && d.after > 0 {
			time.AfterFunc(d.after, fc.freeze)
		}
		return fc, nil
	}}}
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(dctx, url, &websocket.DialOptions{HTTPClient: hc})
	if err != nil {
		return nil, err
	}
	if frozen && d.after == 0 {
		fc.freeze() // the upgrade passed; the node handshake will not
	}
	c.SetReadLimit(maxFrame)
	return c, nil
}

// frozenMesh: A (dial-out-only, like ru-1) and B (like eeee) with two endpoints: the direct one and a second
// listener with priority 10 (the CDN route in production).
func frozenMesh(t *testing.T, after time.Duration) (m *mesh, direct, second *pb.Endpoint, aLog *memLog, rank *Ranker) {
	m = newMesh(t, 2, false)
	a, b := m.nodes[0], m.nodes[1]
	mux := http.NewServeMux()
	mux.Handle("/x/peer", b.repl)
	srv2 := httptest.NewServer(mux)
	t.Cleanup(srv2.Close)
	u, _ := url.Parse(srv2.URL)
	port2, _ := strconv.Atoi(u.Port())
	man := proto.Clone(a.svc.CurrentManifest()).(*pb.Manifest)
	man.Version = 2
	man.Nodes[0].DialOutOnly = true // A dials B, never the other way round
	direct = man.Nodes[1].Endpoints[0]
	second = &pb.Endpoint{Kind: pb.Endpoint_WS_PLAIN, Host: "127.0.0.1", Port: uint32(port2), Path: "/x", ViaCdn: true, Priority: 10}
	man.Nodes[1].Endpoints = append(man.Nodes[1].Endpoints, second)
	rec := m.sign(pb.RecordType_MANIFEST, keys.ID16(m.netPub), man, m.netPriv)
	for _, nd := range m.nodes {
		if _, err := nd.svc.ImportRecord(context.Background(), rec); err != nil {
			t.Fatal(err)
		}
	}
	aLog = &memLog{}
	rank = NewRanker(time.Now)
	dd := &dpiDialer{frozen: map[string]bool{EndpointName(direct): true}, after: after}
	a.repl = New(a.svc, &MultiDialer{EP: dd, Rank: rank, Log: aLog}, quiet, WithNetlog(aLog, rank))
	return m, direct, second, aLog, rank
}

func TestFrozenSessionFallsBackToSecondEndpoint(t *testing.T) {
	m, direct, second, aLog, rank := frozenMesh(t, 300*time.Millisecond)
	a, b := m.nodes[0], m.nodes[1]
	m.start()
	eventually(t, "a frozen session counted as throttling", func() bool {
		return aLog.find(func(e netlog.Entry) bool {
			return e.Endpoint == EndpointName(direct) && e.Class == netlog.ResetAfterKB && strings.HasPrefix(e.Detail, "frozen:")
		})
	})
	rank.mu.Lock()
	throttles := len(rank.st[EndpointName(direct)].throttles)
	rank.mu.Unlock()
	if throttles < 1 {
		t.Fatalf("ranker throttles for the direct endpoint: %d", throttles)
	}
	eventually(t, "a dial over the second endpoint", func() bool {
		return aLog.find(func(e netlog.Entry) bool { return e.Endpoint == EndpointName(second) && e.Class == netlog.OK })
	})
	boris := m.register(1, "boris")
	eventually(t, "boris reaches A over the second endpoint", func() bool { return known(a, boris) })
	s := sessionOf(a, b.id)
	time.Sleep(10 * peerPing)
	if s == nil || sessionOf(a, b.id) != s {
		t.Fatal("the session over the second endpoint did not hold")
	}
}

func TestFrozenHandshakeTriesNextEndpoint(t *testing.T) {
	m, direct, second, aLog, rank := frozenMesh(t, 0)
	m.start()
	eventually(t, "a dial over the second endpoint", func() bool {
		return aLog.find(func(e netlog.Entry) bool { return e.Endpoint == EndpointName(second) && e.Class == netlog.OK })
	})
	rank.mu.Lock()
	st := rank.st[EndpointName(direct)]
	failed := st != nil && !st.lastFail.IsZero()
	rank.mu.Unlock()
	if !failed {
		t.Fatal("a handshake that froze did not mark the direct endpoint failed")
	}
}
