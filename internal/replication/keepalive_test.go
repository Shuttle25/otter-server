package replication

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"ottermsg/server/internal/netlog"
	pb "ottermsg/server/internal/proto/otterv1"
)

type recLog struct {
	mu sync.Mutex
	es []netlog.Entry
}

func (r *recLog) Add(_ context.Context, e netlog.Entry) {
	r.mu.Lock()
	r.es = append(r.es, e)
	r.mu.Unlock()
}
func (r *recLog) find(endpoint string) *netlog.Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.es {
		if r.es[i].Endpoint == endpoint {
			e := r.es[i]
			return &e
		}
	}
	return nil
}

// freezeConn plays a link that DPI froze (or a peer that stops answering on purpose): after freeze nothing is read
// or written, no FIN is sent, until Close.
type freezeConn struct {
	net.Conn
	frozen chan struct{}
	closed chan struct{}
	fOnce  sync.Once
	cOnce  sync.Once
}

func newFreezeConn(c net.Conn) *freezeConn {
	return &freezeConn{Conn: c, frozen: make(chan struct{}), closed: make(chan struct{})}
}

func (c *freezeConn) freeze() { c.fOnce.Do(func() { close(c.frozen) }) }
func (c *freezeConn) block() error {
	select {
	case <-c.frozen:
		<-c.closed
		return net.ErrClosed
	default:
		return nil
	}
}
func (c *freezeConn) Read(p []byte) (int, error) {
	if err := c.block(); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(p)
	if err == nil {
		if err := c.block(); err != nil {
			return 0, err
		}
	}
	return n, err
}
func (c *freezeConn) Write(p []byte) (int, error) {
	if err := c.block(); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}
func (c *freezeConn) Close() error { c.cOnce.Do(func() { close(c.closed) }); return c.Conn.Close() }

// freezeDialer dials WS_PLAIN endpoints like NetDialer and can freeze every connection it made so far.
type freezeDialer struct {
	mu    sync.Mutex
	conns []*freezeConn
}

func (d *freezeDialer) freezeAll() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.conns {
		c.freeze()
	}
}

func (d *freezeDialer) Dial(ctx context.Context, n *pb.NodeInfo) (*websocket.Conn, error) {
	ep := n.Endpoints[0]
	url := "ws://" + net.JoinHostPort(ep.Host, strconv.Itoa(int(ep.Port))) + ep.Path + "/peer"
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		fc := newFreezeConn(c)
		d.mu.Lock()
		d.conns = append(d.conns, fc)
		d.mu.Unlock()
		return fc, nil
	}}}
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(dctx, url, &websocket.DialOptions{HTTPClient: hc})
	if err != nil {
		return nil, err
	}
	c.SetReadLimit(maxFrame)
	return c, nil
}

func sessionOf(nd *tnode, peer []byte) *session {
	nd.repl.reg.mu.Lock()
	defer nd.repl.reg.mu.Unlock()
	return nd.repl.reg.byPeer[string(peer)]
}

func TestKeepaliveDropsFrozenPeerAndLogs(t *testing.T) {
	m := newMesh(t, 2, false)
	fd := &freezeDialer{}
	logs := &recLog{}
	for _, nd := range m.nodes {
		nd.gate.inner = fd // whichever side wins the duplicate-session race, its link can be frozen
		nd.repl.nlog = logs
	}
	m.start()
	eventually(t, "session up", func() bool { return sessionOf(m.nodes[0], m.nodes[1].id) != nil })
	old := sessionOf(m.nodes[0], m.nodes[1].id)
	fd.freezeAll()
	eventually(t, "ping failure in the netlog", func() bool { return logs.find("ping") != nil })
	e := logs.find("ping")
	if e.Class != netlog.Timeout || e.Result != "fail" || (e.Direction != "in" && e.Direction != "out") {
		t.Fatalf("netlog entry %+v", e)
	}
	eventually(t, "a new session after the drop", func() bool {
		s := sessionOf(m.nodes[0], m.nodes[1].id)
		return s != nil && s != old
	})
}

func TestKeepaliveKeepsHealthySession(t *testing.T) {
	m := newMesh(t, 2, false)
	m.start()
	eventually(t, "session up", func() bool { return sessionOf(m.nodes[0], m.nodes[1].id) != nil })
	s := sessionOf(m.nodes[0], m.nodes[1].id)
	time.Sleep(10 * peerPing)
	if sessionOf(m.nodes[0], m.nodes[1].id) != s {
		t.Fatal("a healthy session was replaced")
	}
}
