package gateway

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	pb "ottermsg/server/internal/proto/otterv1"
)

// freezeConn simulates a phone whose socket died silently: after freeze() nothing is read or written any more
// (no pong, no FIN), until Close.
type freezeConn struct {
	net.Conn
	once   sync.Once
	frozen chan struct{}
	closed chan struct{}
	cOnce  sync.Once
}

func (c *freezeConn) freeze() { c.once.Do(func() { close(c.frozen) }) }

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
		if err := c.block(); err != nil { // frozen while the read was pending: drop what arrived
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

func (c *freezeConn) Close() error {
	c.cOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func fastPing(logs *syncBuf) func(*Gateway) {
	return func(g *Gateway) {
		g.PingInterval, g.PingTimeout = 50*time.Millisecond, 200*time.Millisecond
		if logs != nil {
			g.log = slog.New(slog.NewTextHandler(logs, nil))
		}
	}
}

func TestKeepaliveDropsDeadSession(t *testing.T) {
	var logs syncBuf
	n := startNode(t, fastPing(&logs))
	gw := n.svc.Notify.(*Gateway)
	anna, c0 := newTestUser(t, n, "anna")
	c0.c.CloseNow()

	var fc *freezeConn
	opts := &websocket.DialOptions{HTTPClient: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			fc = &freezeConn{Conn: c, frozen: make(chan struct{}), closed: make(chan struct{})}
			return fc, nil
		}}}}
	ca := dialWith(t, n, opts)
	login(t, ca, anna)
	if !gw.Online(anna.id, 1) {
		t.Fatal("logged in: Online must be true")
	}
	fc.freeze()
	deadline := time.Now().Add(5 * time.Second)
	for gw.Online(anna.id, 1) {
		if time.Now().After(deadline) {
			t.Fatal("dead session still online after the ping timeout")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(logs.String(), `msg="session ping failed"`) {
		t.Fatalf("ping failure not logged:\n%s", logs.String())
	}
}

func TestKeepaliveKeepsLiveSession(t *testing.T) {
	n := startNode(t, fastPing(nil))
	gw := n.svc.Notify.(*Gateway)
	anna, ca := newTestUser(t, n, "anna")
	login(t, ca, anna)
	time.Sleep(10 * 50 * time.Millisecond) // ~10 pings
	if !gw.Online(anna.id, 1) {
		t.Fatal("a live client was dropped by the keep-alive")
	}
	if st, msg := ca.call("directory.sync", &pb.Empty{}, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("call after pings: %v %s", st, msg)
	}
}
