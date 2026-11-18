package replication

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"ottermsg/server/internal/limits"
)

// D116 in front of a node marked no_backups (as main.go wraps the public listener, loopback not exempt here because
// every test client is on 127.0.0.1): the peer session and up to 4 restore tunnels per source work under the per-IP
// limits, the tunnel's own 4/source limit still answers the 5th, and a hostile flood of new connections from the same
// address is refused without touching the established session and tunnels.
func TestPeersAndTunnelsUnderConnLimits(t *testing.T) {
	count := &limits.Counters{}
	m := newMeshWrapped(t, 2, false, func(nd *tnode, mux *http.ServeMux) http.Handler {
		mux.Handle("/x/tunnel", http.HandlerFunc(nd.repl.ServeTunnel))
		c := &limits.Conns{PerIP: 32, Rate: limits.NewKeyed(30.0/60, 20), Count: count}
		return c.Wrap(mux)
	})
	m.markNoBackups(0)
	ln := m.nodes[1].repl.TunnelListener()
	go func() { // the far node's TLS server stands in: echo
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	m.start()
	peer := m.session(0, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tunnelURL := "ws" + strings.TrimPrefix(m.nodes[0].srv.URL, "http") + "/x/tunnel?to=" + hex.EncodeToString(m.nodes[1].id)
	echo := func(c net.Conn, i int) {
		t.Helper()
		msg := []byte(fmt.Sprintf("restore %d", i))
		if _, err := c.Write(msg); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(msg))
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(c, got); err != nil || string(got) != string(msg) {
			t.Fatalf("tunnel %d: %q %v", i, got, err)
		}
	}
	var phones []net.Conn
	for i := 0; i < maxTunnelsPerIP; i++ {
		ws, _, err := websocket.Dial(ctx, tunnelURL, nil)
		if err != nil {
			t.Fatalf("tunnel %d: %v", i, err)
		}
		c := websocket.NetConn(ctx, ws, websocket.MessageBinary)
		defer c.Close()
		echo(c, i)
		phones = append(phones, c)
	}
	if _, resp, err := websocket.Dial(ctx, tunnelURL, nil); err == nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("5th tunnel from one source: %v", err)
	}
	if n := count.ConnIP.Load() + count.ConnRate.Load(); n != 0 {
		t.Fatalf("per-IP limits refused normal use: %v", count.Map())
	}

	// hostile: new connections as fast as it can from the same address
	refused := 0
	for i := 0; i < 40; i++ {
		resp, err := http.Get(m.nodes[0].srv.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			refused++
		}
	}
	if refused < 20 || count.ConnRate.Load() == 0 {
		t.Fatalf("flood: %d refused, %v", refused, count.Map())
	}
	for i, c := range phones {
		echo(c, 100+i)
	}
	if s := m.nodes[0].repl.reg.get(m.nodes[1].id); s != peer {
		t.Fatal("the peer session was dropped by the flood")
	}
}
