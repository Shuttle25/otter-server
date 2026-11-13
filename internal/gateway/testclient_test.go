package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"log/slog"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/blobs"
	"ottermsg/server/internal/keys"
	"ottermsg/server/internal/service"
	"ottermsg/server/internal/store"
)

type node struct {
	url     string
	svc     *service.Service
	netPriv ed25519.PrivateKey
}

func startNode(t *testing.T) *node {
	st, err := store.Open(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	_, nodeKey, _ := ed25519.GenerateKey(nil)
	svc := service.New(st, nodeKey, pub)
	bd, err := blobs.New(filepath.Join(t.TempDir(), "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	svc.Blobs = bd
	gw := New(svc, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(gw)
	t.Cleanup(func() { srv.Close(); st.Close() })
	return &node{url: "ws" + strings.TrimPrefix(srv.URL, "http"), svc: svc, netPriv: priv}
}

type client struct {
	t      *testing.T
	c      *websocket.Conn
	next   atomic.Uint64
	resps  chan *pb.Response
	events chan *pb.Event
	hello  *pb.Hello
}

func dial(t *testing.T, n *node) *client {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, n.url, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadLimit(maxFrame)
	cl := &client{t: t, c: c, resps: make(chan *pb.Response, 16), events: make(chan *pb.Event, 64)}
	go func() {
		for {
			_, data, err := c.Read(context.Background())
			if err != nil {
				close(cl.events)
				return
			}
			var f pb.Frame
			proto.Unmarshal(data, &f)
			if r := f.GetResponse(); r != nil {
				cl.resps <- r
			}
			if e := f.GetEvent(); e != nil {
				cl.events <- e
			}
		}
	}()
	e := cl.nextEvent("hello")
	cl.hello = &pb.Hello{}
	proto.Unmarshal(e.Body, cl.hello)
	t.Cleanup(func() { c.CloseNow() })
	return cl
}

func (c *client) call(method string, req, resp proto.Message) (pb.Status, string) {
	c.t.Helper()
	b, _ := proto.Marshal(req)
	id := c.next.Add(1)
	f, _ := proto.Marshal(&pb.Frame{Kind: &pb.Frame_Request{Request: &pb.Request{Id: id, Method: method, Body: b}}})
	if err := c.c.Write(context.Background(), websocket.MessageBinary, f); err != nil {
		c.t.Fatal(err)
	}
	select {
	case r := <-c.resps:
		if r.Id != id {
			c.t.Fatalf("response id %d, want %d", r.Id, id)
		}
		if resp != nil && r.Status == pb.Status_STATUS_OK {
			proto.Unmarshal(r.Body, resp)
		}
		return r.Status, r.Error
	case <-time.After(5 * time.Second):
		c.t.Fatalf("%s: timeout", method)
	}
	return 0, ""
}

func (c *client) nextEvent(typ string) *pb.Event {
	c.t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case e, ok := <-c.events:
			if !ok {
				c.t.Fatalf("closed while waiting for %s", typ)
			}
			if e.Type == typ {
				return e
			}
		case <-deadline:
			c.t.Fatalf("timeout waiting for event %s", typ)
		}
	}
}

func (c *client) noEvent(typ string, d time.Duration) {
	c.t.Helper()
	deadline := time.After(d)
	for {
		select {
		case e := <-c.events:
			if e.Type == typ {
				c.t.Fatalf("unexpected event %s", typ)
			}
		case <-deadline:
			return
		}
	}
}

// newTestUser registers a new account through a fresh invite; the returned client is not logged in.
func newTestUser(t *testing.T, n *node, name string) (*acct, *client) {
	t.Helper()
	secret := make([]byte, 32)
	rand.Read(secret)
	sum := sha256.Sum256(secret)
	inv := sign(t, pb.RecordType_INVITE, keys.ID16(n.svc.NetworkPub), &pb.Invite{InviteId: sum[:], ExpiresMs: time.Now().Add(time.Hour).UnixMilli()}, n.netPriv)
	if _, err := n.svc.ImportRecord(context.Background(), inv); err != nil {
		t.Fatal(err)
	}
	c := dial(t, n)
	a, req := registerReq(t, n, secret, name)
	if st, msg := c.call("register", req, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("register %s: %v %s", name, st, msg)
	}
	return a, c
}
