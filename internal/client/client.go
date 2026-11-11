// Package client is a small client for the node protocol (admin tools, tests). Not used by the apps.
package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/pinning"
	pb "ottermsg/server/internal/proto/otterv1"
)

// StatusError is a non-OK response.
type StatusError struct {
	Status  pb.Status
	Message string
}

func (e *StatusError) Error() string { return fmt.Sprintf("%v: %s", e.Status, e.Message) }

type Conn struct {
	c     *websocket.Conn
	hello *pb.Hello
	next  atomic.Uint64

	mu      sync.Mutex
	pending map[uint64]chan *pb.Response
	done    chan struct{}
	err     error
}

// URL returns the client URL of an endpoint, or an error if it cannot be used.
func URL(ep *pb.Endpoint, allowPlain bool) (string, error) {
	hostport := net.JoinHostPort(ep.Host, strconv.Itoa(int(ep.Port)))
	switch {
	case ep.Kind == pb.Endpoint_WSS:
		return "wss://" + hostport + ep.Path, nil
	case ep.Kind == pb.Endpoint_WS_PLAIN && allowPlain:
		return "ws://" + hostport + ep.Path, nil
	case ep.Kind == pb.Endpoint_WS_PLAIN:
		return "", errors.New("plain endpoint (use --allow-plain for development nodes)")
	default:
		return "", fmt.Errorf("unsupported endpoint kind %v", ep.Kind)
	}
}

// Dial connects to ep (pinned TLS for WSS) and waits for the node's hello.
func Dial(ctx context.Context, ep *pb.Endpoint, allowPlain bool) (*Conn, error) {
	url, err := URL(ep, allowPlain)
	if err != nil {
		return nil, err
	}
	opts := &websocket.DialOptions{}
	if ep.Kind == pb.Endpoint_WSS {
		opts.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: pinning.ClientConfig(ep.Host, ep.TlsSpkiPins)}}
	}
	c, _, err := websocket.Dial(ctx, url, opts)
	if err != nil {
		return nil, err
	}
	c.SetReadLimit(4 << 20)
	conn := &Conn{c: c, pending: map[uint64]chan *pb.Response{}, done: make(chan struct{})}
	hello := make(chan *pb.Hello, 1)
	go conn.readLoop(hello)
	select {
	case h := <-hello:
		conn.hello = h
		return conn, nil
	case <-conn.done:
		return nil, conn.err
	case <-ctx.Done():
		c.CloseNow()
		return nil, ctx.Err()
	}
}

func (c *Conn) Hello() *pb.Hello { return c.hello }

func (c *Conn) Close() error { return c.c.Close(websocket.StatusNormalClosure, "") }

func (c *Conn) readLoop(hello chan<- *pb.Hello) {
	var err error
	defer func() {
		c.mu.Lock()
		c.err = err
		close(c.done)
		c.mu.Unlock()
	}()
	for {
		var data []byte
		if _, data, err = c.c.Read(context.Background()); err != nil {
			return
		}
		var f pb.Frame
		if err = proto.Unmarshal(data, &f); err != nil {
			return
		}
		if e := f.GetEvent(); e != nil && e.Type == "hello" {
			h := &pb.Hello{}
			proto.Unmarshal(e.Body, h)
			select {
			case hello <- h:
			default:
			}
		}
		if r := f.GetResponse(); r != nil {
			c.mu.Lock()
			ch := c.pending[r.Id]
			delete(c.pending, r.Id)
			c.mu.Unlock()
			if ch != nil {
				ch <- r
			}
		}
	}
}

// Call sends a request and decodes the response body into resp (may be nil). Non-OK → *StatusError.
func (c *Conn) Call(ctx context.Context, method string, req, resp proto.Message) error {
	body, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	id := c.next.Add(1)
	ch := make(chan *pb.Response, 1)
	c.mu.Lock()
	c.pending[id] = ch
	c.mu.Unlock()
	f, _ := proto.Marshal(&pb.Frame{Kind: &pb.Frame_Request{Request: &pb.Request{Id: id, Method: method, Body: body}}})
	if err := c.c.Write(ctx, websocket.MessageBinary, f); err != nil {
		return err
	}
	select {
	case r := <-ch:
		if r.Status != pb.Status_STATUS_OK {
			return &StatusError{Status: r.Status, Message: r.Error}
		}
		if resp != nil {
			return proto.Unmarshal(r.Body, resp)
		}
		return nil
	case <-c.done:
		return fmt.Errorf("connection closed: %v", c.err)
	case <-ctx.Done():
		return ctx.Err()
	}
}
