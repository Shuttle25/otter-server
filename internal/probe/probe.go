// Package probe checks that a node answers with its hello over (pinned) WSS. Used by health checks.
package probe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"ottermsg/server/internal/client"
	pb "ottermsg/server/internal/proto/otterv1"
)

type Options struct {
	URL        string
	Pins       [][]byte
	Addr       string // connect here instead of the URL host (SNI and certificate checks keep the URL host)
	Insecure   bool
	ExpectNode []byte
	Timeout    time.Duration
}

type Result struct {
	NodeID   []byte
	Protocol uint32
	RTT      time.Duration
}

func Run(ctx context.Context, o Options) (*Result, error) {
	u, err := url.Parse(o.URL)
	if err != nil || (u.Scheme != "wss" && u.Scheme != "ws") {
		return nil, errors.New("url must look like wss://host:port/path")
	}
	port, _ := strconv.Atoi(u.Port())
	if port <= 0 || port > 65535 {
		return nil, errors.New("url needs an explicit port")
	}
	kind := pb.Endpoint_WSS
	if u.Scheme == "ws" {
		kind = pb.Endpoint_WS_PLAIN
	}
	if kind == pb.Endpoint_WSS && len(o.Pins) == 0 && !o.Insecure {
		return nil, errors.New("--pin or --insecure is required for wss")
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	ep := &pb.Endpoint{Kind: kind, Host: u.Hostname(), Port: uint32(port), Path: path, TlsSpkiPins: o.Pins}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	t0 := time.Now()
	c, err := client.DialWith(ctx, ep, client.DialOptions{AllowPlain: kind == pb.Endpoint_WS_PLAIN, Addr: o.Addr, Insecure: o.Insecure})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	h := c.Hello()
	if len(o.ExpectNode) > 0 && !bytes.Equal(h.NodeId, o.ExpectNode) {
		return nil, fmt.Errorf("node_id %x, expected %x", h.NodeId, o.ExpectNode)
	}
	return &Result{NodeID: h.NodeId, Protocol: h.ProtocolVersion, RTT: time.Since(t0)}, nil
}
