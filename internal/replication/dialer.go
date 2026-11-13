package replication

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"
	"ottermsg/server/internal/pinning"
	pb "ottermsg/server/internal/proto/otterv1"
)

type Dialer interface {
	Dial(ctx context.Context, n *pb.NodeInfo) (*websocket.Conn, error)
}

// RealityDialer opens a TCP stream to a REALITY endpoint (internal/reality.Client); nil = REALITY unsupported.
type RealityDialer interface {
	DialContext(ctx context.Context, ep *pb.Endpoint) (net.Conn, error)
}

// NetDialer dials one endpoint: WSS (pinned), WS_PLAIN (development), REALITY (through Reality).
type NetDialer struct {
	AllowPlain bool
	Reality    RealityDialer
}

const dialTimeout = 15 * time.Second

func (d NetDialer) DialEndpoint(ctx context.Context, n *pb.NodeInfo, ep *pb.Endpoint) (*websocket.Conn, error) {
	hostport := net.JoinHostPort(ep.Host, strconv.Itoa(int(ep.Port)))
	var url string
	var hc *http.Client
	switch {
	case ep.Kind == pb.Endpoint_WSS:
		url = "wss://" + hostport + ep.Path + "/peer"
		hc = &http.Client{Transport: &http.Transport{TLSClientConfig: pinning.ClientConfig(ep.Host, ep.TlsSpkiPins)}}
	case ep.Kind == pb.Endpoint_WS_PLAIN && d.AllowPlain:
		url = "ws://" + hostport + ep.Path + "/peer"
	case ep.Kind == pb.Endpoint_REALITY && d.Reality != nil:
		// plain HTTP inside the REALITY tunnel; the far side redirects every stream to its internal listener
		url = "ws://" + hostport + ep.Path + "/peer"
		hc = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.Reality.DialContext(ctx, ep)
		}}}
	default:
		return nil, ErrUnsupported
	}
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	c, _, err := websocket.Dial(dctx, url, &websocket.DialOptions{HTTPClient: hc})
	if err != nil {
		return nil, err
	}
	c.SetReadLimit(maxFrame)
	return c, nil
}
