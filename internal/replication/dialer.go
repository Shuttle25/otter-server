package replication

import (
	"context"
	"errors"
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

type NetDialer struct{ AllowPlain bool }

func (d NetDialer) Dial(ctx context.Context, n *pb.NodeInfo) (*websocket.Conn, error) {
	var lastErr error = errors.New("no usable endpoint")
	for _, ep := range n.Endpoints {
		var url string
		var hc *http.Client
		hostport := net.JoinHostPort(ep.Host, strconv.Itoa(int(ep.Port)))
		switch {
		case ep.Kind == pb.Endpoint_WSS:
			url = "wss://" + hostport + ep.Path + "/peer"
			hc = &http.Client{Transport: &http.Transport{TLSClientConfig: pinning.ClientConfig(ep.Host, ep.TlsSpkiPins)}}
		case ep.Kind == pb.Endpoint_WS_PLAIN && d.AllowPlain:
			url = "ws://" + hostport + ep.Path + "/peer"
		default:
			continue
		}
		dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		c, _, err := websocket.Dial(dctx, url, &websocket.DialOptions{HTTPClient: hc})
		cancel()
		if err == nil {
			c.SetReadLimit(maxFrame)
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
