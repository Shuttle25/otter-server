package reality

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/vless"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	xreality "github.com/xtls/xray-core/transport/internet/reality"
	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
)

// Client dials REALITY endpoints; one Xray instance per distinct endpoint config, kept for the process lifetime.
type Client struct {
	mu   sync.Mutex
	inst map[string]*core.Instance
}

func NewClient() *Client { return &Client{inst: map[string]*core.Instance{}} }

func clientConfig(ep *pb.Endpoint) (*core.Config, error) {
	if len(ep.RealityPub) != 32 || ep.VlessUuid == "" || len(ep.ServerNames) == 0 || ep.Host == "" || ep.Port == 0 {
		return nil, fmt.Errorf("reality endpoint %s:%d is incomplete", ep.Host, ep.Port)
	}
	id, err := checkUUID(ep.VlessUuid)
	if err != nil {
		return nil, err
	}
	sid := ""
	if len(ep.ShortIds) > 0 {
		sid = ep.ShortIds[0]
	}
	sidb, err := shortID(sid)
	if err != nil {
		return nil, err
	}
	fp := strings.ToLower(ep.Fingerprint)
	if fp == "" {
		fp = "chrome"
	}
	cfg := baseConfig()
	cfg.Outbound = []*core.OutboundHandlerConfig{{
		SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: realityStream(&xreality.Config{
			ServerName: ep.ServerNames[0], Fingerprint: fp, PublicKey: ep.RealityPub, ShortId: sidb,
			SpiderX: "/", SpiderY: make([]int64, 10),
		})}),
		ProxySettings: serial.ToTypedMessage(&vlessout.Config{Vnext: &protocol.ServerEndpoint{
			Address: ipOrDomain(ep.Host), Port: ep.Port,
			User: &protocol.User{Account: serial.ToTypedMessage(&vless.Account{Id: id, Encryption: "none"})},
		}}),
	}}
	return cfg, nil
}

func (c *Client) instance(ep *pb.Endpoint) (*core.Instance, error) {
	cfg, err := clientConfig(ep)
	if err != nil {
		return nil, err
	}
	kb, err := proto.MarshalOptions{Deterministic: true}.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	k := string(kb)
	c.mu.Lock()
	defer c.mu.Unlock()
	if in := c.inst[k]; in != nil {
		return in, nil
	}
	in, err := core.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("reality client: %w", err)
	}
	if err := in.Start(); err != nil {
		in.Close()
		return nil, fmt.Errorf("reality client: %w", err)
	}
	c.inst[k] = in
	return in, nil
}

// DialContext opens a stream through the endpoint. The far side redirects it to its internal listener, so the
// destination given here is only a placeholder. Errors of the tunnel itself surface on the first read/write.
// The stream lives until the returned conn is closed, not until ctx ends: Xray ties a dispatched link to its
// context, and callers cancel their dial timeouts once the WebSocket is up.
func (c *Client) DialContext(ctx context.Context, ep *pb.Endpoint) (net.Conn, error) {
	in, err := c.instance(ep)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return core.Dial(context.WithoutCancel(ctx), in, xnet.TCPDestination(xnet.ParseAddress("127.0.0.1"), xnet.Port(80)))
}

// Close stops all instances.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, in := range c.inst {
		_ = in.Close()
		delete(c.inst, k)
	}
}
