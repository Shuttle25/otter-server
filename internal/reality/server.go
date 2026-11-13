package reality

import (
	"errors"
	"fmt"

	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	xreality "github.com/xtls/xray-core/transport/internet/reality"
)

type ServerConfig struct {
	Listen      string   // ":443"
	PrivateKey  string   // base64 RawURL
	Dest        string   // camouflage "host:443": unauthenticated connections are forwarded there
	ServerNames []string // SNI values accepted, e.g. ["www.microsoft.com"]
	ShortIDs    []string
	VlessUUID   string
	Forward     string // internal plain-HTTP listener, "127.0.0.1:PORT"
}

// Server is a running REALITY inbound.
type Server struct{ inst *core.Instance }

func serverConfig(c ServerConfig) (*core.Config, error) {
	host, port, err := hostPort(c.Listen)
	if err != nil {
		return nil, fmt.Errorf("reality listen %q: %w", c.Listen, err)
	}
	priv, err := b64.DecodeString(c.PrivateKey)
	if err != nil || len(priv) != 32 {
		return nil, errors.New("reality: private key must be 32 bytes, base64 RawURL")
	}
	if _, _, err := hostPort(c.Dest); err != nil {
		return nil, fmt.Errorf("reality dest %q: %w", c.Dest, err)
	}
	if len(c.ServerNames) == 0 || len(c.ShortIDs) == 0 {
		return nil, errors.New("reality: server_names and short_ids must not be empty")
	}
	sids := make([][]byte, len(c.ShortIDs))
	for i, s := range c.ShortIDs {
		if sids[i], err = shortID(s); err != nil {
			return nil, err
		}
	}
	id, err := checkUUID(c.VlessUUID)
	if err != nil {
		return nil, err
	}
	fhost, fport, err := hostPort(c.Forward)
	if err != nil || fhost == "" {
		return nil, fmt.Errorf("reality forward %q: must be host:port", c.Forward)
	}

	recv := &proxyman.ReceiverConfig{
		PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(port))}},
		StreamSettings: realityStream(&xreality.Config{
			Dest: c.Dest, Type: "tcp", ServerNames: c.ServerNames, PrivateKey: priv, ShortIds: sids,
			LimitFallbackUpload: &xreality.LimitFallback{}, LimitFallbackDownload: &xreality.LimitFallback{},
		}),
	}
	if host != "" {
		recv.Listen = ipOrDomain(host)
	}
	cfg := baseConfig()
	cfg.Inbound = []*core.InboundHandlerConfig{{
		ReceiverSettings: serial.ToTypedMessage(recv),
		ProxySettings: serial.ToTypedMessage(&vlessin.Config{
			Clients:    []*protocol.User{{Account: serial.ToTypedMessage(&vless.Account{Id: id})}},
			Decryption: "none",
		}),
	}}
	// the only outbound: every authenticated stream goes to our own listener, never anywhere else
	cfg.Outbound = []*core.OutboundHandlerConfig{{
		SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{}),
		ProxySettings: serial.ToTypedMessage(&freedom.Config{DestinationOverride: &freedom.DestinationOverride{
			Server: &protocol.ServerEndpoint{Address: ipOrDomain(fhost), Port: fport}}}),
	}}
	return cfg, nil
}

// StartServer starts the REALITY inbound described by c.
func StartServer(c ServerConfig) (*Server, error) {
	cfg, err := serverConfig(c)
	if err != nil {
		return nil, err
	}
	inst, err := core.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("reality server: %w", err)
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		return nil, fmt.Errorf("reality server: %w", err)
	}
	return &Server{inst}, nil
}

func (s *Server) Close() error { return s.inst.Close() }
