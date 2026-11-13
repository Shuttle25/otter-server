package reality

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
	xreality "github.com/xtls/xray-core/transport/internet/reality"

	// the features our configs use register themselves here; nothing else of Xray is linked in
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

// idleTimeout replaces Xray's 300 s default: peer sessions may be silent for long and must not be cut
// (a dead TCP link still ends the stream).
const idleTimeout = 24 * 60 * 60

// baseConfig is what every instance needs: dispatcher, inbound/outbound managers, a long idle timeout.
func baseConfig() *core.Config {
	return &core.Config{App: []*serial.TypedMessage{
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		serial.ToTypedMessage(&policy.Config{Level: map[uint32]*policy.Policy{0: {Timeout: &policy.Policy_Timeout{
			Handshake:      &policy.Second{Value: 60},
			ConnectionIdle: &policy.Second{Value: idleTimeout},
			UplinkOnly:     &policy.Second{Value: 1},
			DownlinkOnly:   &policy.Second{Value: 1},
		}}}}),
	}}
}

// realityStream is a RAW (TCP) stream secured by REALITY.
func realityStream(rc *xreality.Config) *internet.StreamConfig {
	tm := serial.ToTypedMessage(rc)
	return &internet.StreamConfig{ProtocolName: "tcp", SecurityType: tm.Type, SecuritySettings: []*serial.TypedMessage{tm}}
}

// shortID decodes a REALITY short id: up to 16 hex digits, stored in 8 bytes (as Xray's own config loader does).
func shortID(s string) ([]byte, error) {
	if len(s) > 16 {
		return nil, fmt.Errorf("reality short id %q: longer than 16 hex digits", s)
	}
	b := make([]byte, 8)
	if _, err := hex.Decode(b, []byte(s)); err != nil {
		return nil, fmt.Errorf("reality short id %q: %w", s, err)
	}
	return b, nil
}

func checkUUID(s string) (string, error) {
	u, err := uuid.ParseString(s)
	if err != nil {
		return "", fmt.Errorf("vless uuid %q: %w", s, err)
	}
	return u.String(), nil
}

func hostPort(s string) (string, uint32, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("port %q: %w", port, err)
	}
	return host, uint32(p), nil
}

func ipOrDomain(host string) *xnet.IPOrDomain { return xnet.NewIPOrDomain(xnet.ParseAddress(host)) }
