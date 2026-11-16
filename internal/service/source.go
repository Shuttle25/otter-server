package service

import (
	"net"
	"strings"
)

// SourceOf maps a connection's remote address to its restore rate-limit source (D105): the IPv4 address, the IPv6
// /64, "local" for loopback (the in-process REALITY listener, tests), "unknown" for anything unparsable. No
// forwarding header is ever trusted: phones connect straight to the node's WSS listener (no CDN, D75). Restores
// relayed through a restore tunnel arrive as "tunnel:<hex node id>" and share that node's source (D114; until a
// PROXY header follow-up, owner answer Q12 of M9.2).
func SourceOf(remoteAddr string) string {
	if strings.HasPrefix(remoteAddr, "tunnel:") {
		return remoteAddr
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	switch {
	case ip == nil:
		return "unknown"
	case ip.IsLoopback():
		return "local"
	case ip.To4() != nil:
		return ip.To4().String()
	}
	m := net.CIDRMask(64, 128)
	return (&net.IPNet{IP: ip.Mask(m), Mask: m}).String()
}
