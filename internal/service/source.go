package service

import "net"

// SourceOf maps a connection's remote address to its restore rate-limit source (D105): the IPv4 address, the IPv6
// /64, "local" for loopback (the in-process REALITY listener, tests), "unknown" for anything unparsable. No
// forwarding header is ever trusted: phones connect straight to the node's WSS listener (no CDN, D75). Until M9.3,
// restores relayed by a dial-out pass-through share that node's source.
func SourceOf(remoteAddr string) string {
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
