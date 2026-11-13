package turnsrv

import "net"

// denied are special-purpose ranges that net.IP's predicates do not cover. A TURN peer there is either not a
// phone or a way into a network behind the node (6to4 / NAT64 embed an IPv4 address).
var denied = func() []*net.IPNet {
	var n []*net.IPNet
	for _, c := range []string{
		"0.0.0.0/8",      // "this network"
		"100.64.0.0/10",  // CGNAT
		"192.0.0.0/24",   // IETF protocol assignments
		"198.18.0.0/15",  // benchmarking
		"240.0.0.0/4",    // reserved, incl. 255.255.255.255
		"64:ff9b::/96",   // NAT64
		"64:ff9b:1::/48", // local-use NAT64
		"2002::/16",      // 6to4
		"2001::/32",      // Teredo
		"100::/64",       // discard
	} {
		_, ipn, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		n = append(n, ipn)
	}
	return n
}()

// peerAllowed: TURN relays only to public addresses, never into the node's own network (no SSRF).
// The node's own public address is allowed here; relayGen limits it to relay ports.
func peerAllowed(ip net.IP, allowPrivate bool) bool {
	if ip == nil {
		return false
	}
	if allowPrivate {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	for _, n := range denied {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}
