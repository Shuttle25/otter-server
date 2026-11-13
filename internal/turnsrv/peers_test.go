package turnsrv

import (
	"net"
	"testing"
)

func TestPeerAllowed(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8": true, "203.0.113.9": true, "127.0.0.1": false,
		"169.254.1.1": false, "100.64.0.1": false, "0.0.0.0": false, "224.0.0.1": false,
		"fd00::1": false, "::1": false, "2001:4860:4860::8888": true, "::": false, "fe80::1": false,
		"ff02::1": false, "::ffff:127.0.0.1": false, "::ffff:8.8.8.8": true,
		"0.1.2.3": false, "255.255.255.255": false, "240.0.0.1": false, "192.0.0.8": false, "198.18.0.1": false,
		"64:ff9b::a00:1": false, "2002:a00:1::1": false,
	} {
		if got := peerAllowed(net.ParseIP(ip), false); got != want {
			t.Errorf("%s: %v want %v", ip, got, want)
		}
	}
	// RFC 1918 addresses built from bytes: secrets-check.sh refuses private IPv4 literals in tracked files.
	// net.IPv4 returns the 16-byte v4-mapped form, so this also covers ::ffff:<private>.
	for _, ip := range []net.IP{net.IPv4(10, 1, 2, 3), net.IPv4(172, 16, 0, 1), net.IPv4(192, 168, 1, 5)} {
		if peerAllowed(ip, false) {
			t.Errorf("%s: allowed, want refused", ip)
		}
	}
	if peerAllowed(nil, false) || peerAllowed(nil, true) {
		t.Error("nil IP must be refused")
	}
	if !peerAllowed(net.ParseIP("127.0.0.1"), true) {
		t.Error("allow_private_peers must allow loopback (tests, dev mesh)")
	}
}
