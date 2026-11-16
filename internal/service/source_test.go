package service

import "testing"

func TestSourceOf(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7:5000":           "203.0.113.7",
		"[2001:db8:1:2:3:4:5:6]:443": "2001:db8:1:2::/64",
		"[::ffff:203.0.113.9]:80":    "203.0.113.9",
		"127.0.0.1:1":                "local",
		"[::1]:1":                    "local",
		"not an address":             "unknown",
		"":                           "unknown",
		"tunnel:00112233":            "tunnel:00112233", // restore tunnel: the relaying node (D114)
	} {
		if got := SourceOf(in); got != want {
			t.Errorf("SourceOf(%q) = %q, want %q", in, got, want)
		}
	}
}
