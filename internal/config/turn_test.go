package config

import (
	"strings"
	"testing"
)

// withTLS is the valid config with a TLS pair in [wss] (the last section of valid).
const withTLS = valid + `tls_cert = "/etc/otter/tls.crt"
tls_key = "/etc/otter/tls.key"
`

func TestTurnDefaultsAndValidation(t *testing.T) {
	c, err := Load(write(t, withTLS+"[turn]\nenabled = true\nrelay_ip = \"203.0.113.7\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	tc := c.Turn
	if !c.TurnEnabled() || tc.UDPListen != ":3478" || tc.TCPListen != ":3478" || tc.TLSListen != ":5349" ||
		tc.RelayPortMin != 49160 || tc.RelayPortMax != 49200 || tc.SecretFile != "/etc/otter/turn.secret" ||
		tc.MaxAllocationsPerUser != 4 || tc.MaxAllocations != 41 || tc.RelayKbps != 200 || tc.Realm != "otter" {
		t.Fatalf("defaults: %+v", tc)
	}
	for name, extra := range map[string]string{
		"no relay_ip":   "[turn]\nenabled = true\n",
		"bad relay_ip":  "[turn]\nenabled = true\nrelay_ip = \"nope\"\n",
		"ipv6 relay_ip": "[turn]\nenabled = true\nrelay_ip = \"2001:db8::1\"\n",
		"min > max":     "[turn]\nenabled = true\nrelay_ip = \"203.0.113.7\"\nrelay_port_min = 50000\nrelay_port_max = 49000\n",
		"low port":      "[turn]\nenabled = true\nrelay_ip = \"203.0.113.7\"\nrelay_port_min = 80\n",
		"high port":     "[turn]\nenabled = true\nrelay_ip = \"203.0.113.7\"\nrelay_port_max = 70000\n",
		"too many":      "[turn]\nenabled = true\nrelay_ip = \"203.0.113.7\"\nmax_allocations = 500\n",
		"unknown key":   "[turn]\nenabled = true\nrelay_ip = \"203.0.113.7\"\nbogus = 1\n",
	} {
		if _, err := Load(write(t, withTLS+extra)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if c, err := Load(write(t, withTLS)); err != nil || c.TurnEnabled() {
		t.Fatalf("no [turn] must stay off: %v %v", c, err)
	}
}

func TestTurnWithoutTLS(t *testing.T) {
	c, err := Load(write(t, valid+"[turn]\nenabled = true\nrelay_ip = \"203.0.113.7\"\n"))
	if err != nil || c.Turn.TLSListen != "" {
		t.Fatalf("plain node: TURN without TLS: %v %+v", err, c)
	}
	_, err = Load(write(t, valid+"[turn]\nenabled = true\nrelay_ip = \"203.0.113.7\"\ntls_listen = \":5349\"\n"))
	if err == nil || !strings.Contains(err.Error(), "tls_listen") {
		t.Fatalf("tls_listen without a cert: want error, got %v", err)
	}
}
