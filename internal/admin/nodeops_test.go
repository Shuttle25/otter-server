package admin

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ottermsg/server/internal/pinning"
)

func newNet(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := InitNetwork(dir, []byte("test-passphrase-123")); err != nil {
		t.Fatal(err)
	}
	if _, err := AddNode(dir, NodeSpec{Label: "fi-1", WSSHost: "chat.example.org", IPs: []string{"203.0.113.10"}}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func pinOf(t *testing.T, dir, label, file string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "nodes", label, file))
	if err != nil {
		t.Fatal(err)
	}
	p, err := pinning.CertPin(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func certOf(t *testing.T, dir, label, file string) *x509.Certificate {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(dir, "nodes", label, file))
	blk, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func endpointPins(t *testing.T, dir, label string) [][]byte {
	t.Helper()
	st, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range st.Nodes {
		if n.Label == label {
			return n.Endpoints[0].TlsSpkiPins
		}
	}
	t.Fatal("no node")
	return nil
}

func TestSetIPKeepsPin(t *testing.T) {
	dir := newNet(t)
	before := pinOf(t, dir, "fi-1", "tls.crt")
	if err := SetIPs(dir, "fi-1", []string{"198.51.100.7", "2001:db8::7"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, pinOf(t, dir, "fi-1", "tls.crt")) {
		t.Fatal("pin changed")
	}
	ips, _ := NodeIPs(dir, "fi-1")
	if len(ips) != 2 || ips[0] != "198.51.100.7" {
		t.Fatalf("ips %v", ips)
	}
	c := certOf(t, dir, "fi-1", "tls.crt")
	if len(c.IPAddresses) != 2 || c.DNSNames[0] != "chat.example.org" {
		t.Fatalf("SANs %v %v", c.DNSNames, c.IPAddresses)
	}
	if err := SetIPs(dir, "fi-1", []string{"nope"}); err == nil {
		t.Fatal("bad ip accepted")
	}
	if ips, _ := NodeIPs(dir, "fi-1"); len(ips) != 2 {
		t.Fatalf("a rejected set-ip changed meta.json: %v", ips)
	}
}

func TestRotateAndDropPins(t *testing.T) {
	dir := newNet(t)
	old := pinOf(t, dir, "fi-1", "tls.crt")
	newPin, err := RotateTLS(dir, "fi-1")
	if err != nil {
		t.Fatal(err)
	}
	if pins := endpointPins(t, dir, "fi-1"); len(pins) != 2 || !bytes.Equal(pins[0], old) || !bytes.Equal(pins[1], newPin) {
		t.Fatalf("pins after rotate: %d", len(pins))
	}
	if _, err := RotateTLS(dir, "fi-1"); err == nil {
		t.Fatal("second rotate must fail while staged")
	}
	env, _ := NodeEnv(dir, "fi-1")
	if env["OTTER_PIN"] != base64.StdEncoding.EncodeToString(newPin) || !strings.HasSuffix(env["OTTER_TLS_CERT"], "tls.new.crt") {
		t.Fatalf("env uses staged pair: %v", env)
	}
	if err := SetIPs(dir, "fi-1", []string{"198.51.100.7"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pinOf(t, dir, "fi-1", "tls.new.crt"), newPin) || len(certOf(t, dir, "fi-1", "tls.new.crt").IPAddresses) != 1 {
		t.Fatal("staged certificate not re-issued with the same key")
	}
	if err := DropOldPins(dir, "fi-1"); err != nil {
		t.Fatal(err)
	}
	if pins := endpointPins(t, dir, "fi-1"); len(pins) != 1 || !bytes.Equal(pins[0], newPin) {
		t.Fatal("old pin kept")
	}
	if !bytes.Equal(pinOf(t, dir, "fi-1", "tls.crt"), newPin) || !bytes.Equal(pinOf(t, dir, "fi-1", "tls.old.crt"), old) {
		t.Fatal("files not promoted")
	}
	if err := DropOldPins(dir, "fi-1"); err == nil {
		t.Fatal("drop without staged pair must fail")
	}
}

func TestNodeEnv(t *testing.T) {
	dir := newNet(t)
	env, err := NodeEnv(dir, "fi-1")
	if err != nil {
		t.Fatal(err)
	}
	if env["OTTER_HOST"] != "chat.example.org" || env["OTTER_PORT"] != "27443" || !strings.HasPrefix(env["OTTER_PATH"], "/") ||
		env["OTTER_KIND"] != "wss" || len(env["OTTER_NETWORK_PUB"]) != 64 || len(env["OTTER_NODE_ID"]) != 32 {
		t.Fatalf("%v", env)
	}
	if env["OTTER_PIN"] != base64.StdEncoding.EncodeToString(pinOf(t, dir, "fi-1", "tls.crt")) {
		t.Fatal("pin")
	}
	if got := ShellQuote("it's"); got != `'it'\''s'` {
		t.Fatal(got)
	}
	if _, err := NodeEnv(dir, "nope"); err == nil {
		t.Fatal("unknown label accepted")
	}
}

func TestSetPush(t *testing.T) {
	dir := newNet(t)
	pushOf := func() bool {
		st, err := LoadState(dir)
		if err != nil {
			t.Fatal(err)
		}
		return st.Nodes[0].PushCapable
	}
	if pushOf() {
		t.Fatal("push_capable before set-push")
	}
	if err := SetPush(dir, "fi-1", true); err != nil {
		t.Fatal(err)
	}
	if !pushOf() {
		t.Fatal("push_capable not set")
	}
	if err := SetPush(dir, "fi-1", false); err != nil || pushOf() {
		t.Fatalf("set-push --off: %v %v", err, pushOf())
	}
	if err := SetPush(dir, "nope", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown label: %v", err)
	}
}
