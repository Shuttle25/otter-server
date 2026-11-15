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

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/pinning"
	pb "ottermsg/server/internal/proto/otterv1"
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
	if env["OTTER_IP"] != "203.0.113.10" { // the first recorded public IP (reality-setup.sh)
		t.Fatalf("OTTER_IP %q", env["OTTER_IP"])
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

func TestSetDialOutOnly(t *testing.T) {
	dir := newNet(t)
	get := func() bool {
		st, err := LoadState(dir)
		if err != nil {
			t.Fatal(err)
		}
		return st.Nodes[0].DialOutOnly
	}
	if get() {
		t.Fatal("dial_out_only must default to false")
	}
	if err := SetDialOutOnly(dir, "fi-1", true); err != nil || !get() {
		t.Fatalf("set: %v %v", err, get())
	}
	if err := SetDialOutOnly(dir, "fi-1", false); err != nil || get() {
		t.Fatalf("off: %v %v", err, get())
	}
	if err := SetDialOutOnly(dir, "nope", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown label: %v", err)
	}
}

func TestAddReality(t *testing.T) {
	dir := newNet(t)
	pub := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	ep, err := AddReality(dir, RealitySpec{Label: "fi-1", Host: "203.0.113.10", Port: 443, Pub: pub, ServerName: "www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if ep.Kind != pb.Endpoint_REALITY || len(ep.RealityPub) != 32 || len(ep.ShortIds) != 1 || len(ep.ShortIds[0]) != 8 ||
		ep.VlessUuid == "" || ep.Fingerprint != "chrome" || ep.ServerNames[0] != "www.example.com" {
		t.Fatalf("endpoint: %+v", ep)
	}
	st, _ := LoadState(dir)
	n := st.Nodes[0]
	if len(n.Endpoints) != 2 || n.Endpoints[0].Kind != pb.Endpoint_WSS || n.Endpoints[1].Path != n.Endpoints[0].Path {
		t.Fatalf("endpoints: %+v", n.Endpoints)
	}
	if _, err := AddReality(dir, RealitySpec{Label: "fi-1", Host: "203.0.113.10", Port: 443, Pub: pub, ServerName: "b.example", ShortID: "abcd0123"}); err != nil {
		t.Fatal(err)
	}
	st, _ = LoadState(dir)
	if len(st.Nodes[0].Endpoints) != 2 || st.Nodes[0].Endpoints[1].ShortIds[0] != "abcd0123" {
		t.Fatalf("second add-reality must replace: %+v", st.Nodes[0].Endpoints)
	}
	if _, err := AddReality(dir, RealitySpec{Label: "fi-1", Host: "h", Port: 443, Pub: "short", ServerName: "s"}); err == nil {
		t.Fatal("bad public key accepted")
	}
	const uuid = "d6a3f0b2-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
	ep, err = AddReality(dir, RealitySpec{Label: "fi-1", Host: "203.0.113.10", Port: 443, Pub: pub, ServerName: "www.example.com", UUID: uuid})
	if err != nil || ep.VlessUuid != uuid {
		t.Fatalf("explicit uuid: %v %+v", err, ep)
	}
}

// A development node (--plain, ws://) can carry a REALITY endpoint too: the path comes from its WS_PLAIN endpoint.
func TestAddRealityOnPlainDevNode(t *testing.T) {
	dir := t.TempDir()
	if err := InitNetwork(dir, []byte("test-passphrase-123")); err != nil {
		t.Fatal(err)
	}
	if _, err := AddNode(dir, NodeSpec{Label: "fi", WSSHost: "127.0.0.1", WSSPort: 9181, Plain: true}); err != nil {
		t.Fatal(err)
	}
	pub := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	ep, err := AddReality(dir, RealitySpec{Label: "fi", Host: "127.0.0.1", Port: 24443, Pub: pub, ServerName: "www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	st, _ := LoadState(dir)
	n := st.Nodes[0]
	if len(n.Endpoints) != 2 || n.Endpoints[0].Kind != pb.Endpoint_WS_PLAIN || ep.Path == "" || ep.Path != n.Endpoints[0].Path {
		t.Fatalf("endpoints: %+v", n.Endpoints)
	}
}

func TestAddWSSCDN(t *testing.T) {
	dir := newNet(t)
	st, _ := LoadState(dir)
	own := proto.Clone(st.Nodes[0].Endpoints[0]).(*pb.Endpoint)
	ep, err := AddWSS(dir, WSSSpec{Label: "fi-1", Host: "n2.example.net", Port: 443, CDN: true, Priority: 10})
	if err != nil {
		t.Fatal(err)
	}
	if ep.Kind != pb.Endpoint_WSS || !ep.ViaCdn || len(ep.TlsSpkiPins) != 0 || ep.Priority != 10 || ep.Path != own.Path || ep.Port != 443 {
		t.Fatalf("endpoint: %+v", ep)
	}
	st, _ = LoadState(dir)
	n := st.Nodes[0]
	if len(n.Endpoints) != 2 || !proto.Equal(n.Endpoints[0], own) {
		t.Fatalf("endpoints: %+v", n.Endpoints)
	}
	if _, err := AddWSS(dir, WSSSpec{Label: "fi-1", Host: "n2.example.net", Port: 443, CDN: true, Priority: 20}); err != nil {
		t.Fatal(err)
	}
	st, _ = LoadState(dir)
	if len(st.Nodes[0].Endpoints) != 2 || st.Nodes[0].Endpoints[1].Priority != 20 {
		t.Fatalf("second add must replace: %+v", st.Nodes[0].Endpoints)
	}
	if _, err := AddWSS(dir, WSSSpec{Label: "fi-1", Host: "n3.example.net", Port: 8443}); err != nil {
		t.Fatal(err)
	}
	st, _ = LoadState(dir)
	if e := st.Nodes[0].Endpoints[2]; e.ViaCdn || len(e.TlsSpkiPins) == 0 || !bytes.Equal(e.TlsSpkiPins[0], own.TlsSpkiPins[0]) {
		t.Fatalf("a direct extra endpoint must carry the node's pins: %+v", e)
	}
	for _, bad := range []WSSSpec{
		{Label: "fi-1", Host: "", Port: 443},
		{Label: "fi-1", Host: "x.example.net", Port: 0},
		{Label: "fi-1", Host: "x.example.net", Port: 70000},
		{Label: "fi-1", Host: own.Host, Port: own.Port},
		{Label: "nope", Host: "x.example.net", Port: 443},
	} {
		if _, err := AddWSS(dir, bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

func TestRemoveEndpoint(t *testing.T) {
	dir := newNet(t)
	if _, err := AddWSS(dir, WSSSpec{Label: "fi-1", Host: "n2.example.net", Port: 443, CDN: true, Priority: 10}); err != nil {
		t.Fatal(err)
	}
	st, _ := LoadState(dir)
	own := st.Nodes[0].Endpoints[0]
	if err := RemoveEndpoint(dir, "fi-1", own.Host, own.Port); err == nil {
		t.Fatal("removed the node's own endpoint")
	}
	if err := RemoveEndpoint(dir, "fi-1", "missing.example.net", 443); err == nil {
		t.Fatal("removed a missing endpoint")
	}
	if err := RemoveEndpoint(dir, "fi-1", "n2.example.net", 443); err != nil {
		t.Fatal(err)
	}
	st, _ = LoadState(dir)
	if len(st.Nodes[0].Endpoints) != 1 {
		t.Fatalf("endpoints: %+v", st.Nodes[0].Endpoints)
	}
}
