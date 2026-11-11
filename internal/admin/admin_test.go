package admin

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/pinning"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

var pass = []byte("a very long passphrase")

func TestFullFlow(t *testing.T) {
	dir := t.TempDir()
	if err := InitNetwork(dir, pass); err != nil {
		t.Fatal(err)
	}
	if err := InitNetwork(dir, pass); !errors.Is(err, ErrExists) {
		t.Fatalf("want ErrExists, got %v", err)
	}

	if _, err := AddNode(dir, NodeSpec{Label: "fi-1", WSSHost: "chat.example.org", WSSPort: 443}); err != nil {
		t.Fatal(err)
	}
	if _, err := AddNode(dir, NodeSpec{Label: "fi-1", WSSHost: "x"}); !errors.Is(err, ErrExists) {
		t.Fatalf("dup label: %v", err)
	}
	if _, err := AddNode(dir, NodeSpec{Label: "Bad Label", WSSHost: "x"}); err == nil {
		t.Fatal("bad label accepted")
	}
	st0, err := os.Stat(filepath.Join(dir, "nodes", "fi-1", "node.key"))
	if err != nil {
		t.Fatal(err)
	}
	if st0.Mode().Perm() != 0o600 {
		t.Fatalf("node.key mode %v", st0.Mode())
	}

	rec, err := SignManifest(dir, pass, time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	st, _ := LoadState(dir)
	v := &records.Validator{NetworkPub: st.NetworkPub, Users: noUsers{}, Now: time.Now}
	body, err := v.Validate(rec)
	if err != nil {
		t.Fatalf("manifest invalid: %v", err)
	}
	var m pb.Manifest
	proto.Unmarshal(body.Payload, &m)
	if m.Version != 1 || len(m.Nodes) != 1 || m.Nodes[0].Endpoints[0].Path == "" {
		t.Fatalf("manifest: %v", &m)
	}

	rec2, _ := SignManifest(dir, pass, time.UnixMilli(2000))
	body2, _ := v.Validate(rec2)
	var m2 pb.Manifest
	proto.Unmarshal(body2.Payload, &m2)
	if m2.Version != 2 {
		t.Fatalf("version %d", m2.Version)
	}

	if err := RemoveNode(dir, "fi-1"); err != nil {
		t.Fatal(err)
	}
	if err := RemoveNode(dir, "fi-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remove missing: %v", err)
	}
	if _, err := SignManifest(dir, []byte("wrong passphrase!!"), time.Now()); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
}

type noUsers struct{}

func (noUsers) UserKey([]byte) (records.UserKey, bool) { return records.UserKey{}, false }

func TestBootstrapInvite(t *testing.T) {
	dir := t.TempDir()
	if err := InitNetwork(dir, pass); err != nil {
		t.Fatal(err)
	}
	if _, err := BootstrapInvite(dir, pass, time.Now(), time.Hour); err == nil {
		t.Fatal("must require manifest")
	}
	if _, err := AddNode(dir, NodeSpec{Label: "dev", WSSHost: "10.0.2.2", WSSPort: 8080, Plain: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := SignManifest(dir, pass, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := BootstrapInvite(dir, []byte("wrong passphrase!!"), time.Now(), time.Hour); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	now := time.Now()
	res, err := BootstrapInvite(dir, pass, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := LoadState(dir)
	v := &records.Validator{NetworkPub: st.NetworkPub, Users: noUsers{}, Now: time.Now}
	body, err := v.Validate(res.Record)
	if err != nil || body.Type != pb.RecordType_INVITE {
		t.Fatalf("invite record: %v", err)
	}
	b, err := DecodeInviteLink(res.Link)
	if err != nil || len(b.Secret) != 32 || b.Manifest == nil || !bytes.Equal(b.NetworkPub, st.NetworkPub) {
		t.Fatalf("link: %v", err)
	}
	sum := sha256.Sum256(b.Secret)
	var inv pb.Invite
	proto.Unmarshal(body.Payload, &inv)
	if !bytes.Equal(sum[:], inv.InviteId) {
		t.Fatal("secret does not match invite_id")
	}
	exp := now.Add(time.Hour).UnixMilli()
	if inv.ExpiresMs != exp || body.ExpiresMs != exp {
		t.Fatalf("expiry: payload %d body %d want %d", inv.ExpiresMs, body.ExpiresMs, exp)
	}
	if fi, err := os.Stat(res.File); err != nil || filepath.Base(res.File) != fmt.Sprintf("%x.bin", sum[:8]) {
		t.Fatalf("invite file %s: %v %v", res.File, fi, err)
	}
	if st.Nodes[0].Endpoints[0].Kind != pb.Endpoint_WS_PLAIN {
		t.Fatal("plain endpoint")
	}
	if _, err := DecodeInviteLink("https://x/"); err == nil {
		t.Fatal("scheme")
	}
	if _, err := DecodeInviteLink(InvitePrefix + "!!!"); err == nil {
		t.Fatal("base64")
	}
}

func TestNodeTLS(t *testing.T) {
	dir := t.TempDir()
	if err := InitNetwork(dir, pass); err != nil {
		t.Fatal(err)
	}
	n, err := AddNode(dir, NodeSpec{Label: "fi-1", WSSHost: "chat.example.org", IPs: []string{"203.0.113.10"}})
	if err != nil {
		t.Fatal(err)
	}
	nd := filepath.Join(dir, "nodes", "fi-1")
	b, _ := os.ReadFile(filepath.Join(nd, "tls.crt"))
	blk, _ := pem.Decode(b)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.VerifyHostname("chat.example.org") != nil || cert.VerifyHostname("203.0.113.10") != nil {
		t.Fatal("SAN must contain host and ip")
	}
	e := n.Endpoints[0]
	if e.Port != DefaultPort || len(e.TlsSpkiPins) != 1 || !bytes.Equal(e.TlsSpkiPins[0], pinning.SPKIPin(cert)) {
		t.Fatalf("endpoint %v", e)
	}
	if st, _ := os.Stat(filepath.Join(nd, "tls.key")); st.Mode().Perm() != 0o600 {
		t.Fatal("tls.key mode")
	}
	var meta nodeMeta
	mb, _ := os.ReadFile(filepath.Join(nd, "meta.json"))
	if json.Unmarshal(mb, &meta) != nil || len(meta.IPs) != 1 {
		t.Fatalf("meta %s", mb)
	}
	if _, err := AddNode(dir, NodeSpec{Label: "bad", WSSHost: "x", IPs: []string{"nope"}}); err == nil {
		t.Fatal("bad ip accepted")
	}
	p, err := AddNode(dir, NodeSpec{Label: "dev", WSSHost: "10.0.2.2", WSSPort: 8080, Plain: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Endpoints[0].TlsSpkiPins) != 0 {
		t.Fatal("plain endpoint must have no pins")
	}
	if _, err := os.Stat(filepath.Join(dir, "nodes", "dev", "tls.crt")); !os.IsNotExist(err) {
		t.Fatal("plain node must have no cert")
	}
}
