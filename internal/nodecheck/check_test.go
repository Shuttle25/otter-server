package nodecheck

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ottermsg/server/internal/admin"
	"ottermsg/server/internal/pinning"
	"ottermsg/server/internal/reality"
	"ottermsg/server/internal/turnsrv"
)

const pass = "test-passphrase-123"

// setup returns a node.toml for node fi-1 of a fresh network and the node's directory in the admin dir.
func setup(t *testing.T, wssPath string) (cfg, nodeDir string) {
	dir := t.TempDir()
	if err := admin.InitNetwork(dir, []byte(pass)); err != nil {
		t.Fatal(err)
	}
	n, err := admin.AddNode(dir, admin.NodeSpec{Label: "fi-1", WSSHost: "chat.test", IPs: []string{"203.0.113.10"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.SignManifest(dir, []byte(pass), time.Now()); err != nil {
		t.Fatal(err)
	}
	st, _ := admin.LoadState(dir)
	if wssPath == "" {
		wssPath = n.Endpoints[0].Path
	}
	nodeDir = filepath.Join(dir, "nodes", "fi-1")
	cfg = filepath.Join(t.TempDir(), "node.toml")
	body := fmt.Sprintf(`data_dir = %q
node_key = %q
network_pub = %q
manifest_file = %q
[wss]
listen = ":27443"
path = %q
tls_cert = %q
tls_key = %q
`, t.TempDir(), filepath.Join(nodeDir, "node.key"), hex.EncodeToString(st.NetworkPub), filepath.Join(dir, "manifest.bin"),
		wssPath, filepath.Join(nodeDir, "tls.crt"), filepath.Join(nodeDir, "tls.key"))
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg, nodeDir
}

func TestCheckOK(t *testing.T) {
	cfg, _ := setup(t, "")
	lines, err := Run(cfg)
	if err != nil || len(lines) != 6 || lines[5] != "ok push off (no key file)" {
		t.Fatalf("%v %q", err, lines)
	}
}

// withPush adds [push] fcm_credentials to the config and writes key (nil: no file).
func withPush(t *testing.T, cfg string, key []byte) {
	p := filepath.Join(t.TempDir(), "fcm.json")
	f, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(f, "[push]\nfcm_credentials = %q\n", p)
	f.Close()
	if key != nil {
		if err := os.WriteFile(p, key, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCheckPushKey(t *testing.T) {
	cfg, _ := setup(t, "")
	withPush(t, cfg, nil)
	if lines, err := Run(cfg); err != nil || lines[len(lines)-1] != "ok push off (no key file)" {
		t.Fatalf("missing key file: %v %q", err, lines)
	}

	cfg, _ = setup(t, "")
	withPush(t, cfg, []byte(`{"type":"service_account"}`))
	if _, err := Run(cfg); err == nil || !strings.Contains(err.Error(), "push key") {
		t.Fatalf("want push key error, got %v", err)
	}

	cfg, _ = setup(t, "")
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	sa, _ := json.Marshal(map[string]string{"type": "service_account", "project_id": "otter-test",
		"private_key_id": "k1", "private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email": "otter@otter-test.iam.gserviceaccount.com", "token_uri": "https://oauth2.invalid/token"})
	withPush(t, cfg, sa)
	if lines, err := Run(cfg); err != nil || lines[len(lines)-1] != "ok push key (project otter-test)" {
		t.Fatalf("valid key: %v %q", err, lines)
	}
}

func TestCheckWrongCert(t *testing.T) {
	cfg, nd := setup(t, "")
	c, k, _, _ := pinning.GenerateCert([]string{"chat.test"}, nil, time.Hour)
	os.WriteFile(filepath.Join(nd, "tls.crt"), c, 0o644)
	os.WriteFile(filepath.Join(nd, "tls.key"), k, 0o600)
	if _, err := Run(cfg); err == nil || !strings.Contains(err.Error(), "pin") {
		t.Fatalf("want pin error, got %v", err)
	}
}

func TestCheckWrongPath(t *testing.T) {
	cfg, _ := setup(t, "/elsewhere")
	if _, err := Run(cfg); err == nil || !strings.Contains(err.Error(), "wss.path") {
		t.Fatalf("want wss.path error, got %v", err)
	}
}

// withReality adds a [reality] section whose key file is keyPath.
func withReality(t *testing.T, cfg, keyPath string) {
	f, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(f, `[reality]
listen = ":443"
private_key_file = %q
dest = "www.example.com:443"
server_names = ["www.example.com"]
short_ids = ["a1b2c3d4"]
vless_uuid = "d6a3f0b2-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
`, keyPath)
	f.Close()
}

func TestCheckRealityKey(t *testing.T) {
	cfg, _ := setup(t, "")
	withReality(t, cfg, filepath.Join(t.TempDir(), "missing.key"))
	if _, err := Run(cfg); err == nil || !strings.Contains(err.Error(), "reality key") {
		t.Fatalf("missing key file: want reality key error, got %v", err)
	}

	cfg, _ = setup(t, "")
	keyPath := filepath.Join(t.TempDir(), "reality.key")
	priv, pub, _ := reality.GenerateKey()
	if err := reality.WriteKeyFile(keyPath, priv); err != nil {
		t.Fatal(err)
	}
	withReality(t, cfg, keyPath)
	lines, err := Run(cfg)
	if err != nil || !strings.HasPrefix(lines[len(lines)-1], "ok reality key ") || !strings.Contains(lines[len(lines)-1], pub) {
		t.Fatalf("valid key: %v %q", err, lines)
	}
}

// A manifest REALITY endpoint must carry this node's public key; its path equals wss.path but it is not the WSS
// endpoint the TLS pins are checked against.
func TestCheckRealityManifestPub(t *testing.T) {
	for _, match := range []bool{true, false} {
		cfg, nd := setup(t, "")
		dir := filepath.Dir(filepath.Dir(nd))
		keyPath := filepath.Join(t.TempDir(), "reality.key")
		priv, pub, _ := reality.GenerateKey()
		reality.WriteKeyFile(keyPath, priv)
		withReality(t, cfg, keyPath)
		if !match {
			_, pub, _ = reality.GenerateKey()
		}
		if _, err := admin.AddReality(dir, admin.RealitySpec{Label: "fi-1", Host: "203.0.113.10", Port: 443, Pub: pub,
			ServerName: "www.example.com", ShortID: "a1b2c3d4"}); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.SignManifest(dir, []byte(pass), time.Now()); err != nil {
			t.Fatal(err)
		}
		lines, err := Run(cfg)
		if match && (err != nil || !strings.Contains(lines[len(lines)-1], "matches the manifest")) {
			t.Fatalf("matching pub: %v %q", err, lines)
		}
		if !match && (err == nil || !strings.Contains(err.Error(), "reality key")) {
			t.Fatalf("other pub: want reality key error, got %v %q", err, lines)
		}
	}
}

// withTurn adds an enabled [turn] section whose secret file is secretPath.
func withTurn(t *testing.T, cfg, secretPath string) {
	f, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(f, "[turn]\nenabled = true\nrelay_ip = \"203.0.113.10\"\nsecret_file = %q\n", secretPath)
	f.Close()
}

func TestCheckTurnSecret(t *testing.T) {
	cfg, _ := setup(t, "")
	withTurn(t, cfg, filepath.Join(t.TempDir(), "missing.secret"))
	if _, err := Run(cfg); err == nil || !strings.Contains(err.Error(), "turn secret") {
		t.Fatalf("missing secret: want turn secret error, got %v", err)
	}

	cfg, _ = setup(t, "")
	short := filepath.Join(t.TempDir(), "short.secret")
	os.WriteFile(short, make([]byte, 16), 0o640)
	withTurn(t, cfg, short)
	if _, err := Run(cfg); err == nil || !strings.Contains(err.Error(), "turn secret") {
		t.Fatalf("short secret: want turn secret error, got %v", err)
	}

	cfg, _ = setup(t, "")
	p := filepath.Join(t.TempDir(), "turn.secret")
	if err := turnsrv.WriteSecret(p, false); err != nil {
		t.Fatal(err)
	}
	withTurn(t, cfg, p)
	lines, err := Run(cfg)
	want := fmt.Sprintf("ok turn secret %s (32 bytes), relay 203.0.113.10:49160-49200", p)
	if err != nil || lines[len(lines)-1] != want {
		t.Fatalf("valid secret: %v %q", err, lines)
	}
}
