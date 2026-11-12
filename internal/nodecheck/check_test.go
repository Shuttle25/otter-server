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
