package nodecheck

import (
	"encoding/hex"
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
	if err != nil || len(lines) != 5 {
		t.Fatalf("%v %q", err, lines)
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
