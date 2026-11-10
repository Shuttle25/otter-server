package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const valid = `data_dir = "/var/lib/otter"
node_key = "/etc/otter/node.key"
network_pub = "0bbc346a57667c380120bd9c7fd7e51d2c5fdfea37cd2f5bf405b2c6bf6f2d78"
manifest_file = "/etc/otter/manifest.bin"
[wss]
listen = "0.0.0.0:443"
path = "/abcdefgh12"
`

func write(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "node.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValid(t *testing.T) {
	c, err := Load(write(t, valid))
	if err != nil {
		t.Fatal(err)
	}
	if c.LogLevel != "info" || c.WSS.Path != "/abcdefgh12" || c.ManifestFile == "" {
		t.Fatalf("%+v", c)
	}
	if k, err := c.NetworkPubKey(); err != nil || len(k) != 32 {
		t.Fatalf("network pub: %v", err)
	}
}

func TestInvalid(t *testing.T) {
	cases := map[string]struct{ body, field string }{
		"missing data_dir": {strings.Replace(valid, `data_dir = "/var/lib/otter"`, "", 1), "data_dir"},
		"missing listen":   {strings.Replace(valid, `listen = "0.0.0.0:443"`, "", 1), "wss.listen"},
		"bad network_pub":  {strings.Replace(valid, "0bbc346a", "zz", 1), "network_pub"},
		"short pub":        {strings.Replace(valid, "0bbc346a", "", 1), "network_pub"},
		"bad path":         {strings.Replace(valid, `path = "/abcdefgh12"`, `path = "x"`, 1), "wss.path"},
		"short path":       {strings.Replace(valid, `path = "/abcdefgh12"`, `path = "/abc"`, 1), "wss.path"},
		"cert without key": {valid + "tls_cert = \"/c.pem\"\n", "tls_cert"},
		"unknown key":      {"foo = 1\n" + valid, "foo"},
		"loud log":         {"log_level = \"loud\"\n" + valid, "log_level"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(write(t, c.body))
			if err == nil || !strings.Contains(err.Error(), c.field) {
				t.Fatalf("want error mentioning %q, got %v", c.field, err)
			}
		})
	}
}
