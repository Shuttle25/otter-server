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

func TestMeshAllowPlain(t *testing.T) {
	c, err := Load(write(t, valid))
	if err != nil || c.Mesh.AllowPlain {
		t.Fatalf("default must be false: %v %v", c.Mesh.AllowPlain, err)
	}
	c, err = Load(write(t, valid+"[mesh]\nallow_plain = true\n"))
	if err != nil || !c.Mesh.AllowPlain {
		t.Fatalf("allow_plain: %v %v", c, err)
	}
}

func TestLimits(t *testing.T) {
	c, err := Load(write(t, valid))
	if err != nil || c.UserQuotaBytes != 2<<30 || c.MaxBlobBytes != 100<<20 || c.BlobBytesPerSec != 2_000_000 {
		t.Fatalf("defaults: %d %d %d %v", c.UserQuotaBytes, c.MaxBlobBytes, c.BlobBytesPerSec, err)
	}
	c, err = Load(write(t, valid+"[limits]\nuser_quota = \"1MiB\"\nmax_blob = \"500KB\"\n[replication]\nblob_bandwidth = \"0\"\n"))
	if err != nil || c.UserQuotaBytes != 1<<20 || c.MaxBlobBytes != 500_000 || c.BlobBytesPerSec != 0 {
		t.Fatalf("set: %d %d %d %v", c.UserQuotaBytes, c.MaxBlobBytes, c.BlobBytesPerSec, err)
	}
	if c.DiskFloorBytes != 1<<30 {
		t.Fatalf("disk_floor default: %d", c.DiskFloorBytes)
	}
	for in, want := range map[string]int64{"2GiB": 2 << 30, "0": 0} {
		c, err = Load(write(t, valid+"[limits]\ndisk_floor = \""+in+"\"\n"))
		if err != nil || c.DiskFloorBytes != want {
			t.Fatalf("disk_floor %q: %d %v", in, c.DiskFloorBytes, err)
		}
	}
	if _, err := Load(write(t, valid+"[limits]\ndisk_floor = \"lots\"\n")); err == nil || !strings.Contains(err.Error(), "limits.disk_floor") {
		t.Fatalf("bad disk_floor: %v", err)
	}
	for _, bad := range []string{
		"[limits]\nuser_quota = \"lots\"\n", "[limits]\nmax_blob = \"200MiB\"\n", "[limits]\nmax_blob = \"-1MiB\"\n",
		"[replication]\nblob_bandwidth = \"2MB\"\n",
	} {
		if _, err := Load(write(t, valid+bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"10": 10, "10B": 10, "1KiB": 1024, "1.5 MiB": 3 << 19, "2GiB": 2 << 30, "3KB": 3000, "2MB": 2e6, "1GB": 1e9} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("%q: %d %v", in, got, err)
		}
	}
	if got, err := ParseRate("2MB/s"); err != nil || got != 2e6 {
		t.Errorf("rate %d %v", got, err)
	}
}

func TestPush(t *testing.T) {
	c, err := Load(write(t, valid))
	if err != nil || c.PushEnabled() {
		t.Fatalf("no [push]: enabled=%v err=%v", c != nil && c.PushEnabled(), err)
	}
	key := filepath.Join(t.TempDir(), "fcm.json")
	c, err = Load(write(t, valid+"[push]\nfcm_credentials = \""+key+"\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Push.FCMCredentials != key || c.PushEnabled() {
		t.Fatalf("missing key file must mean push off: %+v", c.Push)
	}
	if err := os.WriteFile(key, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !c.PushEnabled() {
		t.Fatal("key file present: push should be on")
	}
	if _, err := Load(write(t, valid+"[push]\nfcm_key = \"x\"\n")); err == nil || !strings.Contains(err.Error(), "fcm_key") {
		t.Fatalf("unknown [push] key accepted: %v", err)
	}
}

func TestRealitySection(t *testing.T) {
	ok := `
[reality]
listen = ":443"
private_key_file = "/etc/otter/reality.key"
dest = "www.example.com:443"
server_names = ["www.example.com"]
short_ids = ["a1b2c3d4"]
vless_uuid = "d6a3f0b2-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
`
	c, err := Load(write(t, valid+ok))
	if err != nil || !c.RealityEnabled() || c.Reality.Dest != "www.example.com:443" || len(c.Reality.ShortIDs) != 1 {
		t.Fatalf("valid [reality]: %v %+v", err, c)
	}
	for name, bad := range map[string]string{
		"dest without port": strings.Replace(ok, `dest = "www.example.com:443"`, `dest = "www.example.com"`, 1),
		"no vless_uuid":     strings.Replace(ok, `vless_uuid = "d6a3f0b2-1c2d-4e5f-8a9b-0c1d2e3f4a5b"`, ``, 1),
		"no short_ids":      strings.Replace(ok, `short_ids = ["a1b2c3d4"]`, ``, 1),
		"no listen":         strings.Replace(ok, `listen = ":443"`, ``, 1),
	} {
		if _, err := Load(write(t, valid+bad)); err == nil || !strings.Contains(err.Error(), "reality") {
			t.Errorf("%s: want a reality error, got %v", name, err)
		}
	}
	c, err = Load(write(t, valid))
	if err != nil || c.RealityEnabled() {
		t.Fatalf("no [reality]: %v", err)
	}
}

// D116: per-IP limits default to 32 connections and 50 requests/s; 0 = default, negative is refused.
func TestIPLimits(t *testing.T) {
	c, err := Load(write(t, valid))
	if err != nil || c.ConnsPerIP() != 32 || c.RequestsPerIP() != 50 {
		t.Fatalf("defaults: %d %d %v", c.ConnsPerIP(), c.RequestsPerIP(), err)
	}
	c, err = Load(write(t, valid+"[limits]\nconns_per_ip = 8\nrequests_per_ip = 200\n"))
	if err != nil || c.ConnsPerIP() != 8 || c.RequestsPerIP() != 200 {
		t.Fatalf("set: %d %d %v", c.ConnsPerIP(), c.RequestsPerIP(), err)
	}
	for _, bad := range []string{"[limits]\nconns_per_ip = -1\n", "[limits]\nrequests_per_ip = -5\n"} {
		if _, err := Load(write(t, valid+bad)); err == nil || !strings.Contains(err.Error(), "limits.") {
			t.Errorf("accepted %q: %v", bad, err)
		}
	}
}
