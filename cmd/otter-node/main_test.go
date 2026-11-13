package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/admin"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/reality"
	"ottermsg/server/internal/store"
	"ottermsg/server/internal/turnsrv"
)

var pass = []byte("a very long passphrase")

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func freePort(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// testNode creates a throwaway network with node n1 and returns its config path and manifest path.
func testNode(t *testing.T) (cfg, manifest string, n *pb.NodeInfo, addr, path string) {
	t.Helper()
	dir := t.TempDir()
	adm := filepath.Join(dir, "admin")
	if err := admin.InitNetwork(adm, pass); err != nil {
		t.Fatal(err)
	}
	var err error
	n, err = admin.AddNode(adm, admin.NodeSpec{Label: "n1", WSSHost: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.SignManifest(adm, pass, time.Now()); err != nil {
		t.Fatal(err)
	}
	st, _ := admin.LoadState(adm)
	addr = freePort(t)
	path = n.Endpoints[0].Path
	cfg = filepath.Join(dir, "node.toml")
	os.WriteFile(cfg, []byte(fmt.Sprintf(`data_dir = %q
node_key = %q
network_pub = %q
[wss]
listen = %q
path = %q
`, filepath.Join(dir, "data"), filepath.Join(adm, "nodes", "n1", "node.key"), hex.EncodeToString(st.NetworkPub), addr, path)), 0o600)
	return cfg, filepath.Join(adm, "manifest.bin"), n, addr, path
}

func TestStats(t *testing.T) {
	cfg, manifest, _, _, _ := testNode(t)
	var out bytes.Buffer
	if err := run(context.Background(), []string{"import", "--config", cfg, manifest}, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run(context.Background(), []string{"stats", "--config", cfg}, &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); !strings.HasPrefix(got, "users=0 records=1 oplog_seq=1 blobs=0 blob_bytes=0 peers=") ||
		strings.Contains(got, "turn_") {
		t.Fatalf("stats: %q", got)
	}

	// a running relay publishes its counters next to the database; only a fresh snapshot is shown
	snap := filepath.Join(filepath.Dir(cfg), "data", "turn.stats.json")
	var ts turnsrv.Stats
	ts.Allocations.Store(2)
	ts.Relayed.Store(12345)
	for _, c := range []struct {
		at   time.Time
		want bool
	}{{time.Now(), true}, {time.Now().Add(-2 * time.Minute), false}} {
		if err := ts.WriteFile(snap, c.at); err != nil {
			t.Fatal(err)
		}
		out.Reset()
		if err := run(context.Background(), []string{"stats", "--config", cfg}, &out); err != nil {
			t.Fatal(err)
		}
		got := out.String()
		if has := strings.HasSuffix(got, " turn_allocs=2 turn_relayed_bytes=12345\n"); has != c.want {
			t.Fatalf("snapshot at %v: %q", c.at, got)
		}
	}
}

func TestImportAndRun(t *testing.T) {
	cfg, manifest, n, addr, path := testNode(t)
	dir := filepath.Dir(cfg)
	var err error
	var out bytes.Buffer
	if err := run(context.Background(), []string{"import", "--config", cfg, manifest}, &out); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"import", "--config", cfg, manifest}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "applied") || !strings.Contains(out.String(), "already present") {
		t.Fatalf("import output: %s", out.String())
	}
	bogus := filepath.Join(dir, "bogus.bin")
	os.WriteFile(bogus, []byte("not a record at all"), 0o600)
	if err := run(context.Background(), []string{"import", "--config", cfg, bogus}, &out); err == nil {
		t.Fatal("bogus import accepted")
	}

	ctx, cancel := context.WithCancel(context.Background())
	logs := &syncBuf{}
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"run", "--config", cfg}, logs) }()

	var c *websocket.Conn
	for i := 0; i < 100; i++ {
		dctx, dcancel := context.WithTimeout(context.Background(), time.Second)
		c, _, err = websocket.Dial(dctx, "ws://"+addr+path, nil)
		dcancel()
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial: %v\nlogs: %s", err, logs.String())
	}
	rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, data, err := c.Read(rctx)
	rcancel()
	if err != nil {
		t.Fatal(err)
	}
	var f pb.Frame
	proto.Unmarshal(data, &f)
	var hello pb.Hello
	proto.Unmarshal(f.GetEvent().GetBody(), &hello)
	if f.GetEvent().GetType() != "hello" || hello.ManifestVersion != 1 || !bytes.Equal(hello.NodeId, n.NodeId) {
		t.Fatalf("hello: %v %v", f.GetEvent(), &hello)
	}
	if strings.Contains(logs.String(), "not listed in the manifest") {
		t.Fatalf("node should be in the manifest: %s", logs.String())
	}
	c.CloseNow()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not stop")
	}
}

func TestProbeNeedsPin(t *testing.T) {
	var out bytes.Buffer
	err := run(context.Background(), []string{"probe", "--url", "wss://x:1/p"}, &out)
	if err == nil || !strings.Contains(err.Error(), "--pin") {
		t.Fatalf("got %v", err)
	}
}

func TestBackupNeedsOut(t *testing.T) {
	var out bytes.Buffer
	err := run(context.Background(), []string{"backup", "--config", "/nonexistent.toml"}, &out)
	if err == nil || !strings.Contains(err.Error(), "--out") {
		t.Fatalf("got %v", err)
	}
}

func TestApkImport(t *testing.T) {
	cfg, _, _, _, _ := testNode(t)
	apkFile := filepath.Join(t.TempDir(), "otter-0.6.0.apk")
	data := bytes.Repeat([]byte("apk!"), 1000)
	if err := os.WriteFile(apkFile, data, 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run(context.Background(), []string{"apk", "import", "--config", cfg, apkFile}, &out); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if want := fmt.Sprintf("%s: stored %x\n", apkFile, sum); out.String() != want {
		t.Fatalf("output %q, want %q", out.String(), want)
	}
	stored := filepath.Join(filepath.Dir(cfg), "data", "apk", hex.EncodeToString(sum[:])+".apk")
	if got, err := os.ReadFile(stored); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("stored file: %v", err)
	}
	if err := run(context.Background(), []string{"apk", "--config", cfg, apkFile}, &out); err == nil {
		t.Fatal("apk without import accepted")
	}
	if err := run(context.Background(), []string{"apk", "import", "--config", cfg}, &out); err == nil {
		t.Fatal("apk import without files accepted")
	}

	// the running node serves it (apk.get)
	a, err := open(cfg, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	chunk, total, err := a.svc.ApkChunk(sum[:], 0)
	if err != nil || total != uint64(len(data)) || !bytes.Equal(chunk, data) {
		t.Fatalf("ApkChunk: %d %v", total, err)
	}
}

// appendConfig adds text to a config written by testNode.
func appendConfig(t *testing.T, cfg, text string) {
	f, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
}

func realitySection(listen, keyPath, dest string) string {
	return fmt.Sprintf(`[reality]
listen = %q
private_key_file = %q
dest = %q
server_names = ["camo.test"]
short_ids = ["a1b2"]
vless_uuid = "d6a3f0b2-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
`, listen, keyPath, dest)
}

func TestRealityKeygen(t *testing.T) {
	cfg, _, _, _, _ := testNode(t)
	keyPath := filepath.Join(t.TempDir(), "reality.key")
	var out bytes.Buffer
	if err := run(context.Background(), []string{"reality", "keygen", "--config", cfg}, &out); err == nil ||
		!strings.Contains(err.Error(), "[reality]") {
		t.Fatalf("keygen without [reality]: %v", err)
	}
	appendConfig(t, cfg, realitySection("127.0.0.1:0", keyPath, "127.0.0.1:1"))
	out.Reset()
	if err := run(context.Background(), []string{"reality", "keygen", "--config", cfg}, &out); err != nil {
		t.Fatal(err)
	}
	first := out.String()
	if !strings.HasPrefix(first, "public key: ") {
		t.Fatalf("output %q", first)
	}
	pub := strings.TrimPrefix(strings.TrimSpace(first), "public key: ")
	priv, err := reality.ReadKeyFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := reality.PublicFromPrivate(priv); p != pub {
		t.Fatalf("printed %s, key file has %s", pub, p)
	}
	out.Reset()
	if err := run(context.Background(), []string{"reality", "keygen", "--config", cfg}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "exists") || !strings.Contains(out.String(), pub) {
		t.Fatalf("second keygen must keep the key and re-print it: %q", out.String())
	}
	if again, _ := reality.ReadKeyFile(keyPath); again != priv {
		t.Fatal("second keygen replaced the key")
	}
	if err := run(context.Background(), []string{"reality"}, &out); err == nil {
		t.Fatal("reality without keygen accepted")
	}
}

func TestRealityCheckCommand(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"reality-check"}, &out); err == nil {
		t.Fatal("no hosts accepted")
	}
	out.Reset()
	if err := run(context.Background(), []string{"reality-check", "nonexistent.invalid"}, &out); err == nil ||
		!strings.HasPrefix(out.String(), "FAIL nonexistent.invalid") {
		t.Fatalf("%v %q", err, out.String())
	}
}

func TestNetlogCommand(t *testing.T) {
	cfg, _, _, _, _ := testNode(t)
	var out bytes.Buffer
	if err := run(context.Background(), []string{"netlog", "--config", cfg}, &out); err != nil || out.Len() != 0 {
		t.Fatalf("empty log: %v %q", err, out.String())
	}
	st, err := store.Open(filepath.Join(filepath.Dir(cfg), "data", "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		st.NetlogAdd(ctx, store.NetlogEntry{Peer: "eeee", Endpoint: "reality:203.0.113.5:443", Direction: "out", Result: "ok", Class: "ok"})
	}
	st.NetlogAdd(ctx, store.NetlogEntry{Peer: "fi-1", Endpoint: "wss:203.0.113.6:27443", Direction: "out", Result: "fail",
		Class: "timeout", Detail: "i/o timeout"})
	st.Close()
	out.Reset()
	if err := run(ctx, []string{"netlog", "--config", cfg}, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.HasSuffix(lines[0], "  fi-1  wss:203.0.113.6:27443  out  fail timeout  ×1  (i/o timeout)") ||
		!strings.HasSuffix(lines[1], "  eeee  reality:203.0.113.5:443  out  ok  ×3") {
		t.Fatalf("netlog:\n%s", out.String())
	}
	out.Reset()
	if err := run(ctx, []string{"netlog", "--config", cfg, "--limit", "1", "--json"}, &out); err != nil {
		t.Fatal(err)
	}
	var es []store.NetlogEntry
	if err := json.Unmarshal(out.Bytes(), &es); err != nil || len(es) != 1 || es[0].Peer != "fi-1" {
		t.Fatalf("json: %v %s", err, out.String())
	}
}

// With [reality], run serves the client WebSocket through the REALITY listener as well (D72).
func TestRunWithReality(t *testing.T) {
	cfg, manifest, n, _, path := testNode(t)
	var out bytes.Buffer
	if err := run(context.Background(), []string{"import", "--config", cfg, manifest}, &out); err != nil {
		t.Fatal(err)
	}
	camo := httptest.NewUnstartedServer(http.NotFoundHandler())
	camo.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	camo.StartTLS()
	defer camo.Close()
	raddr := freePort(t)
	appendConfig(t, cfg, realitySection(raddr, filepath.Join(t.TempDir(), "reality.key"), camo.Listener.Addr().String()))
	out.Reset()
	if err := run(context.Background(), []string{"reality", "keygen", "--config", cfg}, &out); err != nil {
		t.Fatal(err)
	}
	pub, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(out.String()), "public key: "))

	ctx, cancel := context.WithCancel(context.Background())
	logs := &syncBuf{}
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"run", "--config", cfg}, logs) }()

	host, port, _ := net.SplitHostPort(raddr)
	p, _ := strconv.Atoi(port)
	ep := &pb.Endpoint{Kind: pb.Endpoint_REALITY, Host: host, Port: uint32(p), Path: path, VlessUuid: "d6a3f0b2-1c2d-4e5f-8a9b-0c1d2e3f4a5b",
		RealityPub: pub, ShortIds: []string{"a1b2"}, ServerNames: []string{"camo.test"}, Fingerprint: "chrome"}
	rc := reality.NewClient()
	defer rc.Close()
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return rc.DialContext(ctx, ep)
	}}}
	var c *websocket.Conn
	var err error
	for i := 0; i < 50; i++ {
		dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
		c, _, err = websocket.Dial(dctx, "ws://"+raddr+path, &websocket.DialOptions{HTTPClient: hc})
		dcancel()
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial through reality: %v\nlogs: %s", err, logs.String())
	}
	rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, data, err := c.Read(rctx)
	rcancel()
	if err != nil {
		t.Fatal(err)
	}
	var f pb.Frame
	proto.Unmarshal(data, &f)
	var hello pb.Hello
	proto.Unmarshal(f.GetEvent().GetBody(), &hello)
	if f.GetEvent().GetType() != "hello" || !bytes.Equal(hello.NodeId, n.NodeId) {
		t.Fatalf("hello: %v", f.GetEvent())
	}
	if !strings.Contains(logs.String(), "reality on") {
		t.Fatalf("logs: %s", logs.String())
	}
	c.CloseNow()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not stop")
	}
}

func TestTurnKeygen(t *testing.T) {
	cfg, _, _, _, _ := testNode(t)
	secret := filepath.Join(t.TempDir(), "turn.secret")
	appendConfig(t, cfg, fmt.Sprintf("[turn]\nenabled = true\nrelay_ip = \"203.0.113.7\"\nsecret_file = %q\n", secret))
	var out bytes.Buffer
	if err := run(context.Background(), []string{"turn", "keygen", "--config", cfg}, &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "turn secret written "+secret {
		t.Fatalf("output %q", got)
	}
	first, err := turnsrv.ReadSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), string(first)) || strings.Contains(out.String(), hex.EncodeToString(first)) {
		t.Fatal("secret printed")
	}
	if err := run(context.Background(), []string{"turn", "keygen", "--config", cfg}, &out); err == nil {
		t.Fatal("second keygen without --force accepted")
	}
	if err := run(context.Background(), []string{"turn", "keygen", "--config", cfg, "--force"}, &out); err != nil {
		t.Fatal(err)
	}
	if again, _ := turnsrv.ReadSecret(secret); bytes.Equal(again, first) {
		t.Fatal("--force did not replace the secret")
	}
	if err := run(context.Background(), []string{"turn"}, &out); err == nil {
		t.Fatal("turn without keygen accepted")
	}
}

func turnSection(listen, secret string) string {
	return fmt.Sprintf("[turn]\nenabled = true\nudp_listen = %q\ntcp_listen = %q\nrelay_ip = \"127.0.0.1\"\nsecret_file = %q\nallow_private_peers = true\n",
		listen, listen, secret)
}

// runNode starts `otter-node run`, waits for the hello on the client WebSocket and returns the logs and a stop func.
func runNode(t *testing.T, cfg, addr, path string) (*syncBuf, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	logs := &syncBuf{}
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"run", "--config", cfg}, logs) }()
	var c *websocket.Conn
	var err error
	for i := 0; i < 100; i++ {
		dctx, dcancel := context.WithTimeout(context.Background(), time.Second)
		c, _, err = websocket.Dial(dctx, "ws://"+addr+path, nil)
		dcancel()
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatalf("dial: %v\nlogs: %s", err, logs.String())
	}
	rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, data, err := c.Read(rctx)
	rcancel()
	var f pb.Frame
	if err != nil || proto.Unmarshal(data, &f) != nil || f.GetEvent().GetType() != "hello" {
		cancel()
		t.Fatalf("hello: %v %v", err, f.GetEvent())
	}
	c.CloseNow()
	return logs, func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("run did not stop")
		}
	}
}

// With [turn], run starts the embedded relay and publishes its counters; Close releases the ports on stop.
func TestRunWithTurn(t *testing.T) {
	cfg, manifest, _, addr, path := testNode(t)
	var out bytes.Buffer
	if err := run(context.Background(), []string{"import", "--config", cfg, manifest}, &out); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "turn.secret")
	turnAddr := freePort(t)
	appendConfig(t, cfg, turnSection(turnAddr, secret))
	if err := run(context.Background(), []string{"turn", "keygen", "--config", cfg}, &out); err != nil {
		t.Fatal(err)
	}
	raw, _ := turnsrv.ReadSecret(secret)
	logs, stop := runNode(t, cfg, addr, path)
	if !strings.Contains(logs.String(), `"msg":"turn on"`) {
		t.Fatalf("logs: %s", logs.String())
	}
	if _, ok := turnsrv.ReadSnapshot(filepath.Join(filepath.Dir(cfg), "data", "turn.stats.json"), time.Now(), time.Minute); !ok {
		t.Fatal("no stats snapshot")
	}
	stop()
	if strings.Contains(logs.String(), hex.EncodeToString(raw)) || strings.Contains(logs.String(), base64.StdEncoding.EncodeToString(raw)) {
		t.Fatal("secret logged")
	}
	// the relay's TCP port is free again after the node stopped
	ln, err := net.Listen("tcp4", turnAddr)
	if err != nil {
		t.Fatalf("turn port still bound: %v", err)
	}
	ln.Close()
}

// A relay that cannot start (no secret file) is logged and netlogged; the node keeps serving without calls.
func TestRunTurnStartFailure(t *testing.T) {
	cfg, manifest, _, addr, path := testNode(t)
	var out bytes.Buffer
	if err := run(context.Background(), []string{"import", "--config", cfg, manifest}, &out); err != nil {
		t.Fatal(err)
	}
	appendConfig(t, cfg, turnSection(freePort(t), filepath.Join(t.TempDir(), "missing.secret")))
	logs, stop := runNode(t, cfg, addr, path)
	stop()
	if !strings.Contains(logs.String(), "turn off: could not start") || strings.Contains(logs.String(), `"msg":"turn on"`) {
		t.Fatalf("logs: %s", logs.String())
	}
	st, err := store.Open(filepath.Join(filepath.Dir(cfg), "data", "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	es, err := st.Netlog(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range es {
		found = found || (e.Peer == "turn" && e.Class == "listen" && e.Result == "fail")
	}
	if !found {
		t.Fatalf("netlog: %+v", es)
	}
}
