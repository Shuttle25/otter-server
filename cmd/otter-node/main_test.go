package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/admin"
	pb "ottermsg/server/internal/proto/otterv1"
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

func TestImportAndRun(t *testing.T) {
	dir := t.TempDir()
	adm := filepath.Join(dir, "admin")
	if err := admin.InitNetwork(adm, pass); err != nil {
		t.Fatal(err)
	}
	n, err := admin.AddNode(adm, admin.NodeSpec{Label: "n1", WSSHost: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.SignManifest(adm, pass, time.Now()); err != nil {
		t.Fatal(err)
	}
	st, _ := admin.LoadState(adm)
	addr := freePort(t)
	path := n.Endpoints[0].Path
	cfg := filepath.Join(dir, "node.toml")
	os.WriteFile(cfg, []byte(fmt.Sprintf(`data_dir = %q
node_key = %q
network_pub = %q
[wss]
listen = %q
path = %q
`, filepath.Join(dir, "data"), filepath.Join(adm, "nodes", "n1", "node.key"), hex.EncodeToString(st.NetworkPub), addr, path)), 0o600)

	var out bytes.Buffer
	manifest := filepath.Join(adm, "manifest.bin")
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
