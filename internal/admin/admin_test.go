package admin

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
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
