package admin

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

func readVersion(dir string) uint64 {
	b, err := os.ReadFile(filepath.Join(dir, "manifest_version"))
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v
}

// SignManifest builds a manifest from nodes.json with version+1, signs it with the network
// key and writes manifest.bin (a serialized pb.Record).
func SignManifest(dir string, pass []byte, now time.Time) (*pb.Record, error) {
	st, err := LoadState(dir)
	if err != nil {
		return nil, err
	}
	priv, err := keys.ReadEncryptedKey(filepath.Join(dir, "network.key.enc"), pass)
	if err != nil {
		return nil, err
	}
	version := readVersion(dir) + 1
	m := &pb.Manifest{Version: version, IssuedMs: now.UnixMilli(), NetworkPub: st.NetworkPub, Nodes: st.Nodes}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 16)
	rand.Read(id)
	rec, err := records.Sign(&pb.RecordBody{Id: id, Type: pb.RecordType_MANIFEST, Author: keys.ID16(st.NetworkPub),
		CreatedMs: now.UnixMilli(), Payload: payload}, priv)
	if err != nil {
		return nil, err
	}
	raw, _ := proto.Marshal(rec)
	if err := os.WriteFile(filepath.Join(dir, "manifest.bin"), raw, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest_version"), []byte(fmt.Sprintf("%d\n", version)), 0o644); err != nil {
		return nil, err
	}
	return rec, nil
}
