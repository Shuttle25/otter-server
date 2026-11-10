// Package admin implements the network admin's local state and operations.
package admin

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"google.golang.org/protobuf/encoding/protojson"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

var (
	ErrExists   = errors.New("already exists")
	ErrNotFound = errors.New("not found")
	labelRe     = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
)

type State struct {
	Dir        string
	NetworkPub ed25519.PublicKey
	VlessUUID  string
	Nodes      []*pb.NodeInfo
}

type networkJSON struct {
	NetworkPub string `json:"network_pub"`
	VlessUUID  string `json:"vless_uuid"`
}

type nodesJSON struct {
	Nodes []json.RawMessage `json:"nodes"`
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func randPath() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return "/" + string(b)
}

func InitNetwork(dir string, pass []byte) error {
	if _, err := os.Stat(filepath.Join(dir, "network.json")); err == nil {
		return fmt.Errorf("network in %s: %w", dir, ErrExists)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	if err := keys.WriteEncryptedKey(filepath.Join(dir, "network.key.enc"), priv, pass); err != nil {
		return err
	}
	nj, _ := json.MarshalIndent(networkJSON{NetworkPub: hex.EncodeToString(pub), VlessUUID: newUUID()}, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "network.json"), nj, 0o644); err != nil {
		return err
	}
	return saveNodes(dir, nil)
}

func LoadState(dir string) (*State, error) {
	b, err := os.ReadFile(filepath.Join(dir, "network.json"))
	if err != nil {
		return nil, fmt.Errorf("no network in %s (run 'network init'): %w", dir, err)
	}
	var nj networkJSON
	if err := json.Unmarshal(b, &nj); err != nil {
		return nil, err
	}
	pub, err := hex.DecodeString(nj.NetworkPub)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("network.json: bad network_pub")
	}
	st := &State{Dir: dir, NetworkPub: pub, VlessUUID: nj.VlessUUID}
	nb, err := os.ReadFile(filepath.Join(dir, "nodes.json"))
	if err != nil {
		return nil, err
	}
	var nodes nodesJSON
	if err := json.Unmarshal(nb, &nodes); err != nil {
		return nil, err
	}
	for _, raw := range nodes.Nodes {
		n := &pb.NodeInfo{}
		if err := protojson.Unmarshal(raw, n); err != nil {
			return nil, err
		}
		st.Nodes = append(st.Nodes, n)
	}
	return st, nil
}

func saveNodes(dir string, nodes []*pb.NodeInfo) error {
	out := nodesJSON{Nodes: []json.RawMessage{}}
	for _, n := range nodes {
		b, err := protojson.Marshal(n)
		if err != nil {
			return err
		}
		out.Nodes = append(out.Nodes, b)
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return os.WriteFile(filepath.Join(dir, "nodes.json"), b, 0o644)
}

type NodeSpec struct {
	Label   string
	WSSHost string
	WSSPort uint32
	WSSPath string
	CDN     bool
	Push    bool
}

func AddNode(dir string, s NodeSpec) (*pb.NodeInfo, error) {
	if !labelRe.MatchString(s.Label) {
		return nil, fmt.Errorf("label %q: must match %s", s.Label, labelRe)
	}
	if s.WSSHost == "" {
		return nil, errors.New("wss host required")
	}
	st, err := LoadState(dir)
	if err != nil {
		return nil, err
	}
	for _, n := range st.Nodes {
		if n.Label == s.Label {
			return nil, fmt.Errorf("node %s: %w", s.Label, ErrExists)
		}
	}
	if s.WSSPort == 0 {
		s.WSSPort = 443
	}
	if s.WSSPath == "" {
		s.WSSPath = randPath()
	}
	nodeDir := filepath.Join(dir, "nodes", s.Label)
	if err := os.MkdirAll(nodeDir, 0o700); err != nil {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	if err := keys.WritePlainKey(filepath.Join(nodeDir, "node.key"), priv); err != nil {
		return nil, err
	}
	n := &pb.NodeInfo{NodeId: keys.ID16(pub), NodePub: pub, Label: s.Label, PushCapable: s.Push,
		Endpoints: []*pb.Endpoint{{Kind: pb.Endpoint_WSS, Host: s.WSSHost, Port: s.WSSPort, Path: s.WSSPath, ViaCdn: s.CDN}}}
	return n, saveNodes(dir, append(st.Nodes, n))
}

func RemoveNode(dir, label string) error {
	st, err := LoadState(dir)
	if err != nil {
		return err
	}
	kept := st.Nodes[:0]
	found := false
	for _, n := range st.Nodes {
		if n.Label == label {
			found = true
			continue
		}
		kept = append(kept, n)
	}
	if !found {
		return fmt.Errorf("node %s: %w", label, ErrNotFound)
	}
	return saveNodes(dir, kept)
}
