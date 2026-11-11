// Package nodecheck verifies a node's config, keys, manifest and TLS pair before it starts (install, upgrade).
package nodecheck

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/config"
	"ottermsg/server/internal/keys"
	"ottermsg/server/internal/pinning"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

// Run returns one "ok …" line per passed check, or the first failure. It never opens the database.
func Run(cfgPath string) ([]string, error) {
	var out []string
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return out, err
	}
	out = append(out, "ok config "+cfgPath)
	key, err := keys.ReadPlainKey(cfg.NodeKey)
	if err != nil {
		return out, fmt.Errorf("node_key: %w", err)
	}
	nodeID := keys.ID16(key.Public().(ed25519.PublicKey))
	out = append(out, fmt.Sprintf("ok node key, node_id %x", nodeID))
	netPub, err := cfg.NetworkPubKey()
	if err != nil {
		return out, fmt.Errorf("network_pub: %w", err)
	}
	raw, err := os.ReadFile(cfg.ManifestFile)
	if err != nil {
		return out, fmt.Errorf("manifest_file: %w", err)
	}
	var rec pb.Record
	if err := proto.Unmarshal(raw, &rec); err != nil {
		return out, fmt.Errorf("manifest_file: %w", err)
	}
	v := &records.Validator{NetworkPub: netPub, Users: noUsers{}, Now: time.Now}
	body, err := v.Validate(&rec)
	if err != nil || body.Type != pb.RecordType_MANIFEST {
		return out, fmt.Errorf("manifest_file does not verify against network_pub: %v", err)
	}
	var m pb.Manifest
	if err := proto.Unmarshal(body.Payload, &m); err != nil {
		return out, fmt.Errorf("manifest_file: %w", err)
	}
	var me *pb.NodeInfo
	for _, n := range m.Nodes {
		if bytes.Equal(n.NodeId, nodeID) {
			me = n
		}
	}
	if me == nil {
		return out, fmt.Errorf("node %x is not in manifest version %d", nodeID, m.Version)
	}
	out = append(out, fmt.Sprintf("ok manifest version %d lists node %s", m.Version, me.Label))
	var ep *pb.Endpoint
	for _, e := range me.Endpoints {
		if e.Path == cfg.WSS.Path {
			ep = e
		}
	}
	if ep == nil {
		return out, errors.New("no manifest endpoint uses wss.path from the config")
	}
	out = append(out, fmt.Sprintf("ok endpoint %s:%d%s", ep.Host, ep.Port, ep.Path))
	if cfg.WSS.TLSCert == "" {
		return append(out, "ok plain endpoint (development)"), nil
	}
	pair, err := tls.LoadX509KeyPair(cfg.WSS.TLSCert, cfg.WSS.TLSKey)
	if err != nil {
		return out, fmt.Errorf("tls pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return out, fmt.Errorf("tls_cert: %w", err)
	}
	pin := pinning.SPKIPin(leaf)
	for _, p := range ep.TlsSpkiPins {
		if bytes.Equal(p, pin) {
			return append(out, "ok tls certificate matches pin "+base64.StdEncoding.EncodeToString(pin)), nil
		}
	}
	return out, fmt.Errorf("tls certificate pin %s is not in the manifest", base64.StdEncoding.EncodeToString(pin))
}

type noUsers struct{}

func (noUsers) UserKey([]byte) (records.UserKey, bool) { return records.UserKey{}, false }
