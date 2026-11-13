package admin

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ottermsg/server/internal/pinning"
	pb "ottermsg/server/internal/proto/otterv1"
)

func findNode(st *State, label string) (*pb.NodeInfo, error) {
	for _, n := range st.Nodes {
		if n.Label == label {
			return n, nil
		}
	}
	return nil, fmt.Errorf("node %s: %w", label, ErrNotFound)
}

func nodeDir(dir, label string) string { return filepath.Join(dir, "nodes", label) }

// NodeIPs returns the IPs recorded for label (meta.json).
func NodeIPs(dir, label string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(nodeDir(dir, label), "meta.json"))
	if err != nil {
		return nil, err
	}
	var m nodeMeta
	return m.IPs, json.Unmarshal(b, &m)
}

func parseIPs(ips []string) ([]net.IP, error) {
	var out []net.IP
	for _, a := range ips {
		ip := net.ParseIP(a)
		if ip == nil {
			return nil, fmt.Errorf("invalid ip %q", a)
		}
		out = append(out, ip)
	}
	return out, nil
}

// certNames splits an endpoint host into DNS names / IPs for a certificate (an IP host is added to the IPs once).
func certNames(host string, ips []net.IP) ([]string, []net.IP) {
	ip := net.ParseIP(host)
	if ip == nil {
		return []string{host}, ips
	}
	all := append([]net.IP{}, ips...)
	for _, x := range ips {
		if x.Equal(ip) {
			return nil, all
		}
	}
	return nil, append(all, ip)
}

// reissue rewrites <name>.crt for the node's host and ips with the key in <name>.key (pin unchanged).
func reissue(nd, name, host string, ips []net.IP) error {
	kb, err := os.ReadFile(filepath.Join(nd, name+".key"))
	if err != nil {
		return err
	}
	key, err := pinning.ReadKeyPEM(kb)
	if err != nil {
		return err
	}
	hosts, all := certNames(host, ips)
	certPEM, _, err := pinning.IssueCert(key, hosts, all, CertValidity)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(nd, name+".crt"), certPEM, 0o644)
}

// SetIPs records the node's public IPs and re-issues its certificate(s) with the same key, so the pin is unchanged
// (D42). The manifest does not change; DNS does.
func SetIPs(dir, label string, ips []string) error {
	st, err := LoadState(dir)
	if err != nil {
		return err
	}
	n, err := findNode(st, label)
	if err != nil {
		return err
	}
	parsed, err := parseIPs(ips)
	if err != nil {
		return err
	}
	nd := nodeDir(dir, label)
	if err := writeNodeMeta(nd, ips); err != nil {
		return err
	}
	ep := n.Endpoints[0]
	if ep.Kind != pb.Endpoint_WSS {
		return nil
	}
	if err := reissue(nd, "tls", ep.Host, parsed); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(nd, "tls.new.key")); err == nil {
		return reissue(nd, "tls.new", ep.Host, parsed)
	}
	return nil
}

// RotateTLS stages a new key pair as tls.new.{crt,key} and adds its pin next to the old one (D42).
func RotateTLS(dir, label string) ([]byte, error) {
	st, err := LoadState(dir)
	if err != nil {
		return nil, err
	}
	n, err := findNode(st, label)
	if err != nil {
		return nil, err
	}
	nd := nodeDir(dir, label)
	if _, err := os.Stat(filepath.Join(nd, "tls.new.key")); err == nil {
		return nil, fmt.Errorf("node %s already has a staged certificate (run 'node drop-old-pins' after deploying it)", label)
	}
	ep := n.Endpoints[0]
	if ep.Kind != pb.Endpoint_WSS {
		return nil, errors.New("plain endpoints have no TLS")
	}
	ipStr, err := NodeIPs(dir, label)
	if err != nil {
		return nil, err
	}
	ips, err := parseIPs(ipStr)
	if err != nil {
		return nil, err
	}
	hosts, all := certNames(ep.Host, ips)
	certPEM, keyPEM, pin, err := pinning.GenerateCert(hosts, all, CertValidity)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(nd, "tls.new.key"), keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(nd, "tls.new.crt"), certPEM, 0o644); err != nil {
		return nil, err
	}
	ep.TlsSpkiPins = append(ep.TlsSpkiPins, pin)
	return pin, saveNodes(dir, st.Nodes)
}

// DropOldPins promotes the staged pair (old pair kept as tls.old.*) and leaves only its pin (D42).
func DropOldPins(dir, label string) error {
	st, err := LoadState(dir)
	if err != nil {
		return err
	}
	n, err := findNode(st, label)
	if err != nil {
		return err
	}
	nd := nodeDir(dir, label)
	newCrt, err := os.ReadFile(filepath.Join(nd, "tls.new.crt"))
	if err != nil {
		return fmt.Errorf("node %s has no staged certificate (run 'node rotate-tls' first)", label)
	}
	pin, err := pinning.CertPin(newCrt)
	if err != nil {
		return err
	}
	for _, ext := range []string{"crt", "key"} {
		if err := os.Rename(filepath.Join(nd, "tls."+ext), filepath.Join(nd, "tls.old."+ext)); err != nil {
			return err
		}
		if err := os.Rename(filepath.Join(nd, "tls.new."+ext), filepath.Join(nd, "tls."+ext)); err != nil {
			return err
		}
	}
	n.Endpoints[0].TlsSpkiPins = [][]byte{pin}
	return saveNodes(dir, st.Nodes)
}

// NodeEnv returns the facts deploy scripts need about one node (TLS = the staged pair when present).
func NodeEnv(dir, label string) (map[string]string, error) {
	st, err := LoadState(dir)
	if err != nil {
		return nil, err
	}
	n, err := findNode(st, label)
	if err != nil {
		return nil, err
	}
	ep := n.Endpoints[0]
	nd := nodeDir(dir, label)
	env := map[string]string{
		"OTTER_LABEL": label, "OTTER_HOST": ep.Host, "OTTER_PORT": strconv.Itoa(int(ep.Port)), "OTTER_PATH": ep.Path,
		"OTTER_NETWORK_PUB": hex.EncodeToString(st.NetworkPub), "OTTER_NODE_ID": hex.EncodeToString(n.NodeId),
		"OTTER_NODE_DIR": nd, "OTTER_KIND": "wss", "OTTER_TLS_CERT": "", "OTTER_TLS_KEY": "", "OTTER_PIN": "",
	}
	if ep.Kind != pb.Endpoint_WSS {
		env["OTTER_KIND"] = "plain"
		return env, nil
	}
	name := "tls"
	if _, err := os.Stat(filepath.Join(nd, "tls.new.crt")); err == nil {
		name = "tls.new"
	}
	crt, err := os.ReadFile(filepath.Join(nd, name+".crt"))
	if err != nil {
		return nil, err
	}
	pin, err := pinning.CertPin(crt)
	if err != nil {
		return nil, err
	}
	env["OTTER_TLS_CERT"] = filepath.Join(nd, name+".crt")
	env["OTTER_TLS_KEY"] = filepath.Join(nd, name+".key")
	env["OTTER_PIN"] = base64.StdEncoding.EncodeToString(pin)
	return env, nil
}

// ShellQuote quotes s for a POSIX shell.
func ShellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// SetPush marks a node push-capable (it has /etc/otter/fcm.json) or not (D58).
func SetPush(dir, label string, on bool) error {
	st, err := LoadState(dir)
	if err != nil {
		return err
	}
	n, err := findNode(st, label)
	if err != nil {
		return err
	}
	n.PushCapable = on
	return saveNodes(dir, st.Nodes)
}

// SetDialOutOnly marks a node inside a censored network: it dials its peers and is never dialed (D71).
func SetDialOutOnly(dir, label string, on bool) error {
	st, err := LoadState(dir)
	if err != nil {
		return err
	}
	n, err := findNode(st, label)
	if err != nil {
		return err
	}
	n.DialOutOnly = on
	return saveNodes(dir, st.Nodes)
}

type RealitySpec struct {
	Label, Host, Pub, ServerName, ShortID string
	UUID                                  string // the node's [reality].vless_uuid; generated when empty
	Port                                  uint32
}

// AddReality adds (or replaces) the node's VLESS+REALITY endpoint (D72). Pub is the node's X25519 public key in
// base64 RawURL encoding, printed by `otter-node reality keygen`. The WSS endpoint stays first.
func AddReality(dir string, s RealitySpec) (*pb.Endpoint, error) {
	st, err := LoadState(dir)
	if err != nil {
		return nil, err
	}
	n, err := findNode(st, s.Label)
	if err != nil {
		return nil, err
	}
	pub, err := base64.RawURLEncoding.DecodeString(s.Pub)
	if err != nil || len(pub) != 32 {
		return nil, errors.New("--pub must be the 32-byte X25519 public key in base64 RawURL encoding (otter-node reality keygen)")
	}
	if s.Host == "" || s.ServerName == "" || s.Port == 0 || s.Port > 65535 {
		return nil, errors.New("--host, --port and --server-name are required")
	}
	sid := s.ShortID
	if sid == "" {
		b := make([]byte, 4)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		sid = hex.EncodeToString(b)
	}
	if _, err := hex.DecodeString(sid); err != nil || len(sid) > 16 || len(sid)%2 != 0 {
		return nil, errors.New("--short-id must be 2-16 hex characters, even length")
	}
	path := ""
	keep := n.Endpoints[:0]
	uuid := newUUID()
	for _, e := range n.Endpoints {
		if e.Kind == pb.Endpoint_WSS && path == "" {
			path = e.Path
		}
		if e.Kind == pb.Endpoint_REALITY {
			uuid = e.VlessUuid // keep the UUID across replacements: nodes' configs already use it
			continue
		}
		keep = append(keep, e)
	}
	if path == "" {
		return nil, fmt.Errorf("node %s has no WSS endpoint to take the secret path from", s.Label)
	}
	ep := &pb.Endpoint{Kind: pb.Endpoint_REALITY, Host: s.Host, Port: s.Port, Path: path, VlessUuid: uuid,
		RealityPub: pub, ShortIds: []string{sid}, ServerNames: []string{s.ServerName}, Fingerprint: "chrome"}
	if s.UUID != "" {
		ep.VlessUuid = s.UUID // reality-setup.sh passes the UUID it wrote into the node's config
	}
	n.Endpoints = append(keep, ep)
	return ep, saveNodes(dir, st.Nodes)
}
