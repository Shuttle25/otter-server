package admin

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"time"

	"ottermsg/server/internal/pinning"
)

// CertValidity of node certificates; rotation adds a second pin to the manifest first (docs/11 D27).
const CertValidity = 10 * 365 * 24 * time.Hour

type nodeMeta struct {
	IPs []string `json:"ips"`
}

// writeNodeTLS generates tls.crt/tls.key in nodeDir for host+ips and returns the pin.
func writeNodeTLS(nodeDir, host string, ips []net.IP) ([]byte, error) {
	var hosts []string
	if ip := net.ParseIP(host); ip == nil {
		hosts = []string{host}
	} else {
		ips = append(ips, ip)
	}
	certPEM, keyPEM, pin, err := pinning.GenerateCert(hosts, ips, CertValidity)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(nodeDir, "tls.crt"), certPEM, 0o644); err != nil {
		return nil, err
	}
	return pin, os.WriteFile(filepath.Join(nodeDir, "tls.key"), keyPEM, 0o600)
}

func writeNodeMeta(nodeDir string, ips []string) error {
	if ips == nil {
		ips = []string{}
	}
	b, _ := json.MarshalIndent(nodeMeta{IPs: ips}, "", "  ")
	return os.WriteFile(filepath.Join(nodeDir, "meta.json"), b, 0o644)
}
