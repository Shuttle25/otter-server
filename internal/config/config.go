// Package config loads otter-node's TOML configuration.
package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

type WSS struct {
	Listen  string `toml:"listen"`
	Path    string `toml:"path"`
	TLSCert string `toml:"tls_cert"`
	TLSKey  string `toml:"tls_key"`
	SiteDir string `toml:"site_dir"`
}

type Mesh struct {
	// AllowPlain lets this node dial peers' WS_PLAIN endpoints (development only).
	AllowPlain bool `toml:"allow_plain"`
}

// Limits for blobs (D44); sizes like "2GiB", "100MiB", "500KB".
type Limits struct {
	UserQuota string `toml:"user_quota"`
	MaxBlob   string `toml:"max_blob"`
}

// Replication tuning; blob_bandwidth like "2MB/s", "0" = unlimited.
type Replication struct {
	BlobBandwidth string `toml:"blob_bandwidth"`
}

// Push (D59): the Firebase service-account key; a missing file means push is off.
type Push struct {
	FCMCredentials string `toml:"fcm_credentials"`
}

// Reality (D72): VLESS+REALITY listener for peers; optional.
type Reality struct {
	Listen         string   `toml:"listen"`
	PrivateKeyFile string   `toml:"private_key_file"`
	Dest           string   `toml:"dest"`
	ServerNames    []string `toml:"server_names"`
	ShortIDs       []string `toml:"short_ids"`
	VlessUUID      string   `toml:"vless_uuid"`
}

// Turn is the embedded TURN relay for calls (D77). Missing section or enabled = false: no relay.
type Turn struct {
	Enabled               bool   `toml:"enabled"`
	UDPListen             string `toml:"udp_listen"`
	TCPListen             string `toml:"tcp_listen"`
	TLSListen             string `toml:"tls_listen"` // "" = no TURN over TLS; defaults to ":5349" when [wss] has TLS
	RelayIP               string `toml:"relay_ip"`   // public IP written into relay addresses (OTTER_IP)
	RelayPortMin          int    `toml:"relay_port_min"`
	RelayPortMax          int    `toml:"relay_port_max"`
	SecretFile            string `toml:"secret_file"`
	Realm                 string `toml:"realm"`
	MaxAllocationsPerUser int    `toml:"max_allocations_per_user"`
	MaxAllocations        int    `toml:"max_allocations"`
	RelayKbps             int    `toml:"relay_kbps"`          // per allocation, each direction
	AllowPrivatePeers     bool   `toml:"allow_private_peers"` // tests and dev mesh only
}

// DefaultTurnSecretFile is where `otter-node turn keygen` writes when [turn] names no secret_file.
const DefaultTurnSecretFile = "/etc/otter/turn.secret"

// MaxBlobLimit equals records.MaxBlobSize (kept here to avoid an import cycle).
const MaxBlobLimit = 100 << 20

type Config struct {
	DataDir      string      `toml:"data_dir"`
	NodeKey      string      `toml:"node_key"`
	NetworkPub   string      `toml:"network_pub"`
	ManifestFile string      `toml:"manifest_file"`
	LogLevel     string      `toml:"log_level"`
	WSS          WSS         `toml:"wss"`
	Mesh         Mesh        `toml:"mesh"`
	Limits       Limits      `toml:"limits"`
	Replication  Replication `toml:"replication"`
	Push         Push        `toml:"push"`
	Reality      Reality     `toml:"reality"`
	Turn         Turn        `toml:"turn"`

	// parsed by Load
	UserQuotaBytes  int64 `toml:"-"`
	MaxBlobBytes    int64 `toml:"-"`
	BlobBytesPerSec int64 `toml:"-"` // 0 = unlimited
}

func Load(path string) (*Config, error) {
	var c Config
	md, err := toml.DecodeFile(path, &c)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		return nil, fmt.Errorf("%s: unknown keys %v", path, und)
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	return &c, c.validate()
}

func (c *Config) validate() error {
	req := map[string]string{"data_dir": c.DataDir, "node_key": c.NodeKey, "network_pub": c.NetworkPub,
		"wss.listen": c.WSS.Listen, "wss.path": c.WSS.Path}
	for k, v := range req {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("config: %s is required", k)
		}
	}
	if _, err := c.NetworkPubKey(); err != nil {
		return err
	}
	if !strings.HasPrefix(c.WSS.Path, "/") || len(c.WSS.Path) < 8 {
		return fmt.Errorf("config: wss.path must start with / and be at least 8 characters")
	}
	if (c.WSS.TLSCert == "") != (c.WSS.TLSKey == "") {
		return fmt.Errorf("config: wss.tls_cert and wss.tls_key must be set together")
	}
	var err error
	if c.UserQuotaBytes, err = sizeOr(c.Limits.UserQuota, "2GiB"); err != nil {
		return fmt.Errorf("config: limits.user_quota: %w", err)
	}
	if c.MaxBlobBytes, err = sizeOr(c.Limits.MaxBlob, "100MiB"); err != nil {
		return fmt.Errorf("config: limits.max_blob: %w", err)
	}
	if c.MaxBlobBytes > MaxBlobLimit {
		return fmt.Errorf("config: limits.max_blob is above the protocol limit of 100MiB")
	}
	rate := c.Replication.BlobBandwidth
	if rate == "" {
		rate = "2MB/s"
	}
	if c.BlobBytesPerSec, err = ParseRate(rate); err != nil {
		return fmt.Errorf("config: replication.blob_bandwidth: %w", err)
	}
	if c.RealityEnabled() {
		r := c.Reality
		if r.Listen == "" || r.PrivateKeyFile == "" || r.Dest == "" || r.VlessUUID == "" || len(r.ServerNames) == 0 || len(r.ShortIDs) == 0 {
			return fmt.Errorf("config: [reality] needs listen, private_key_file, dest, server_names, short_ids, vless_uuid")
		}
		if _, _, err := net.SplitHostPort(r.Dest); err != nil {
			return fmt.Errorf("config: reality.dest must be host:port: %w", err)
		}
		if _, _, err := net.SplitHostPort(r.Listen); err != nil {
			return fmt.Errorf("config: reality.listen must be [host]:port: %w", err)
		}
	}
	if err := c.validateTurn(); err != nil {
		return err
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: log_level %q (debug|info|warn|error)", c.LogLevel)
	}
	return nil
}

// validateTurn fills [turn] defaults and checks it; only when enabled.
func (c *Config) validateTurn() error {
	t := &c.Turn
	if !t.Enabled {
		return nil
	}
	def := func(s *string, v string) {
		if *s == "" {
			*s = v
		}
	}
	defInt := func(p *int, v int) {
		if *p == 0 {
			*p = v
		}
	}
	def(&t.UDPListen, ":3478")
	def(&t.TCPListen, ":3478")
	def(&t.SecretFile, DefaultTurnSecretFile)
	def(&t.Realm, "otter")
	if t.TLSListen == "" && c.WSS.TLSCert != "" {
		t.TLSListen = ":5349"
	}
	defInt(&t.RelayPortMin, 49160)
	defInt(&t.RelayPortMax, 49200)
	defInt(&t.MaxAllocationsPerUser, 12) // up to 3 per phone per call (UDP, TCP, TLS); old ones linger until they time out
	defInt(&t.RelayKbps, 200)
	if ip := net.ParseIP(t.RelayIP); ip == nil {
		return fmt.Errorf("config: turn.relay_ip %q is not an IP address", t.RelayIP)
	} else if ip.To4() == nil {
		return fmt.Errorf("config: turn.relay_ip must be IPv4 (got %q)", t.RelayIP)
	}
	if t.RelayPortMin < 1024 || t.RelayPortMax > 65535 || t.RelayPortMin > t.RelayPortMax {
		return fmt.Errorf("config: turn relay ports %d-%d invalid (1024-65535, min <= max)", t.RelayPortMin, t.RelayPortMax)
	}
	span := t.RelayPortMax - t.RelayPortMin + 1
	defInt(&t.MaxAllocations, span)
	if t.MaxAllocations > span {
		return fmt.Errorf("config: turn.max_allocations %d > relay port range %d", t.MaxAllocations, span)
	}
	if t.MaxAllocationsPerUser < 0 || t.MaxAllocations < 0 || t.RelayKbps < 0 {
		return fmt.Errorf("config: turn limits must not be negative")
	}
	if t.TLSListen != "" && c.WSS.TLSCert == "" {
		return fmt.Errorf("config: turn.tls_listen needs [wss] tls_cert/tls_key")
	}
	return nil
}

// TurnEnabled reports whether the embedded TURN relay is on ([turn] enabled = true).
func (c *Config) TurnEnabled() bool { return c.Turn.Enabled }

// RealityEnabled reports whether a [reality] section is configured (any key set; validation then wants all).
func (c *Config) RealityEnabled() bool {
	r := c.Reality
	return r.Listen != "" || r.PrivateKeyFile != "" || r.Dest != "" || r.VlessUUID != "" || len(r.ServerNames) > 0 || len(r.ShortIDs) > 0
}

// PushEnabled reports whether a key file is configured and present.
func (c *Config) PushEnabled() bool {
	if c.Push.FCMCredentials == "" {
		return false
	}
	_, err := os.Stat(c.Push.FCMCredentials)
	return err == nil
}

func (c *Config) NetworkPubKey() (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(c.NetworkPub)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("config: network_pub must be %d hex-encoded bytes", ed25519.PublicKeySize)
	}
	return b, nil
}

func sizeOr(v, def string) (int64, error) {
	if strings.TrimSpace(v) == "" {
		v = def
	}
	return ParseSize(v)
}

var units = []struct {
	suffix string
	mul    float64
}{{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}, {"KB", 1e3}, {"MB", 1e6}, {"GB", 1e9}, {"B", 1}}

// ParseSize parses "10", "10B", "1.5MiB", "2GiB", "500KB" … into bytes (≥ 0).
func ParseSize(v string) (int64, error) {
	s := strings.TrimSpace(v)
	mul := 1.0
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			s, mul = strings.TrimSpace(strings.TrimSuffix(s, u.suffix)), u.mul
			break
		}
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q (e.g. 2GiB, 100MiB, 500KB)", v)
	}
	return int64(n * mul), nil
}

// ParseRate parses a size per second ("2MB/s"); "0" means unlimited.
func ParseRate(v string) (int64, error) {
	s := strings.TrimSpace(v)
	if s == "0" {
		return 0, nil
	}
	if !strings.HasSuffix(s, "/s") {
		return 0, fmt.Errorf("invalid rate %q (e.g. 2MB/s, or 0 for unlimited)", v)
	}
	return ParseSize(strings.TrimSuffix(s, "/s"))
}
