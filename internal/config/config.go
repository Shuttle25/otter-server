// Package config loads otter-node's TOML configuration.
package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
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
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: log_level %q (debug|info|warn|error)", c.LogLevel)
	}
	return nil
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
