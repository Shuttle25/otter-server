// Package config loads otter-node's TOML configuration.
package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
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

type Config struct {
	DataDir      string `toml:"data_dir"`
	NodeKey      string `toml:"node_key"`
	NetworkPub   string `toml:"network_pub"`
	ManifestFile string `toml:"manifest_file"`
	LogLevel     string `toml:"log_level"`
	WSS          WSS    `toml:"wss"`
	Mesh         Mesh   `toml:"mesh"`
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
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: log_level %q (debug|info|warn|error)", c.LogLevel)
	}
	return nil
}

func (c *Config) NetworkPubKey() (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(c.NetworkPub)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("config: network_pub must be %d hex-encoded bytes", ed25519.PublicKeySize)
	}
	return b, nil
}
