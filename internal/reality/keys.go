// Package reality embeds Xray-core's VLESS+REALITY for node-to-node links (D72).
//
// Only the Xray features we use are linked in (VLESS, REALITY over TCP, freedom, the dispatcher and proxyman);
// instances are built from protobuf configs directly, so Xray's JSON loader and its many protocols stay out of the
// binary.
package reality

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"strings"
)

var b64 = base64.RawURLEncoding

// GenerateKey returns a new X25519 key pair as base64 RawURL strings (the encoding Xray uses).
func GenerateKey() (priv, pub string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return b64.EncodeToString(k.Bytes()), b64.EncodeToString(k.PublicKey().Bytes()), nil
}

// PublicFromPrivate derives the public key (for `reality keygen` re-prints and checks).
func PublicFromPrivate(priv string) (string, error) {
	raw, err := b64.DecodeString(strings.TrimSpace(priv))
	if err != nil || len(raw) != 32 {
		return "", errors.New("reality: private key must be 32 bytes, base64 RawURL")
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(k.PublicKey().Bytes()), nil
}

// ReadKeyFile reads a private key written by WriteKeyFile.
func ReadKeyFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	priv := strings.TrimSpace(string(b))
	_, err = PublicFromPrivate(priv)
	return priv, err
}

// WriteKeyFile creates path (0640, must not exist) with the private key.
func WriteKeyFile(path, priv string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(priv + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
