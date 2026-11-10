package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

var ErrBadPassphrase = errors.New("wrong passphrase or corrupted key file")

var magic = []byte("OTTERKEY1")

func kek(pass, salt []byte) []byte { return argon2.IDKey(pass, salt, 3, 64*1024, 4, 32) }

// WriteEncryptedKey stores an Ed25519 private key encrypted with a passphrase:
// magic | salt(16) | nonce(24) | XChaCha20-Poly1305(seed, aad=magic).
func WriteEncryptedKey(path string, priv ed25519.PrivateKey, pass []byte) error {
	salt := make([]byte, 16)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	aead, err := chacha20poly1305.NewX(kek(pass, salt))
	if err != nil {
		return err
	}
	out := bytes.Join([][]byte{magic, salt, nonce, aead.Seal(nil, nonce, priv.Seed(), magic)}, nil)
	return os.WriteFile(path, out, 0o600)
}

func ReadEncryptedKey(path string, pass []byte) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < len(magic)+16+24+16 || !bytes.Equal(b[:len(magic)], magic) {
		return nil, fmt.Errorf("%s: not an otter key file", path)
	}
	b = b[len(magic):]
	salt, nonce, ct := b[:16], b[16:40], b[40:]
	aead, err := chacha20poly1305.NewX(kek(pass, salt))
	if err != nil {
		return nil, err
	}
	seed, err := aead.Open(nil, nonce, ct, magic)
	if err != nil {
		return nil, ErrBadPassphrase
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// WritePlainKey stores the hex seed (for node keys deployed to servers).
func WritePlainKey(path string, priv ed25519.PrivateKey) error {
	return os.WriteFile(path, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600)
}

func ReadPlainKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: invalid key file", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
