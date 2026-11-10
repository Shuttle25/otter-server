package keys

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

const InfoAccount = "otter/account/v1"

// DeriveAccountKey derives the user's Ed25519 account key from the 32-byte recovery seed.
// Must match the Android implementation (see testdata/vectors/v1.json).
func DeriveAccountKey(seed []byte) (ed25519.PrivateKey, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("seed must be 32 bytes, got %d", len(seed))
	}
	k, err := hkdf.Key(sha256.New, seed, nil, InfoAccount, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(k), nil
}
