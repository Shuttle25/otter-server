// Package netcode derives the network code a new member compares with the person who invited them (M9.5, D139).
package netcode

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Code returns "ddddd ddddd ddddd": the first 8 bytes of SHA-256("otter-network-code" ‖ networkPub), big-endian,
// mod 10^15, zero-padded. Digits read the same in every language and over the phone.
func Code(networkPub []byte) string {
	h := sha256.Sum256(append([]byte("otter-network-code"), networkPub...))
	s := fmt.Sprintf("%015d", binary.BigEndian.Uint64(h[:8])%1_000_000_000_000_000)
	return s[:5] + " " + s[5:10] + " " + s[10:]
}
