// Package keys holds identity helpers: ids, key derivation and key files.
package keys

import (
	"crypto/sha256"
	"fmt"
)

// ID16 returns the first 16 bytes of SHA-256(pub). Used for user_id, node_id, network_id.
func ID16(pub []byte) []byte {
	h := sha256.Sum256(pub)
	return append([]byte(nil), h[:16]...)
}

// RecordKey is the global dedup/storage key of a record: author || id.
func RecordKey(author, id []byte) ([]byte, error) {
	if len(author) != 16 || len(id) != 16 {
		return nil, fmt.Errorf("record key: author %d bytes, id %d bytes, want 16/16", len(author), len(id))
	}
	return append(append(make([]byte, 0, 32), author...), id...), nil
}
