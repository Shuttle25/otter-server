// Package turnsrv embeds the TURN relay for calls (D77).
package turnsrv

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
)

// SecretLen is the length of the per-node TURN-REST shared secret.
const SecretLen = 32

// WriteSecret creates the per-node TURN secret (0640). It never overwrites unless force is set.
func WriteSecret(path string, force bool) error {
	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("%s exists (use --force to replace; active credentials stop working)", path)
	}
	b := make([]byte, SecretLen)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o640); err != nil { // WriteFile's mode is subject to the umask
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// ReadSecret loads the secret and checks its length.
func ReadSecret(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) != SecretLen {
		return nil, errors.New("turn secret must be 32 bytes")
	}
	return b, nil
}
