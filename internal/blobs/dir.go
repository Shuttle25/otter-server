// Package blobs keeps blob chunk files on disk: <root>/<hex(key)[0:2]>/<hex(key)>/<index> (D45).
package blobs

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

type Dir struct{ root string }

func New(root string) (*Dir, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	return &Dir{root: root}, nil
}

// KeyLen is the only valid blob key length: 16-byte owner ‖ 16 random bytes (D45).
const KeyLen = 32

// ErrBadKey: a key that is not KeyLen bytes; it never names a file (C11).
var ErrBadKey = errors.New("blobs: key must be 32 bytes")

func (d *Dir) blobDir(key []byte) (string, error) {
	if len(key) != KeyLen {
		return "", fmt.Errorf("%w (got %d)", ErrBadKey, len(key))
	}
	h := hex.EncodeToString(key)
	return filepath.Join(d.root, h[:2], h), nil
}

// Write stores a chunk atomically (temp file, fsync, rename).
func (d *Dir) Write(key []byte, idx uint32, data []byte) error {
	dir, err := d.blobDir(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, strconv.FormatUint(uint64(idx), 10)))
}

// Read returns a chunk; os.ErrNotExist when missing, ErrBadKey for a malformed key.
func (d *Dir) Read(key []byte, idx uint32) ([]byte, error) {
	dir, err := d.blobDir(key)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(dir, strconv.FormatUint(uint64(idx), 10)))
}

// Remove deletes every chunk of a blob.
func (d *Dir) Remove(key []byte) error {
	dir, err := d.blobDir(key)
	if err != nil {
		return err
	}
	err = os.RemoveAll(dir)
	os.Remove(filepath.Dir(dir)) // prefix dir, only if empty
	return err
}

// Keys lists the blobs that have a directory.
func (d *Dir) Keys() ([][]byte, error) {
	var out [][]byte
	prefixes, err := os.ReadDir(d.root)
	if err != nil {
		return nil, err
	}
	for _, p := range prefixes {
		if !p.IsDir() || len(p.Name()) != 2 {
			continue
		}
		entries, err := os.ReadDir(filepath.Join(d.root, p.Name()))
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			k, err := hex.DecodeString(e.Name())
			if !e.IsDir() || err != nil || len(k) != KeyLen {
				continue
			}
			out = append(out, k)
		}
	}
	return out, nil
}
