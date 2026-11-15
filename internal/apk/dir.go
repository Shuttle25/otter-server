// Package apk stores app update files on a node and serves them in chunks (D68).
package apk

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

const (
	ChunkSize = 1 << 20 // apk.get chunk size
	Keep      = 2       // newest files kept
)

// Dir holds APK files named <sha256 hex>.apk.
type Dir struct{ path string }

func New(path string) (*Dir, error) {
	if err := os.MkdirAll(path, 0o750); err != nil {
		return nil, err
	}
	return &Dir{path: path}, nil
}

func hexName(sum []byte) string { return hex.EncodeToString(sum) + ".apk" }

var (
	ErrNotRegular = errors.New("apk: not a regular file")
	ErrEmpty      = errors.New("apk: empty file")
)

// Import copies the regular file src into the directory under its SHA-256 and prunes old files. Returns the sum.
// src is opened without following a symlink and must be a regular file (O_NONBLOCK: a FIFO cannot stall it).
// Runs as the node user only: `otter-node apk import` refuses root (C3, D82).
func (d *Dir) Import(src string) ([]byte, error) {
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", src, ErrNotRegular)
	}
	return d.ImportReader(in)
}

// ImportReader stores everything read from r (deploy streams the APK on stdin) and prunes old files.
func (d *Dir) ImportReader(r io.Reader) ([]byte, error) {
	tmp, err := os.CreateTemp(d.path, ".import-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), r)
	if err != nil {
		tmp.Close()
		return nil, err
	}
	if n == 0 {
		tmp.Close()
		return nil, ErrEmpty
	}
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	sum := h.Sum(nil)
	// rename replaces whatever holds the final name (a planted symlink included) and never writes through it
	if err := os.Rename(tmp.Name(), filepath.Join(d.path, hexName(sum))); err != nil {
		return nil, err
	}
	d.prune()
	return sum, nil
}

// prune keeps the Keep newest APK files (by modification time).
func (d *Dir) prune() {
	files, _ := filepath.Glob(filepath.Join(d.path, "*.apk"))
	if len(files) <= Keep {
		return
	}
	type f struct {
		p string
		t int64
	}
	var all []f
	for _, p := range files {
		if st, err := os.Stat(p); err == nil {
			all = append(all, f{p, st.ModTime().UnixNano()})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t > all[j].t })
	for _, x := range all[min(Keep, len(all)):] {
		os.Remove(x.p)
	}
}

// Chunk returns chunk index of the file with this SHA-256 and the file size.
// A missing file or an index past the end returns an error wrapping os.ErrNotExist.
func (d *Dir) Chunk(sum []byte, index uint32) ([]byte, uint64, error) {
	if len(sum) != sha256.Size {
		return nil, 0, fmt.Errorf("bad sum: %w", os.ErrNotExist)
	}
	f, err := os.Open(filepath.Join(d.path, hexName(sum)))
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	off := int64(index) * ChunkSize
	if off >= st.Size() {
		return nil, 0, fmt.Errorf("chunk %d: %w", index, os.ErrNotExist)
	}
	buf := make([]byte, min(ChunkSize, st.Size()-off))
	if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
		return nil, 0, err
	}
	return buf, uint64(st.Size()), nil
}
