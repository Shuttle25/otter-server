package blobs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDir(t *testing.T) {
	root := filepath.Join(t.TempDir(), "blobs")
	d, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	k1, k2 := bytes.Repeat([]byte{0xab}, 32), bytes.Repeat([]byte{0x01}, 32)
	if err := d.Write(k1, 0, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := d.Write(k1, 7, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := d.Write(k2, 0, []byte("y")); err != nil {
		t.Fatal(err)
	}
	if got, err := d.Read(k1, 0); err != nil || string(got) != "hello" {
		t.Fatalf("read %q %v", got, err)
	}
	if _, err := d.Read(k1, 1); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing chunk: %v", err)
	}
	// stray temp files and junk names are never listed as keys
	os.WriteFile(filepath.Join(root, "ab", ".tmp-x"), nil, 0o600)
	os.MkdirAll(filepath.Join(root, "zz", "nothex"), 0o700)
	keys, err := d.Keys()
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys %d %v", len(keys), err)
	}
	if err := d.Remove(k1); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Read(k1, 0); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("not removed")
	}
	if keys, _ := d.Keys(); len(keys) != 1 || !bytes.Equal(keys[0], k2) {
		t.Fatalf("keys after remove %x", keys)
	}
}
