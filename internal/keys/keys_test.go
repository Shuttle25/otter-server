package keys

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestID16(t *testing.T) {
	pub := bytes.Repeat([]byte{1}, 32)
	id := ID16(pub)
	if len(id) != 16 {
		t.Fatalf("len %d", len(id))
	}
	if !bytes.Equal(id, ID16(pub)) {
		t.Fatal("not deterministic")
	}
}

func TestRecordKey(t *testing.T) {
	k, err := RecordKey(make([]byte, 16), bytes.Repeat([]byte{2}, 16))
	if err != nil || len(k) != 32 || k[16] != 2 {
		t.Fatalf("bad key %x %v", k, err)
	}
	if _, err := RecordKey(make([]byte, 15), make([]byte, 16)); err == nil {
		t.Fatal("want error")
	}
}

func TestDeriveAccountKey(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	a, err := DeriveAccountKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := DeriveAccountKey(seed)
	if !bytes.Equal(a, b) {
		t.Fatal("not deterministic")
	}
	if len(a) != ed25519.PrivateKeySize {
		t.Fatal("size")
	}
	if _, err := DeriveAccountKey(seed[:31]); err == nil {
		t.Fatal("want error")
	}
}

func TestEncryptedKeyFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "network.key.enc")
	_, priv, _ := ed25519.GenerateKey(nil)
	if err := WriteEncryptedKey(p, priv, []byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	got, err := ReadEncryptedKey(p, []byte("correct horse"))
	if err != nil || !bytes.Equal(got, priv) {
		t.Fatalf("roundtrip: %v", err)
	}
	if _, err := ReadEncryptedKey(p, []byte("wrong")); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("want ErrBadPassphrase, got %v", err)
	}
}

func TestPlainKeyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "node.key")
	_, priv, _ := ed25519.GenerateKey(nil)
	if err := WritePlainKey(p, priv); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPlainKey(p)
	if err != nil || !bytes.Equal(got, priv) {
		t.Fatalf("roundtrip: %v", err)
	}
}

func TestAuthMessage(t *testing.T) {
	m := AuthMessage(bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 32), 0x0102030405060708)
	want := append([]byte("otter-auth-v1"), bytes.Repeat([]byte{1}, 16)...)
	want = append(want, bytes.Repeat([]byte{2}, 32)...)
	want = append(want, 1, 2, 3, 4, 5, 6, 7, 8)
	if !bytes.Equal(m, want) {
		t.Fatalf("got %x", m)
	}
}
