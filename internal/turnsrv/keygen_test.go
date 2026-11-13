package turnsrv

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteSecret(t *testing.T) {
	p := filepath.Join(t.TempDir(), "turn.secret")
	if err := WriteSecret(p, false); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("mode: %v %v", st.Mode(), err)
	}
	first, err := ReadSecret(p)
	if err != nil || len(first) != SecretLen {
		t.Fatalf("read: %v %d", err, len(first))
	}
	if err := WriteSecret(p, false); err == nil {
		t.Fatal("second write without force accepted")
	}
	if again, _ := ReadSecret(p); !bytes.Equal(again, first) {
		t.Fatal("refused write changed the secret")
	}
	if err := WriteSecret(p, true); err != nil {
		t.Fatal(err)
	}
	if again, _ := ReadSecret(p); bytes.Equal(again, first) {
		t.Fatal("force did not replace the secret")
	}
	short := filepath.Join(t.TempDir(), "short")
	os.WriteFile(short, make([]byte, 31), 0o640)
	if _, err := ReadSecret(short); err == nil {
		t.Fatal("31-byte secret accepted")
	}
}
