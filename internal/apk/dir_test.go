package apk

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func writeTemp(t *testing.T, n int) (string, []byte) {
	t.Helper()
	b := make([]byte, n)
	rand.Read(b)
	p := filepath.Join(t.TempDir(), "x.apk")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p, b
}

func TestImportAndChunks(t *testing.T) {
	d, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	src, data := writeTemp(t, ChunkSize*2+10)
	sum, err := d.Import(src)
	want := sha256.Sum256(data)
	if err != nil || !bytes.Equal(sum, want[:]) {
		t.Fatalf("import: %x %v", sum, err)
	}
	if _, err := d.Import(src); err != nil {
		t.Fatal("re-import:", err)
	}
	st, err := os.Stat(filepath.Join(d.path, hexName(sum)))
	if err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("stored file: %v %v", st, err)
	}
	if left, _ := filepath.Glob(filepath.Join(d.path, ".import-*")); len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
	var got []byte
	chunks := 0
	for i := uint32(0); ; i++ {
		c, total, err := d.Chunk(sum, i)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil || total != uint64(len(data)) {
			t.Fatal(err, total)
		}
		got = append(got, c...)
		chunks++
	}
	if !bytes.Equal(got, data) || chunks != 3 {
		t.Fatalf("chunks differ (%d chunks)", chunks)
	}
	if _, _, err := d.Chunk(make([]byte, 32), 0); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing file:", err)
	}
	if _, _, err := d.Chunk([]byte("short"), 0); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("bad sum:", err)
	}
}

func TestKeepsNewestTwo(t *testing.T) {
	d, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-time.Hour)
	var sums [][]byte
	for i := 0; i < 3; i++ {
		src, _ := writeTemp(t, 100)
		s, err := d.Import(src)
		if err != nil {
			t.Fatal(err)
		}
		mt := base.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(filepath.Join(d.path, hexName(s)), mt, mt); err != nil {
			t.Fatal(err)
		}
		sums = append(sums, s)
	}
	d.prune()
	if _, _, err := d.Chunk(sums[0], 0); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("oldest kept")
	}
	for _, s := range sums[1:] {
		if _, _, err := d.Chunk(s, 0); err != nil {
			t.Fatal("newer dropped:", err)
		}
	}
}

func TestImportRefusesSymlinkAndSpecialFiles(t *testing.T) {
	d, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	orig, _ := writeTemp(t, 100)
	link := filepath.Join(t.TempDir(), "link.apk")
	if err := os.Symlink(orig, link); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Import(link); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("symlink source: %v", err)
	}
	fifo := filepath.Join(t.TempDir(), "fifo.apk")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := d.Import(fifo); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Fatalf("fifo: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("import blocked on a FIFO")
	}
	if _, err := d.Import(t.TempDir()); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("directory: %v", err)
	}
	if e, _ := os.ReadDir(d.path); len(e) != 0 {
		t.Fatalf("stored %d entries", len(e))
	}
}

// Regression guard: rename replaces a planted link and never writes through it.
func TestImportReplacesPlantedSymlinkAtDestination(t *testing.T) {
	d, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	src, data := writeTemp(t, 100)
	sum := sha256.Sum256(data)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(d.path, hexName(sum[:]))
	if err := os.Symlink(victim, dst); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Import(src); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep me" {
		t.Fatal("wrote through the planted symlink")
	}
	if st, err := os.Lstat(dst); err != nil || !st.Mode().IsRegular() {
		t.Fatalf("destination: %v %v", st, err)
	}
}

func TestImportReader(t *testing.T) {
	d, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{7}, 3000)
	sum, err := d.ImportReader(bytes.NewReader(data))
	want := sha256.Sum256(data)
	if err != nil || !bytes.Equal(sum, want[:]) {
		t.Fatalf("import: %x %v", sum, err)
	}
	if _, err := d.ImportReader(bytes.NewReader(nil)); !errors.Is(err, ErrEmpty) {
		t.Fatalf("empty stream: %v", err)
	}
	if files, _ := filepath.Glob(filepath.Join(d.path, "*.apk")); len(files) != 1 {
		t.Fatalf("files: %v", files)
	}
}
