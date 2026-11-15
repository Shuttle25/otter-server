package store

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestBackup(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	r, b := rec(t)
	if _, _, err := s.Apply(ctx, r, b); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "copy.db")
	if err := s.Backup(ctx, out); err != nil {
		t.Fatal(err)
	}
	c, err := Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Get(ctx, append(append([]byte{}, b.Author...), b.Id...)); err != nil {
		t.Fatalf("record missing from the copy: %v", err)
	}
	if err := s.Backup(ctx, out); err == nil {
		t.Fatal("overwrote an existing file")
	}
}

func TestBackupIsPrivateAndRefusesLinks(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	s, _ := open(t)
	ctx := context.Background()
	out := filepath.Join(t.TempDir(), "copy.db")
	if err := s.Backup(ctx, out); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(out); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode: %v %v", st.Mode(), err)
	}
	target := filepath.Join(t.TempDir(), "victim.db")
	link := filepath.Join(t.TempDir(), "link.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := s.Backup(ctx, link); err == nil {
		t.Fatal("backup through a planted link")
	}
	if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("link target created: %v", err)
	}
	// a failed VACUUM INTO (here: a cancelled context) leaves no empty file behind
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	failed := filepath.Join(t.TempDir(), "failed.db")
	if err := s.Backup(cctx, failed); err == nil {
		t.Fatal("backup with a cancelled context")
	}
	if _, err := os.Lstat(failed); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("failed backup left a file: %v", err)
	}
}
