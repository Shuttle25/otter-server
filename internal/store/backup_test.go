package store

import (
	"context"
	"path/filepath"
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
