package store

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestHoldsAndDropBackupCopy(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	u := newUser(t, s, "anna")
	blob := u.persistentBlob(t, s, 2*262144)
	if held, _ := s.Holds(ctx, blob); held {
		t.Fatal("held without chunks")
	}
	s.MarkChunk(ctx, blob, 0)
	if held, _ := s.Holds(ctx, blob); held {
		t.Fatal("held with one chunk of two")
	}
	s.MarkChunk(ctx, blob, 1)
	if held, _ := s.Holds(ctx, blob); !held {
		t.Fatal("complete blob not held")
	}
	// a fresh blob nothing references is not a candidate yet (backup.publish follows the upload)
	if items, err := s.LocalBackupItems(ctx, time.Now().Add(-time.Hour).UnixMilli()); err != nil || len(items) != 0 {
		t.Fatalf("fresh unreferenced blob is a candidate: %d %v", len(items), err)
	}
	meta := u.backupMeta(t, s, 1, blob)
	items, err := s.LocalBackupItems(ctx, time.Now().Add(-time.Hour).UnixMilli())
	if err != nil || len(items) != 1 || !bytes.Equal(items[0], blob) {
		t.Fatalf("items %x %v (want only the blob: the meta waits for it)", items, err)
	}
	if held, _ := s.Holds(ctx, meta); !held {
		t.Fatal("backup meta not held")
	}
	if err := s.DropBackupCopy(ctx, blob); err != nil {
		t.Fatal(err)
	}
	items, err = s.LocalBackupItems(ctx, time.Now().Add(-time.Hour).UnixMilli())
	if err != nil || len(items) != 1 || !bytes.Equal(items[0], meta) {
		t.Fatalf("items %x %v (want the meta once its blob is gone)", items, err)
	}
	if err := s.DropBackupCopy(ctx, meta); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Blob(ctx, blob); err != ErrNotFound {
		t.Fatalf("blob row still there after drop: %v", err)
	}
	if have, _ := s.BlobChunks(ctx, blob); len(have) != 0 {
		t.Fatal("chunk rows still there after drop")
	}
	if gone, _ := s.BlobGone(ctx, blob); !gone {
		t.Fatal("no tombstone: a lagging peer could resurrect it")
	}
	if _, err := s.Get(ctx, meta); err != ErrNotFound {
		t.Fatal("backup meta still stored")
	}
	if _, err := s.BackupFor(ctx, "anna"); err != ErrNotFound {
		t.Fatalf("backups row survived: %v", err)
	}
	if items, _ := s.LocalBackupItems(ctx, time.Now().UnixMilli()+1); len(items) != 0 {
		t.Fatalf("dropped items still listed: %d", len(items))
	}
	if held, _ := s.Holds(ctx, r16()); held {
		t.Fatal("unknown key held")
	}
	// re-sent by a lagging peer: stays gone
	u.reapply(t, s, blob)
	if _, err := s.Get(ctx, blob); err != ErrNotFound {
		t.Fatal("dropped blob resurrected")
	}
	if p, _ := s.BlobPersistent(ctx, blob); p {
		t.Fatal("dropped blob still persistent here")
	}
}

// A backup superseded here by a newer one counts as held: the node with no_backups must not keep a stale copy
// forever because the newer backup reached the other nodes first (D50, D113).
func TestHoldsSuperseded(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	u := newUser(t, s, "anna")
	b1 := u.persistentBlob(t, s, 1000)
	m1 := u.backupMeta(t, s, 1, b1)
	b2 := u.persistentBlob(t, s, 1000)
	s.MarkChunk(ctx, b2, 0)
	m2 := u.backupMeta(t, s, 2, b2)
	for _, k := range [][]byte{b1, m1, b2, m2} {
		if held, err := s.Holds(ctx, k); err != nil || !held {
			t.Fatalf("%x: held=%v %v", k, held, err)
		}
	}
	if p, _ := s.BlobPersistent(ctx, b2); !p {
		t.Fatal("persistent blob not reported")
	}
	// an older backup arriving after the newer one is dropped on apply and also counts as held
	b0 := u.persistentBlob(t, s, 1000)
	m0 := u.backupMeta(t, s, 1, b0) // version 1 after version 2: loses
	if held, _ := s.Holds(ctx, m0); !held {
		t.Fatal("losing older backup meta not reported as superseded")
	}
	// expired from the oplog by the janitor: still superseded
	if _, err := s.Expire(ctx, time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if held, _ := s.Holds(ctx, m1); !held {
		t.Fatal("superseded meta forgotten after the janitor")
	}
}
