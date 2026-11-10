package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"path/filepath"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
)

func rec(t *testing.T) (*pb.Record, *pb.RecordBody) {
	id, author := make([]byte, 16), make([]byte, 16)
	rand.Read(id)
	rand.Read(author)
	b := &pb.RecordBody{Id: id, Author: author, Type: pb.RecordType_ACK, CreatedMs: 1}
	raw := append([]byte{0xAA}, id...)
	return &pb.Record{Body: raw, Signature: make([]byte, 64)}, b
}

func mustRaw(r *pb.Record) []byte { b, _ := proto.Marshal(r); return b }

func open(t *testing.T) (*Store, string) {
	p := filepath.Join(t.TempDir(), "node.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, p
}

func TestApplyIdempotent(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	r, b := rec(t)
	seq1, applied, err := s.Apply(ctx, r, b)
	if err != nil || !applied || seq1 != 1 {
		t.Fatalf("first apply: %d %v %v", seq1, applied, err)
	}
	seq2, applied, err := s.Apply(ctx, r, b)
	if err != nil || applied || seq2 != seq1 {
		t.Fatalf("second apply: %d %v %v", seq2, applied, err)
	}
}

func TestSinceAndGet(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	var keys [][]byte
	for i := 0; i < 5; i++ {
		r, b := rec(t)
		if _, _, err := s.Apply(ctx, r, b); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, append(append([]byte{}, b.Author...), b.Id...))
	}
	got, err := s.Since(ctx, 2, 10)
	if err != nil || len(got) != 3 || got[0].Seq != 3 || got[2].Seq != 5 {
		t.Fatalf("since: %+v %v", got, err)
	}
	raw, err := s.Get(ctx, keys[0])
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var gr pb.Record
	if err := proto.Unmarshal(raw, &gr); err != nil || gr.Body[0] != 0xAA {
		t.Fatalf("get: %x %v", raw, err)
	}
	if _, err := s.Get(ctx, make([]byte, 32)); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestConcurrentApply(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	seqs := make(chan int64, 1000)
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, b := rec(t)
			seq, _, err := s.Apply(ctx, r, b)
			if err != nil {
				t.Error(err)
				return
			}
			seqs <- seq
		}()
	}
	wg.Wait()
	close(seqs)
	seen := map[int64]bool{}
	for q := range seqs {
		if seen[q] {
			t.Fatalf("dup seq %d", q)
		}
		seen[q] = true
	}
	if len(seen) != 1000 {
		t.Fatalf("got %d seqs", len(seen))
	}
}

func TestReopen(t *testing.T) {
	s, p := open(t)
	r, b := rec(t)
	if _, _, err := s.Apply(context.Background(), r, b); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, _ := s2.Since(context.Background(), 0, 10)
	if len(got) != 1 || !bytes.Equal(got[0].Raw, mustRaw(r)) {
		t.Fatalf("after reopen: %+v", got)
	}
}

func TestPragmasAndMigrations(t *testing.T) {
	s, p := open(t)
	ctx := context.Background()
	for _, db := range []*sql.DB{s.r, s.w} {
		var mode string
		var sync, busy, fk int
		db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&mode)
		db.QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&sync)
		db.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busy)
		db.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk)
		if mode != "wal" || sync != 1 || busy != 5000 || fk != 1 {
			t.Fatalf("pragmas: journal=%s sync=%d busy=%d fk=%d", mode, sync, busy, fk)
		}
	}
	s.Close()
	s2, err := Open(p) // migrations must not re-run
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	var n int
	s2.r.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n)
	files, _ := migrationsFS.ReadDir("migrations")
	if n != len(files) {
		t.Fatalf("schema_migrations rows: %d, migrations: %d", n, len(files))
	}
}
