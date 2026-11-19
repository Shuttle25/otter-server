package store

import (
	"bytes"
	"context"
	"testing"
)

func TestRelations(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	a, b, c, d := []byte("aaaaaaaaaaaaaaaa"), []byte("bbbbbbbbbbbbbbbb"), []byte("cccccccccccccccc"), []byte("dddddddddddddddd")
	for _, q := range []struct {
		inv, user, inviter []byte
	}{{[]byte("i1"), b, a}, {[]byte("i2"), c, b}, {[]byte("i2"), d, b}} {
		if _, err := s.w.ExecContext(ctx, `INSERT INTO redemptions(invite_id,user_id,rank,inviter) VALUES(?,?,?,?)`,
			q.inv, q.user, []byte{1}, q.inviter); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.w.ExecContext(ctx, `INSERT INTO rekeys(old_user_id,new_user_id,record_key,created_ms) VALUES(?,?,?,?)`,
		b, d, []byte("k"), 1); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Inviters(ctx, c); len(got) != 1 || !bytes.Equal(got[0], b) {
		t.Fatalf("inviters of c: %x", got)
	}
	if got, _ := s.Inviters(ctx, a); len(got) != 0 {
		t.Fatalf("inviters of founding a: %x", got)
	}
	if got, _ := s.Invitees(ctx, b); len(got) != 2 {
		t.Fatalf("invitees of b: %x", got)
	}
	if got, _ := s.Rivals(ctx, c); len(got) != 1 || !bytes.Equal(got[0], d) {
		t.Fatalf("rivals of c: %x", got)
	}
	if got, _ := s.RekeyedTo(ctx, a); got != nil {
		t.Fatalf("rekeyed a: %x", got)
	}
	if got, _ := s.RekeyedTo(ctx, b); !bytes.Equal(got, d) {
		t.Fatalf("rekeyed b: %x", got)
	}
	if got, _ := s.RekeyedFrom(ctx, d); len(got) != 1 || !bytes.Equal(got[0], b) {
		t.Fatalf("rekeyed from d: %x", got)
	}
}
