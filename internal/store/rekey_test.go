package store

import (
	"bytes"
	"context"
	"testing"

	pb "ottermsg/server/internal/proto/otterv1"
)

func rekeyItem(t *testing.T, old, nw []byte, created int64) Item {
	return mkItemAt(t, pb.RecordType_REKEY, netAuthor, &pb.Rekey{OldUserId: old, NewUserId: nw}, created)
}

func nameOf(t *testing.T, s *Store, id []byte) (string, bool) {
	t.Helper()
	u, err := s.UserByID(context.Background(), id)
	if err != nil || u == nil {
		t.Fatalf("user %x: %v", id, err)
	}
	return u.Username, u.Revoked
}

func rankOf(t *testing.T, s *Store, id []byte) int64 {
	t.Helper()
	var r int64
	if err := s.r.QueryRow(`SELECT entry_created_ms FROM users WHERE user_id=?`, id).Scan(&r); err != nil {
		t.Fatal(err)
	}
	return r
}

// D111: the person registers again under the revoked name (name#abcd), then the REKEY hands the name over.
func TestRekeyNewRegistersFirst(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	old, nw := r16(), r16()
	if err := apply(t, s, mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, old, entry(old, "anna", 1), 1000)); err != nil {
		t.Fatal(err)
	}
	// a non-revoked owner's name is still taken locally
	if err := apply(t, s, mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, nw, entry(nw, "anna", 1), 5000)); err != ErrUsernameTaken {
		t.Fatalf("taken name: %v", err)
	}
	replicate(t, s, revocation(t, old, 2000)) // step 1 (M9.2 REVOCATION)
	if err := apply(t, s, mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, nw, entry(nw, "anna", 1), 5000)); err != nil {
		t.Fatalf("a revoked owner's name must be registrable: %v", err)
	}
	if n, _ := nameOf(t, s, nw); n != conflictName("anna", nw) {
		t.Fatalf("before REKEY new = %q", n)
	}
	if err := apply(t, s, rekeyItem(t, old, nw, 6000)); err != nil {
		t.Fatal(err)
	}
	if n, _ := nameOf(t, s, nw); n != "anna" {
		t.Fatalf("after REKEY new = %q", n)
	}
	if n, rev := nameOf(t, s, old); n != conflictName("anna", old) || !rev {
		t.Fatalf("old = %q revoked=%v", n, rev)
	}
	if r := rankOf(t, s, nw); r != 1000 {
		t.Fatalf("new's rank = %d, want old's 1000", r)
	}
	// old's late entry (a thief editing the profile) never takes the name back
	replicate(t, s, mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, old, entry(old, "anna", 2), 7000))
	if n, _ := nameOf(t, s, nw); n != "anna" {
		t.Fatalf("old reclaimed the name: new = %q", n)
	}
	if owner, _ := s.UsernameOwner(ctx, "anna"); !bytes.Equal(owner, nw) {
		t.Fatalf("owner %x", owner)
	}
}

func TestRekeyBeforeNewEntryAndRankInherited(t *testing.T) {
	s, _ := open(t)
	old, nw, other := r16(), r16(), r16()
	replicate(t, s, mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, old, entry(old, "anna", 1), 1000))
	replicate(t, s, rekeyItem(t, old, nw, 6000))
	// a third account registered between old and new must not win the name
	replicate(t, s, mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, other, entry(other, "anna", 1), 3000))
	replicate(t, s, mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, nw, entry(nw, "anna", 1), 5000))
	if n, _ := nameOf(t, s, nw); n != "anna" {
		t.Fatalf("new = %q, want the inherited rank to win", n)
	}
	if n, _ := nameOf(t, s, other); n != conflictName("anna", other) {
		t.Fatalf("other = %q", n)
	}
	var reason string
	if err := s.r.QueryRow(`SELECT revoke_reason FROM users WHERE user_id=?`, old).Scan(&reason); err != nil || reason != ReasonRekey {
		t.Fatalf("old's reason %q %v", reason, err)
	}
	recs, _ := s.Rekeys(context.Background())
	if len(recs) != 1 {
		t.Fatalf("rekeys = %d", len(recs))
	}
}

// Every arrival order of old's entry, a third account's entry, new's entry and the REKEY ends the same way.
func TestRekeyAnyOrder(t *testing.T) {
	old, nw, other := r16(), r16(), r16()
	items := map[byte]Item{
		'o': mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, old, entry(old, "anna", 1), 1000),
		'x': mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, other, entry(other, "anna", 1), 3000),
		'n': mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, nw, entry(nw, "anna", 1), 5000),
		'k': rekeyItem(t, old, nw, 6000),
	}
	for _, order := range perms("oxnk") {
		s, _ := open(t)
		for i := range order {
			replicate(t, s, items[order[i]])
		}
		n1, _ := nameOf(t, s, nw)
		n2, rev := nameOf(t, s, old)
		n3, _ := nameOf(t, s, other)
		if n1 != "anna" || n2 != conflictName("anna", old) || !rev || n3 != conflictName("anna", other) || rankOf(t, s, nw) != 1000 {
			t.Fatalf("order %s: new=%q old=%q revoked=%v other=%q rank=%d", order, n1, n2, rev, n3, rankOf(t, s, nw))
		}
		s.Close()
	}
}

// Two REKEYs of the same old account: the later created_ms wins on every node, in either order.
func TestRekeyLaterWins(t *testing.T) {
	ctx := context.Background()
	old, n1, n2 := r16(), r16(), r16()
	items := map[byte]Item{
		'o': mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, old, entry(old, "anna", 1), 1000),
		'a': mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, n1, entry(n1, "anna", 1), 4000),
		'b': mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, n2, entry(n2, "anna", 1), 5000),
		'1': rekeyItem(t, old, n1, 6000),
		'2': rekeyItem(t, old, n2, 7000),
	}
	for _, order := range perms("oab12") {
		s, _ := open(t)
		for i := range order {
			replicate(t, s, items[order[i]])
		}
		a, _ := nameOf(t, s, n1)
		b, _ := nameOf(t, s, n2)
		if b != "anna" || a != conflictName("anna", n1) || rankOf(t, s, n1) != 4000 || rankOf(t, s, n2) != 1000 {
			t.Fatalf("order %s: n1=%q (%d) n2=%q (%d)", order, a, rankOf(t, s, n1), b, rankOf(t, s, n2))
		}
		recs, _ := s.Rekeys(ctx)
		if len(recs) != 1 || !bytes.Equal(recs[0], mustRaw(items['2'].Record)) {
			t.Fatalf("order %s: rekeys %d", order, len(recs))
		}
		s.Close()
	}
}

// The new account redeemed the admin's invite after someone else did (an intercepted link, D102): the REKEY names
// the account the admin confirmed, so it is admitted in either order and the interceptor's earlier redemption does
// not disable it.
func TestRekeyTargetNotADuplicate(t *testing.T) {
	ctx := context.Background()
	inv := bytes.Repeat([]byte{1}, 32)
	old, thief, nw := r16(), r16(), r16()
	lo, hi := bytes.Repeat([]byte{0x10}, 32), bytes.Repeat([]byte{0x20}, 32)
	items := map[byte]Item{
		't': admitted(t, thief, "tom", inv, lo, 1000, 1000),
		'n': admitted(t, nw, "anna", inv, hi, 1000, 1000),
		'k': rekeyItem(t, old, nw, 6000),
	}
	for _, order := range perms("tnk") {
		s, _ := open(t)
		for i := range order {
			if _, _, err := s.ApplyReplicatedItem(ctx, items[order[i]], peer); err != nil {
				t.Fatal(err)
			}
		}
		if _, rev := nameOf(t, s, nw); rev {
			t.Fatalf("order %s: the REKEY target is disabled", order)
		}
		s.Close()
	}
}

// perms lists every ordering of the bytes of s.
func perms(s string) []string {
	if len(s) <= 1 {
		return []string{s}
	}
	var out []string
	for i := range s {
		for _, p := range perms(s[:i] + s[i+1:]) {
			out = append(out, s[i:i+1]+p)
		}
	}
	return out
}
