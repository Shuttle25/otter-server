package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
)

// entryUsers returns the user ids of the DIRECTORY_ENTRY records in recs, and how many other records there are.
func entryUsers(t *testing.T, recs []*pb.Record) (map[string]bool, int) {
	t.Helper()
	ids, other := map[string]bool{}, 0
	for _, r := range recs {
		var b pb.RecordBody
		if err := proto.Unmarshal(r.Body, &b); err != nil {
			t.Fatal(err)
		}
		if b.Type != pb.RecordType_DIRECTORY_ENTRY {
			other++
			continue
		}
		ids[string(b.Author)] = true
	}
	return ids, other
}

func TestVisibleDirectory(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	a := f.mustRegister(f.invite(nil, time.Hour), "anna")
	b := f.mustRegister(f.invite(a, time.Hour), "boris")
	c := f.mustRegister(f.invite(b, time.Hour), "clara")
	d := f.mustRegister(f.invite(nil, time.Hour), "dima")
	e := f.mustRegister(f.invite(nil, time.Hour), "elena")
	listed := entryV(e, "elena", "Елена", 2, 1)
	listed.Listed = true
	if err := f.svc.UpdateDirectoryEntry(ctx, e.id, sign(t, pb.RecordType_DIRECTORY_ENTRY, e.id, listed, e.priv)); err != nil {
		t.Fatal(err)
	}
	// C sees A only as ancestry (B's inviter), which the phone needs for the chain check (D104)
	want := map[*user][]*user{a: {a, b, e}, b: {a, b, c, e}, c: {a, b, c, e}, d: {d, e}}
	names := map[string]string{string(a.id): "anna", string(b.id): "boris", string(c.id): "clara", string(d.id): "dima", string(e.id): "elena"}
	for who, ws := range want {
		recs, err := f.svc.VisibleDirectory(ctx, who.id)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := entryUsers(t, recs)
		if len(got) != len(ws) {
			t.Errorf("%s sees %d entries, want %d", names[string(who.id)], len(got), len(ws))
		}
		for _, w := range ws {
			if !got[string(w.id)] {
				t.Errorf("%s does not see %s", names[string(who.id)], names[string(w.id)])
			}
		}
	}
	all, _ := f.svc.Directory(ctx)
	if got, _ := entryUsers(t, all); len(got) != 5 {
		t.Fatalf("Directory (admin) shows %d entries, want 5", len(got))
	}
}

func TestVisibleDirectoryCarriesMembershipRecords(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	a := f.mustRegister(f.invite(nil, time.Hour), "anna")
	b := f.mustRegister(f.invite(nil, time.Hour), "boris")
	f.netRecord(pb.RecordType_REVOCATION, &pb.Revocation{UserId: b.id, Reason: "test"})
	recs, err := f.svc.VisibleDirectory(ctx, a.id)
	if err != nil {
		t.Fatal(err)
	}
	if got, other := entryUsers(t, recs); other != 1 || got[string(b.id)] {
		t.Fatalf("membership records: %d, want 1 (the REVOCATION); unrelated boris shown: %v", other, got[string(b.id)])
	}
}

// D111: a re-keyed account keeps its relations both ways; the REKEY itself is in every answer.
func TestVisibleDirectoryFollowsRekey(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	a := f.mustRegister(f.invite(nil, time.Hour), "anna")
	b := f.mustRegister(f.invite(a, time.Hour), "boris")
	f.netRecord(pb.RecordType_REVOCATION, &pb.Revocation{UserId: b.id, Reason: "lost phone"})
	b2 := f.mustRegister(f.invite(nil, time.Hour), "boris")
	f.netRecord(pb.RecordType_REKEY, &pb.Rekey{OldUserId: b.id, NewUserId: b2.id})
	recs, err := f.svc.VisibleDirectory(ctx, a.id)
	if err != nil {
		t.Fatal(err)
	}
	got, other := entryUsers(t, recs)
	if !got[string(b2.id)] || !got[string(b.id)] || len(got) != 3 {
		t.Fatalf("anna sees boris2=%v boris=%v (%d entries)", got[string(b2.id)], got[string(b.id)], len(got))
	}
	if other != 2 {
		t.Fatalf("membership records: %d, want 2 (REVOCATION, REKEY)", other)
	}
	recs, err = f.svc.VisibleDirectory(ctx, b2.id)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := entryUsers(t, recs); !got[string(a.id)] || !got[string(b.id)] || len(got) != 3 {
		t.Fatalf("boris2 sees anna=%v old boris=%v (%d entries)", got[string(a.id)], got[string(b.id)], len(got))
	}
}

func TestDirectoryGet(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	a := f.mustRegister(f.invite(nil, time.Hour), "anna")
	b := f.mustRegister(f.invite(a, time.Hour), "boris")
	recs, err := f.svc.DirectoryGet(ctx, [][]byte{b.id, []byte("unknown-id-16byt")})
	if err != nil {
		t.Fatal(err)
	}
	if got, other := entryUsers(t, recs); len(got) != 2 || !got[string(a.id)] || !got[string(b.id)] || other != 0 {
		t.Fatalf("get boris: %d entries (want boris + inviter anna), %d other", len(got), other)
	}
	if _, err := f.svc.DirectoryGet(ctx, make([][]byte, MaxDirectoryGet+1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("too many ids: %v", err)
	}
}

func TestLookupUsername(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	a := f.mustRegister(f.invite(nil, time.Hour), "anna")
	b := f.mustRegister(f.invite(nil, time.Hour), "boris")
	recs, err := f.svc.LookupUsername(ctx, a.id, "  @Boris ")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := entryUsers(t, recs); !got[string(b.id)] {
		t.Fatal("boris not found")
	}
	tagged := "boris#" + fmt.Sprintf("%x", b.id[:4])
	if recs, err := f.svc.LookupUsername(ctx, a.id, tagged); err != nil {
		t.Fatalf("%s: %v", tagged, err)
	} else if got, _ := entryUsers(t, recs); !got[string(b.id)] {
		t.Fatalf("%s did not find boris", tagged)
	}
	for _, q := range []string{"nobody", "x", "boris#zz", "boris#00000000", ""} {
		if _, err := f.svc.LookupUsername(ctx, a.id, q); !errors.Is(err, ErrNotFound) {
			t.Errorf("%q: %v, want not found", q, err)
		}
	}
	f.netRecord(pb.RecordType_REVOCATION, &pb.Revocation{UserId: b.id, Reason: "test"})
	if _, err := f.svc.LookupUsername(ctx, a.id, "boris"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked: %v", err)
	}
}

func TestLookupLimit(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	a := f.mustRegister(f.invite(nil, time.Hour), "anna")
	for i := 0; i < LookupsPerHour-1; i++ {
		if _, err := f.svc.LookupUsername(ctx, a.id, fmt.Sprintf("nobody%d", i)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("lookup %d: %v", i, err)
		}
	}
	if _, err := f.svc.LookupUsername(ctx, a.id, "anna"); err != nil {
		t.Fatalf("30th lookup: %v", err)
	}
	if _, err := f.svc.LookupUsername(ctx, a.id, "anna"); !errors.Is(err, ErrQuota) {
		t.Fatalf("31st lookup: %v, want quota", err)
	}
}

func TestLookupDayLimit(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	a := f.mustRegister(f.invite(nil, time.Hour), "anna")
	t0 := time.Now()
	at := func(i int) { // a fresh hour every LookupsPerHour lookups
		now := t0.Add(time.Duration(i/LookupsPerHour) * 61 * time.Minute)
		f.svc.Now = func() time.Time { return now }
	}
	for i := 0; i < LookupsPerDay; i++ {
		at(i)
		if _, err := f.svc.LookupUsername(ctx, a.id, fmt.Sprintf("nobody%d", i)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("lookup %d: %v", i, err)
		}
	}
	at(LookupsPerDay) // the hour still has room
	if _, err := f.svc.LookupUsername(ctx, a.id, "anna"); !errors.Is(err, ErrQuota) {
		t.Fatalf("lookup %d in a day: %v, want quota", LookupsPerDay+1, err)
	}
}
