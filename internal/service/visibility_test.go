package service

import (
	"context"
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
