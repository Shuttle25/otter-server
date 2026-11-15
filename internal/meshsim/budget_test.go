package meshsim

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
	"ottermsg/server/internal/store"
)

// signAt is signAs with an explicit created_ms and record expires_ms.
func (s *sim) signAt(a *account, typ pb.RecordType, payload proto.Message, created, expires int64) *pb.Record {
	p, err := proto.Marshal(payload)
	if err != nil {
		s.t.Fatal(err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		s.t.Fatal(err)
	}
	r, err := records.Sign(&pb.RecordBody{Id: id, Type: typ, Author: a.id, CreatedMs: created, ExpiresMs: expires, Payload: p}, a.priv)
	if err != nil {
		s.t.Fatal(err)
	}
	return r
}

// C8: per-author budgets give the same live set everywhere; compaction keeps Since(cursor) complete, and a hostile
// peer replaying compacted records changes nothing.
func TestBudgetsConvergeAfterCompaction(t *testing.T) {
	s := newSim(t, "a", "b", "c")
	a, b, c := s.node("a"), s.node("b"), s.node("c")
	anna := s.register(a, "anna", a, b)
	eventually(t, "anna on C", func() bool { return c.knows(anna) })
	s.stop(c)
	ctx := context.Background()
	annaA := s.login(a, anna)
	defer annaA.close()
	now := time.Now()

	quota := 0
	for i := 0; i < 55; i++ {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			t.Fatal(err)
		}
		inv, err := records.InvitePayload(secret, now.Add(7*24*time.Hour).UnixMilli())
		if err != nil {
			t.Fatal(err)
		}
		r := s.signAt(anna, pb.RecordType_INVITE, inv, now.Add(time.Duration(i)*time.Millisecond).UnixMilli(), inv.ExpiresMs)
		switch st, msg := annaA.call("invite.create", &pb.RecordRequest{Record: r}, nil); st {
		case pb.Status_STATUS_OK:
		case pb.Status_STATUS_QUOTA:
			quota++
		default:
			t.Fatalf("invite %d: %v %s", i, st, msg)
		}
	}
	if quota != 5 {
		t.Fatalf("%d invites refused, want 5", quota)
	}

	var tokens []*pb.Record
	for i := 0; i < 5; i++ {
		r := s.signAt(anna, pb.RecordType_PUSH_TOKEN, &pb.PushToken{DeviceId: 1, Kind: pb.PushToken_FCM, Token: fmt.Sprint("tok", i)},
			now.Add(time.Duration(i-10)*time.Second).UnixMilli(), 0)
		tokens = append(tokens, r)
		annaA.mustCall("push.register", &pb.RecordRequest{Record: r}, nil)
	}

	var refills []*pb.Record
	for i := 0; i < 3; i++ {
		pk := &pb.PreKeys{DeviceId: 1, RegistrationId: 4}
		for j := 0; j < 150; j++ {
			pk.OneTime = append(pk.OneTime, &pb.OneTimePreKey{Id: uint32(1000 + 150*i + j), PublicKey: make([]byte, 33), OwnerNode: b.id})
		}
		r := s.signAs(anna, pb.RecordType_PREKEYS, pk)
		refills = append(refills, r)
		annaA.mustCall("prekeys.upload", &pb.RecordRequest{Record: r}, nil)
	}

	eventually(t, "A and B equal", func() bool { return a.recordKeys() == b.recordKeys() })
	for _, n := range []*simNode{a, b} {
		if _, err := n.st.Expire(ctx, now.Add(2*time.Hour).UnixMilli()); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range append([]*pb.Record{tokens[0]}, refills[0]) {
		if a.has(recordKey(r)) || b.has(recordKey(r)) {
			t.Fatal("compaction left a superseded record on A or B")
		}
	}

	s.start(c)
	eventually(t, "C converged", func() bool { return c.recordKeys() == a.recordKeys() && a.recordKeys() == b.recordKeys() })
	check := func(when string) {
		t.Helper()
		for _, n := range []*simNode{a, b, c} {
			if m, _ := n.st.PrekeyCounts(ctx, anna.id, 1); m[string(b.id)] != store.MaxLiveOneTime {
				t.Fatalf("%s: %s holds %d keys owned by B", when, n.label, m[string(b.id)])
			}
			if tok, _ := n.st.PushToken(ctx, anna.id, 1); tok != "tok4" {
				t.Fatalf("%s: %s token %q", when, n.label, tok)
			}
			if k, _ := n.st.LiveInvites(ctx, anna.id, now.UnixMilli()); k != store.MaxLiveInvites {
				t.Fatalf("%s: %s has %d live invites", when, n.label, k)
			}
		}
	}
	check("caught up")
	for _, r := range []*pb.Record{tokens[0], refills[0]} { // a hostile peer replays compacted records
		if _, err := c.svc.ApplyReplicated(ctx, a.id, r); err != nil {
			t.Fatal(err)
		}
	}
	check("after replay")
	if c.has(recordKey(tokens[0])) {
		t.Fatal("C stored a superseded push token")
	}
	// C never held the first refill, so it may keep the replayed copy (its keys only arrive consumed) until its own
	// janitor compacts it like A and B did; A and B ignore it when C passes it on.
	if _, err := c.st.Expire(ctx, now.Add(2*time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	check("after C's janitor")
	eventually(t, "all equal again", func() bool { return c.recordKeys() == a.recordKeys() && a.recordKeys() == b.recordKeys() })
	if a.has(recordKey(refills[0])) || b.has(recordKey(refills[0])) || c.has(recordKey(refills[0])) {
		t.Fatal("a compacted refill came back")
	}
}
