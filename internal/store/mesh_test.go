package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
)

func mkItemAt(t *testing.T, typ pb.RecordType, author []byte, payload proto.Message, created int64) Item {
	p, _ := proto.Marshal(payload)
	b := &pb.RecordBody{Id: r16(), Type: typ, Author: author, CreatedMs: created, Payload: p}
	raw, _ := proto.Marshal(b)
	return Item{Record: &pb.Record{Body: raw, Signature: make([]byte, 64)}, Body: b}
}

var peer = []byte("peer-peer-peer-1")

func replicate(t *testing.T, s *Store, it Item) {
	t.Helper()
	if _, _, err := s.ApplyReplicated(context.Background(), it.Record, it.Body, peer); err != nil {
		t.Fatalf("replicated apply: %v", err)
	}
}

func TestReplicatedInviteReuse(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	inviter, u1, u2 := r16(), r16(), r16()
	id := make([]byte, 32)
	rand.Read(id)
	if err := apply(t, s, mkItem(t, pb.RecordType_INVITE, inviter, &pb.Invite{InviteId: id, ExpiresMs: 1 << 62})); err != nil {
		t.Fatal(err)
	}
	if err := apply(t, s, mkItem(t, pb.RecordType_INVITE_USED, u1, &pb.InviteUsed{InviteId: id, UserId: u1})); err != nil {
		t.Fatal(err)
	}
	replicate(t, s, mkItem(t, pb.RecordType_INVITE_USED, u2, &pb.InviteUsed{InviteId: id, UserId: u2}))
	inv, _ := s.Invite(ctx, id)
	if !bytes.Equal(inv.UsedBy, u1) {
		t.Fatal("first used_by must win")
	}
	// locally it still fails
	if err := apply(t, s, mkItem(t, pb.RecordType_INVITE_USED, u2, &pb.InviteUsed{InviteId: id, UserId: u2})); err != ErrInviteUnavailable {
		t.Fatalf("local reuse: %v", err)
	}
}

func TestUsernameClashBothOrders(t *testing.T) {
	ctx := context.Background()
	check := func(t *testing.T, s *Store, winner, loser []byte) {
		t.Helper()
		owner, _ := s.UsernameOwner(ctx, "anna")
		if !bytes.Equal(owner, winner) {
			t.Fatalf("anna owned by %x, want %x", owner, winner)
		}
		u, _ := s.UserByID(ctx, loser)
		if u == nil || u.Username != "anna#"+hex.EncodeToString(loser[:4]) {
			t.Fatalf("loser: %+v", u)
		}
	}
	run := func(t *testing.T, created1, created2 int64, u1, u2, winner, loser []byte) {
		e1 := mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, u1, entry(u1, "anna", 1), created1)
		e2 := mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, u2, entry(u2, "anna", 1), created2)
		a, _ := open(t)
		if err := apply(t, a, e1); err != nil {
			t.Fatal(err)
		}
		replicate(t, a, e2)
		check(t, a, winner, loser)
		b, _ := open(t)
		if err := apply(t, b, e2); err != nil {
			t.Fatal(err)
		}
		replicate(t, b, e1)
		check(t, b, winner, loser)
		// a local entry claiming the taken name is still refused
		u3 := r16()
		if err := apply(t, a, mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, u3, entry(u3, "anna", 1), 50)); err != ErrUsernameTaken {
			t.Fatalf("local clash: %v", err)
		}
	}
	u1, u2 := r16(), r16()
	t.Run("earlier wins", func(t *testing.T) { run(t, 100, 200, u1, u2, u1, u2) })
	lo, hi := []byte("aaaaaaaaaaaaaaa1"), []byte("bbbbbbbbbbbbbbb2")
	t.Run("tie: lower id wins", func(t *testing.T) { run(t, 100, 100, hi, lo, lo, hi) })
}

func TestPrekeyConsumedAndCounts(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	u := r16()
	nodeA, nodeB := []byte("node-A-node-A-01"), []byte("node-B-node-B-01")
	pk := &pb.PreKeys{DeviceId: 1, RegistrationId: 1,
		SignedPrekey: &pb.SignedPreKey{Id: 1, PublicKey: []byte{1}, Signature: []byte{2}},
		KyberPrekey:  &pb.SignedPreKey{Id: 1, PublicKey: []byte{3}, Signature: []byte{4}}}
	for i := 0; i < 5; i++ {
		owner := nodeA
		if i >= 3 {
			owner = nodeB
		}
		pk.OneTime = append(pk.OneTime, &pb.OneTimePreKey{Id: uint32(10 + i), PublicKey: []byte{byte(i)}, OwnerNode: owner})
	}
	if err := apply(t, s, mkItem(t, pb.RecordType_PREKEYS, u, pk)); err != nil {
		t.Fatal(err)
	}
	counts := func() map[string]int { c, _ := s.PrekeyCounts(ctx, u, 1); return c }
	if c := counts(); c[string(nodeA)] != 3 || c[string(nodeB)] != 2 {
		t.Fatalf("%v", c)
	}
	replicate(t, s, mkItemAt(t, pb.RecordType_PREKEY_CONSUMED, nodeA, &pb.PrekeyConsumed{UserId: u, DeviceId: 1, KeyIds: []uint32{10}}, time.Now().UnixMilli()))
	// a node can only consume keys it owns
	replicate(t, s, mkItemAt(t, pb.RecordType_PREKEY_CONSUMED, nodeA, &pb.PrekeyConsumed{UserId: u, DeviceId: 1, KeyIds: []uint32{13}}, time.Now().UnixMilli()))
	if c := counts(); c[string(nodeA)] != 2 || c[string(nodeB)] != 2 {
		t.Fatalf("after consumed: %v", c)
	}
	if _, err := s.TakePrekeys(ctx, u, 1, nodeB); err != nil {
		t.Fatal(err)
	}
	if c := counts(); c[string(nodeA)] != 2 || c[string(nodeB)] != 1 {
		t.Fatalf("after take: %v", c)
	}
}

func TestChangedNotification(t *testing.T) {
	s, _ := open(t)
	ch := s.Changed()
	it := mkItem(t, pb.RecordType_DIRECTORY_ENTRY, r16(), entry(r16(), "zed", 1))
	if err := apply(t, s, it); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("not notified")
	}
	ch2 := s.Changed()
	if err := apply(t, s, it); err != nil { // duplicate: nothing new applied
		t.Fatal(err)
	}
	select {
	case <-ch2:
		t.Fatal("notified for a duplicate")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestPeerCursor(t *testing.T) {
	s, p := open(t)
	ctx := context.Background()
	if c, err := s.PeerCursor(ctx, peer); err != nil || c != 0 {
		t.Fatalf("%d %v", c, err)
	}
	s.SetPeerCursor(ctx, peer, 42)
	s.SetPeerCursor(ctx, peer, 7) // never moves backwards
	s.Close()
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if c, _ := s2.PeerCursor(ctx, peer); c != 42 {
		t.Fatalf("cursor %d", c)
	}
}

func TestExpire(t *testing.T) {
	p := filepath.Join(t.TempDir(), "e.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	t0 := time.UnixMilli(1_800_000_000_000)
	clock := t0
	s.now = func() time.Time { return clock }
	sender, rcpt := r16(), r16()
	env := mkItemAt(t, pb.RecordType_ENVELOPE, sender, &pb.Envelope{SenderUser: sender, SenderDevice: 1, Kind: pb.Envelope_SIGNAL,
		Recipients: []*pb.Recipient{{User: rcpt, Device: 1, Content: []byte{1}}}}, t0.UnixMilli())
	other := r16()
	ack := mkItemAt(t, pb.RecordType_ACK, other, &pb.Ack{EnvelopeIds: [][]byte{make([]byte, 32)}, DeviceId: 1}, t0.UnixMilli())
	dir := mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, sender, entry(sender, "old_user", 1), t0.UnixMilli())
	for _, it := range []Item{env, ack, dir} {
		if err := apply(t, s, it); err != nil {
			t.Fatal(err)
		}
	}
	clock = t0.Add(31 * 24 * time.Hour)
	st, err := s.Expire(ctx, clock.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if st.Envelopes != 1 || st.Acks != 1 || st.Oplog != 2 {
		t.Fatalf("stats %+v", st)
	}
	if box, _ := s.Mailbox(ctx, rcpt, 1, 10); len(box) != 0 {
		t.Fatal("mailbox not expired")
	}
	if u, _ := s.UserByID(ctx, sender); u == nil {
		t.Fatal("directory entry must not expire")
	}
	if log, _ := s.Since(ctx, 0, 10); len(log) != 1 {
		t.Fatalf("oplog after compaction: %d entries", len(log))
	}
	// a peer re-sending the expired envelope does not resurrect it
	if _, applied, err := s.ApplyReplicated(ctx, env.Record, env.Body, peer); err != nil || applied {
		t.Fatalf("resurrected: applied=%v err=%v", applied, err)
	}
	if box, _ := s.Mailbox(ctx, rcpt, 1, 10); len(box) != 0 {
		t.Fatal("mailbox resurrected")
	}
}
