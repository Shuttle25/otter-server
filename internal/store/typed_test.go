package store

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
)

func r16() []byte { b := make([]byte, 16); rand.Read(b); return b }

func mkItem(t *testing.T, typ pb.RecordType, author []byte, payload proto.Message) Item {
	p, _ := proto.Marshal(payload)
	b := &pb.RecordBody{Id: r16(), Type: typ, Author: author, Payload: p}
	raw, _ := proto.Marshal(b)
	return Item{Record: &pb.Record{Body: raw, Signature: make([]byte, 64)}, Body: b}
}

func apply(t *testing.T, s *Store, it Item) error {
	_, _, err := s.ApplyFrom(context.Background(), it.Record, it.Body, []byte("node-node-node-1"))
	return err
}

func entry(id []byte, name string, ver uint64) *pb.DirectoryEntry {
	return &pb.DirectoryEntry{UserId: id, Username: name, DisplayName: name, AccountPub: make([]byte, 32), Version: ver, CanInvite: true}
}

func TestDirectoryEntries(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	a, b := r16(), r16()
	if err := apply(t, s, mkItem(t, pb.RecordType_DIRECTORY_ENTRY, a, entry(a, "anna", 1))); err != nil {
		t.Fatal(err)
	}
	if err := apply(t, s, mkItem(t, pb.RecordType_DIRECTORY_ENTRY, b, entry(b, "anna", 1))); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("want ErrUsernameTaken, got %v", err)
	}
	if err := apply(t, s, mkItem(t, pb.RecordType_DIRECTORY_ENTRY, a, entry(a, "anna_k", 2))); err != nil {
		t.Fatal(err)
	}
	u, err := s.UserByID(ctx, a)
	if err != nil || u.Username != "anna_k" || u.Version != 2 {
		t.Fatalf("user: %+v %v", u, err)
	}
	if _, ok := s.UserKey(a); !ok {
		t.Fatal("UserKey missing")
	}
	if _, ok := s.UserKey(b); ok {
		t.Fatal("b must not exist (rolled back)")
	}
	all, _ := s.DirectoryEntries(ctx)
	if len(all) != 1 {
		t.Fatalf("entries %d", len(all))
	}
	owner, _ := s.UsernameOwner(ctx, "anna_k")
	if string(owner) != string(a) {
		t.Fatal("owner")
	}
	// an older version does not win
	if err := apply(t, s, mkItem(t, pb.RecordType_DIRECTORY_ENTRY, a, entry(a, "anna_old", 1))); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.UserByID(ctx, a); u.Username != "anna_k" {
		t.Fatalf("older version won: %s", u.Username)
	}
}

func TestInviteFlowAtomic(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	inviter, newU := r16(), r16()
	id := make([]byte, 32)
	rand.Read(id)
	if err := apply(t, s, mkItem(t, pb.RecordType_INVITE, inviter, &pb.Invite{InviteId: id, ExpiresMs: 1 << 62})); err != nil {
		t.Fatal(err)
	}
	group := []Item{
		mkItem(t, pb.RecordType_DIRECTORY_ENTRY, newU, entry(newU, "boris", 1)),
		mkItem(t, pb.RecordType_INVITE_USED, newU, &pb.InviteUsed{InviteId: id, UserId: newU}),
	}
	if _, err := s.ApplyAll(ctx, nil, group); err != nil {
		t.Fatal(err)
	}
	inv, _ := s.Invite(ctx, id)
	if string(inv.UsedBy) != string(newU) {
		t.Fatal("used_by")
	}
	other := r16()
	group2 := []Item{
		mkItem(t, pb.RecordType_DIRECTORY_ENTRY, other, entry(other, "vera", 1)),
		mkItem(t, pb.RecordType_INVITE_USED, other, &pb.InviteUsed{InviteId: id, UserId: other}),
	}
	if _, err := s.ApplyAll(ctx, nil, group2); !errors.Is(err, ErrInviteUnavailable) {
		t.Fatalf("want ErrInviteUnavailable, got %v", err)
	}
	if u, _ := s.UserByID(ctx, other); u != nil {
		t.Fatal("vera must be rolled back")
	}
	if _, err := s.Get(ctx, append(append([]byte{}, other...), group2[0].Body.Id...)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("vera's entry record must be rolled back, got %v", err)
	}
	// expired invite
	id2 := make([]byte, 32)
	rand.Read(id2)
	if err := apply(t, s, mkItem(t, pb.RecordType_INVITE, inviter, &pb.Invite{InviteId: id2, ExpiresMs: 1})); err != nil {
		t.Fatal(err)
	}
	if err := apply(t, s, mkItem(t, pb.RecordType_INVITE_USED, other, &pb.InviteUsed{InviteId: id2, UserId: other})); !errors.Is(err, ErrInviteUnavailable) {
		t.Fatalf("expired: want ErrInviteUnavailable, got %v", err)
	}
	if _, err := s.Invite(ctx, make([]byte, 32)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown invite: %v", err)
	}
}

func TestMailboxAndAck(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	sender, rcpt := r16(), r16()
	env := mkItem(t, pb.RecordType_ENVELOPE, sender, &pb.Envelope{SenderUser: sender, SenderDevice: 1, Kind: pb.Envelope_SIGNAL,
		Recipients: []*pb.Recipient{{User: rcpt, Device: 1, Content: []byte{9}}}})
	if err := apply(t, s, env); err != nil {
		t.Fatal(err)
	}
	box, _ := s.Mailbox(ctx, rcpt, 1, 10)
	if len(box) != 1 {
		t.Fatalf("mailbox %d", len(box))
	}
	key := box[0].Key
	if err := apply(t, s, mkItem(t, pb.RecordType_ACK, sender, &pb.Ack{EnvelopeIds: [][]byte{key}, DeviceId: 1})); err != nil {
		t.Fatal(err)
	}
	if box, _ := s.Mailbox(ctx, rcpt, 1, 10); len(box) != 1 {
		t.Fatal("someone else's ACK removed the entry")
	}
	if err := apply(t, s, mkItem(t, pb.RecordType_ACK, rcpt, &pb.Ack{EnvelopeIds: [][]byte{key}, DeviceId: 1})); err != nil {
		t.Fatal(err)
	}
	if box, _ := s.Mailbox(ctx, rcpt, 1, 10); len(box) != 0 {
		t.Fatal("not removed")
	}
	if _, err := s.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("envelope should be deleted, got %v", err)
	}
	// re-applying the same envelope (e.g. via replication later) must not resurrect it
	_, _, _ = s.ApplyFrom(ctx, env.Record, env.Body, nil)
	if box, _ := s.Mailbox(ctx, rcpt, 1, 10); len(box) != 0 {
		t.Fatal("resurrected")
	}
}

func TestPrekeys(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	u, me, other := r16(), []byte("me-me-me-me-me-1"), []byte("other-other-oth1")
	pk := &pb.PreKeys{DeviceId: 1, RegistrationId: 42,
		SignedPrekey: &pb.SignedPreKey{Id: 1, PublicKey: []byte{1}, Signature: []byte{2}},
		KyberPrekey:  &pb.SignedPreKey{Id: 1, PublicKey: []byte{3}, Signature: []byte{4}},
		OneTime:      []*pb.OneTimePreKey{{Id: 10, PublicKey: []byte{5}, OwnerNode: me}, {Id: 11, PublicKey: []byte{6}, OwnerNode: other}}}
	if err := apply(t, s, mkItem(t, pb.RecordType_PREKEYS, u, pk)); err != nil {
		t.Fatal(err)
	}
	got, err := s.TakePrekeys(ctx, u, 1, me)
	if err != nil || got.RegistrationID != 42 || got.OneTime == nil || got.OneTime.Id != 10 || got.RemainingOwn != 0 {
		t.Fatalf("%+v %v", got, err)
	}
	got, _ = s.TakePrekeys(ctx, u, 1, me)
	if got.OneTime != nil {
		t.Fatal("one-time key handed out twice / foreign key handed out")
	}
	if got.Signed.Id != 1 || got.Kyber.Id != 1 {
		t.Fatal("signed/kyber missing")
	}
	if _, err := s.TakePrekeys(ctx, r16(), 1, me); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	// a new signed key replaces the old one; new one-time keys are added
	pk2 := &pb.PreKeys{DeviceId: 1, RegistrationId: 42,
		SignedPrekey: &pb.SignedPreKey{Id: 2, PublicKey: []byte{7}, Signature: []byte{8}},
		OneTime:      []*pb.OneTimePreKey{{Id: 12, PublicKey: []byte{9}, OwnerNode: me}}}
	if err := apply(t, s, mkItem(t, pb.RecordType_PREKEYS, u, pk2)); err != nil {
		t.Fatal(err)
	}
	got, _ = s.TakePrekeys(ctx, u, 1, me)
	if got.Signed.Id != 2 || got.Kyber.Id != 1 || got.OneTime == nil || got.OneTime.Id != 12 {
		t.Fatalf("after replace: %+v", got)
	}
}

func TestManifestTable(t *testing.T) {
	s, _ := open(t)
	netID := r16()
	if err := apply(t, s, mkItem(t, pb.RecordType_MANIFEST, netID, &pb.Manifest{Version: 3})); err != nil {
		t.Fatal(err)
	}
	if err := apply(t, s, mkItem(t, pb.RecordType_MANIFEST, netID, &pb.Manifest{Version: 5})); err != nil {
		t.Fatal(err)
	}
	v, raw, err := s.LatestManifest(context.Background())
	if err != nil || v != 5 || len(raw) == 0 {
		t.Fatalf("%d %v", v, err)
	}
}

func TestEmptyManifest(t *testing.T) {
	s, _ := open(t)
	if _, _, err := s.LatestManifest(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestBatchIsolation(t *testing.T) {
	// A failing request in the same writer batch must not affect the others.
	s, _ := open(t)
	ctx := context.Background()
	a := r16()
	if err := apply(t, s, mkItem(t, pb.RecordType_DIRECTORY_ENTRY, a, entry(a, "taken", 1))); err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		i := i
		go func() {
			u := r16()
			name := "free_" + string(rune('a'+i))
			if i%2 == 0 {
				name = "taken"
			}
			errs <- apply(t, s, mkItem(t, pb.RecordType_DIRECTORY_ENTRY, u, entry(u, name, 1)))
		}()
	}
	var ok, taken int
	for i := 0; i < 20; i++ {
		switch err := <-errs; {
		case err == nil:
			ok++
		case errors.Is(err, ErrUsernameTaken):
			taken++
		default:
			t.Fatal(err)
		}
	}
	all, _ := s.DirectoryEntries(ctx)
	if ok != 10 || taken != 10 || len(all) != 11 {
		t.Fatalf("ok=%d taken=%d entries=%d", ok, taken, len(all))
	}
}
