package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
	"ottermsg/server/internal/store"
)

// hostile is a peer node id that relays and replays records (a hostile node in the mesh).
var hostile = []byte("hostile-node-000")

func prekeysRec(t *testing.T, u *user, owner []byte, first uint32, n int) *pb.Record {
	pk := &pb.PreKeys{DeviceId: 1, RegistrationId: 5}
	for i := 0; i < n; i++ {
		pk.OneTime = append(pk.OneTime, &pb.OneTimePreKey{Id: first + uint32(i), PublicKey: make([]byte, 33), OwnerNode: owner})
	}
	return sign(t, pb.RecordType_PREKEYS, u.id, pk, u.priv)
}

func TestPrekeyBudgetAgainstHostilePeer(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna") // 12 keys (ids 100–111) owned by this node
	self := f.svc.NodeID
	var flood []*pb.Record
	for i := 0; i < 5; i++ {
		r := prekeysRec(t, anna, self, uint32(1000+200*i), 200)
		flood = append(flood, r)
		if _, err := f.svc.ApplyReplicated(ctx, hostile, r); err != nil {
			t.Fatalf("batch %d: %v", i, err)
		}
	}
	count := func() int { m, _ := f.svc.Store.PrekeyCounts(ctx, anna.id, 1); return m[string(self)] }
	if n := count(); n != store.MaxLiveOneTime {
		t.Fatalf("%d live one-time keys, want %d", n, store.MaxLiveOneTime)
	}
	got, err := f.svc.Store.TakePrekeys(ctx, anna.id, 1, self)
	if err != nil || got.OneTime == nil || got.OneTime.Id != 1800 {
		t.Fatalf("handed out %v, %v; want id 1800 (the newest 200 kept)", got.OneTime, err)
	}

	later := time.Now().Add(2 * time.Hour).UnixMilli()
	st, err := f.svc.Store.Expire(ctx, later)
	if err != nil {
		t.Fatal(err)
	}
	if st.Compacted != 4 {
		t.Fatalf("compacted %d PREKEYS records, want 4", st.Compacted)
	}
	for i, r := range flood {
		_, err := f.svc.Store.Get(ctx, recordKey(t, r))
		if gone := errors.Is(err, store.ErrNotFound); gone != (i < 4) {
			t.Fatalf("record %d: gone=%v", i, gone)
		}
	}

	// replay inside the tombstone window: ignored
	if applied, err := f.svc.ApplyReplicated(ctx, hostile, flood[0]); err != nil || applied {
		t.Fatalf("replay applied=%v err=%v", applied, err)
	}
	if n := count(); n != store.MaxLiveOneTime-1 {
		t.Fatalf("after replay: %d", n)
	}
	// after the tombstone lapsed: stored again, but the floor keeps its consumed keys out
	if _, err := f.svc.Store.Expire(ctx, time.Now().Add(31*24*time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if applied, err := f.svc.ApplyReplicated(ctx, hostile, flood[0]); err != nil || !applied {
		t.Fatalf("replay after the tombstone lapsed: applied=%v err=%v", applied, err)
	}
	if n := count(); n != store.MaxLiveOneTime-1 {
		t.Fatalf("resurrected keys: %d live", n)
	}
	if got, _ := f.svc.Store.TakePrekeys(ctx, anna.id, 1, self); got.OneTime.Id != 1801 {
		t.Fatalf("a dropped key came back: %d", got.OneTime.Id)
	}
	// the next janitor removes the replayed record again
	if st, err := f.svc.Store.Expire(ctx, time.Now().Add(2*time.Hour).UnixMilli()); err != nil || st.Compacted != 1 {
		t.Fatalf("second janitor compacted %d, %v; want 1", st.Compacted, err)
	}
	if _, err := f.svc.Store.Get(ctx, recordKey(t, flood[0])); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("replayed record kept: %v", err)
	}
}

func TestPrekeyNewInstallResetsFloor(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna")
	self := f.svc.NodeID
	for i := 0; i < 12; i++ { // consume ids 100–111
		if _, err := f.svc.Store.TakePrekeys(ctx, anna.id, 1, self); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.svc.Store.Expire(ctx, time.Now().Add(2*time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	// a restore: new install, ids start again at 1 (InstallGuard.finishRestore)
	pk := &pb.PreKeys{DeviceId: 1, RegistrationId: 6, InstalledMs: time.Now().UnixMilli(),
		SignedPrekey: &pb.SignedPreKey{Id: 1, PublicKey: make([]byte, 33), Signature: make([]byte, 64)},
		KyberPrekey:  &pb.SignedPreKey{Id: 1, PublicKey: make([]byte, 1569), Signature: make([]byte, 64)}}
	for i := 0; i < 50; i++ {
		pk.OneTime = append(pk.OneTime, &pb.OneTimePreKey{Id: uint32(1 + i), PublicKey: make([]byte, 33), OwnerNode: self})
	}
	if _, err := f.svc.Submit(ctx, anna.id, sign(t, pb.RecordType_PREKEYS, anna.id, pk, anna.priv), pb.RecordType_PREKEYS); err != nil {
		t.Fatal(err)
	}
	if m, _ := f.svc.Store.PrekeyCounts(ctx, anna.id, 1); m[string(self)] != 50 {
		t.Fatalf("new install keys below the old floor were dropped: %v", m)
	}
}

func signAt(t *testing.T, typ pb.RecordType, u *user, payload proto.Message, created int64) *pb.Record {
	p, _ := proto.Marshal(payload)
	r, err := records.Sign(&pb.RecordBody{Id: r16(), Type: typ, Author: u.id, CreatedMs: created, Payload: p}, u.priv)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestPushTokenNewestRecordOnly(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna")
	now := time.Now()
	var recs []*pb.Record
	for i := 1; i <= 3; i++ {
		r := signAt(t, pb.RecordType_PUSH_TOKEN, anna, &pb.PushToken{DeviceId: 1, Kind: pb.PushToken_FCM, Token: fmt.Sprintf("tok%d", i)},
			now.Add(time.Duration(i-4)*time.Minute).UnixMilli())
		recs = append(recs, r)
		if _, err := f.svc.Submit(ctx, anna.id, r, pb.RecordType_PUSH_TOKEN); err != nil {
			t.Fatal(err)
		}
	}
	for i, r := range recs[:2] {
		if _, err := f.svc.Store.Get(ctx, recordKey(t, r)); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("superseded token record %d kept: %v", i, err)
		}
	}
	if _, err := f.svc.Store.Expire(ctx, now.UnixMilli()); err != nil { // orphan oplog rows go
		t.Fatal(err)
	}
	if _, err := f.svc.ApplyReplicated(ctx, hostile, recs[0]); err != nil {
		t.Fatal(err)
	}
	if tok, _ := f.svc.Store.PushToken(ctx, anna.id, 1); tok != "tok3" {
		t.Fatalf("token = %q after a replay", tok)
	}
	if _, err := f.svc.Store.Get(ctx, recordKey(t, recs[0])); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("replayed old token record stored")
	}
	// M9.1 (D94): a withdrawn token is the newest record; the older token can still not come back, also after the
	// node forgot the row (FCM said UNREGISTERED)
	off := signAt(t, pb.RecordType_PUSH_TOKEN, anna, &pb.PushToken{DeviceId: 1, Kind: pb.PushToken_FCM, Withdrawn: true}, now.UnixMilli())
	if _, err := f.svc.Submit(ctx, anna.id, off, pb.RecordType_PUSH_TOKEN); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Store.DropPushToken(ctx, anna.id, 1, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ApplyReplicated(ctx, hostile, recs[2]); err != nil {
		t.Fatal(err)
	}
	if tok, _ := f.svc.Store.PushToken(ctx, anna.id, 1); tok != "" {
		t.Fatalf("withdrawn token came back: %q", tok)
	}
}

func TestSubmitRates(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna")
	for typ, lim := range submitRates {
		for i := 0; i <= lim; i++ {
			var r *pb.Record
			if typ == pb.RecordType_PUSH_TOKEN {
				r = sign(t, typ, anna.id, &pb.PushToken{DeviceId: 1, Kind: pb.PushToken_FCM, Token: fmt.Sprint(i)}, anna.priv)
			} else {
				r = prekeysRec(t, anna, f.svc.NodeID, uint32(1000+i), 1)
			}
			_, err := f.svc.Submit(ctx, anna.id, r, typ)
			if i < lim && err != nil || i == lim && !errors.Is(err, ErrQuota) {
				t.Fatalf("%v %d: %v", typ, i, err)
			}
		}
	}
	future := inviteRec(t, anna, time.Now().Add(10*time.Minute), time.Hour)
	if _, err := f.svc.Submit(ctx, anna.id, future, pb.RecordType_INVITE); !errors.Is(err, ErrInvalid) {
		t.Fatalf("future-dated record: %v", err)
	}
}

func inviteRec(t *testing.T, u *user, created time.Time, ttl time.Duration) *pb.Record {
	secret := make([]byte, 32)
	rand.Read(secret)
	inv, err := records.InvitePayload(secret, created.Add(ttl).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	return signAt(t, pb.RecordType_INVITE, u, inv, created.UnixMilli())
}

func TestInviteBudgetLocalAndReplicated(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna")
	boris := f.mustRegister(f.invite(nil, time.Hour), "boris")
	now := time.Now()
	for i := 0; i < store.MaxLiveInvites; i++ {
		if _, err := f.svc.Submit(ctx, anna.id, inviteRec(t, anna, now.Add(-time.Duration(i)*time.Second), 7*24*time.Hour), pb.RecordType_INVITE); err != nil {
			t.Fatalf("invite %d: %v", i, err)
		}
	}
	if _, err := f.svc.Submit(ctx, anna.id, inviteRec(t, anna, now.Add(time.Second), 7*24*time.Hour), pb.RecordType_INVITE); !errors.Is(err, ErrQuota) {
		t.Fatalf("51st invite: %v", err)
	}
	// a hostile peer relays 60 of boris's invites, newest first: the 50 oldest stay
	var oldest, newest []*pb.Record
	for i := 0; i < 60; i++ {
		r := inviteRec(t, boris, now.Add(-time.Duration(i)*time.Minute), 7*24*time.Hour)
		if i >= 10 {
			oldest = append(oldest, r)
		} else {
			newest = append(newest, r)
		}
		if _, err := f.svc.ApplyReplicated(ctx, hostile, r); err != nil {
			t.Fatalf("replicated invite %d: %v", i, err)
		}
	}
	if n, _ := f.svc.Store.LiveInvites(ctx, boris.id, now.UnixMilli()); n != store.MaxLiveInvites {
		t.Fatalf("%d live invites for boris", n)
	}
	for _, r := range oldest {
		if _, err := f.svc.Store.Get(ctx, recordKey(t, r)); err != nil {
			t.Fatalf("an invite within the rank was dropped: %v", err)
		}
	}
	for _, r := range newest {
		if _, err := f.svc.Store.Get(ctx, recordKey(t, r)); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("an invite past the rank was kept: %v", err)
		}
	}
	if _, err := f.svc.Submit(ctx, anna.id, inviteRec(t, anna, now, 31*24*time.Hour), pb.RecordType_INVITE); !errors.Is(err, ErrInvalid) {
		t.Fatalf("31-day invite: %v", err)
	}
	if _, err := f.svc.Store.Expire(ctx, now.Add(9*24*time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.svc.Store.LiveInvites(ctx, anna.id, 0); n != 0 {
		t.Fatalf("%d expired invites kept", n)
	}
	for _, r := range oldest {
		if _, err := f.svc.Store.Get(ctx, recordKey(t, r)); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("expired invite record kept")
		}
	}
	// a hostile peer replays an expired invite after the janitor: not stored again
	if _, err := f.svc.ApplyReplicated(ctx, hostile, oldest[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Store.Get(ctx, recordKey(t, oldest[0])); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("replayed expired invite stored")
	}
}
