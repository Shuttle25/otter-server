package service

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "ottermsg/server/internal/proto/otterv1"
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
