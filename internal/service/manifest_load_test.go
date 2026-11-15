package service

import (
	"context"
	"testing"
)

// A manifest committed by replication whose load was cut short (the peer session's context ended between the commit
// and LoadManifest) must still become current: the side effects of a committed record outlive the session, and a later
// import of the same manifest reloads it instead of reporting "already applied" and stopping there.
func TestCommittedManifestAlwaysLoads(t *testing.T) {
	f := newFx(t)
	f.withManifest(1)
	ctx := context.Background()

	// half 1: afterApply with a session context that is already gone
	rec2 := f.manifestRec(2)
	body2, err := f.svc.validator(nil).Validate(rec2)
	if err != nil {
		t.Fatal(err)
	}
	if _, applied, err := f.svc.Store.ApplyReplicated(ctx, rec2, body2, peerID); err != nil || !applied {
		t.Fatalf("store v2: %v %v", applied, err)
	}
	gone, cancel := context.WithCancel(ctx)
	cancel()
	f.svc.afterApply(gone, body2, peerID)
	if v := f.svc.CurrentManifest().GetVersion(); v != 2 {
		t.Fatalf("after a cut-short load: current manifest v%d, want v2", v)
	}

	// half 2: the record is stored but was never loaded (e.g. a crash between commit and load); importing it again loads it
	rec3 := f.manifestRec(3)
	body3, err := f.svc.validator(nil).Validate(rec3)
	if err != nil {
		t.Fatal(err)
	}
	if _, applied, err := f.svc.Store.ApplyReplicated(ctx, rec3, body3, peerID); err != nil || !applied {
		t.Fatalf("store v3: %v %v", applied, err)
	}
	if v := f.svc.CurrentManifest().GetVersion(); v != 2 {
		t.Fatalf("precondition: v%d loaded without afterApply", v)
	}
	if _, err := f.svc.ImportRecord(ctx, rec3); err != nil {
		t.Fatal(err)
	}
	if v := f.svc.CurrentManifest().GetVersion(); v != 3 {
		t.Fatalf("re-import of a stored manifest: current v%d, want v3", v)
	}
}
