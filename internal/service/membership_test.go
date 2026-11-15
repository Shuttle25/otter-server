package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

type stubTurn struct{}

func (stubTurn) Issue([]byte, time.Time) *pb.TurnCredentials {
	return &pb.TurnCredentials{Username: "u"}
}

func TestRevokedGetsNoTurnAndRecordsAreSkipped(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	f.svc.Turn = stubTurn{}
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna")
	if _, err := f.svc.TurnCredentials(ctx, anna.id); err != nil {
		t.Fatal(err)
	}
	rev := sign(t, pb.RecordType_REVOCATION, keys.ID16(f.svc.NetworkPub), &pb.Revocation{UserId: anna.id}, f.netPriv)
	if err := f.svc.PublishNetworkRecord(ctx, rev); err != nil {
		t.Fatal(err)
	}
	if len(f.notes.revoked) != 1 || string(f.notes.revoked[0]) != string(anna.id) {
		t.Fatalf("sessions of the revoked user not closed: %x", f.notes.revoked)
	}
	if err := f.svc.PublishNetworkRecord(ctx, rev); err != nil { // the same record again: idempotent
		t.Fatal(err)
	}
	if _, err := f.svc.TurnCredentials(ctx, anna.id); !errors.Is(err, ErrRevoked) {
		t.Fatalf("turn for revoked: %v", err)
	}
	if _, err := f.svc.TurnCredentials(ctx, r16()); !errors.Is(err, ErrRevoked) {
		t.Fatalf("turn for an unknown user: %v", err)
	}
	inv := sign(t, pb.RecordType_INVITE, anna.id, &pb.Invite{InviteId: make([]byte, 32), ExpiresMs: time.Now().Add(time.Hour).UnixMilli()}, anna.priv)
	if applied, err := f.svc.ApplyReplicated(ctx, r16(), inv); err != nil || applied {
		t.Fatalf("revoked author's invite: applied=%v err=%v", applied, err)
	}
	if err := f.svc.PublishNetworkRecord(ctx, f.manifestRec(5)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("manifest through network.publish: %v", err)
	}
}
