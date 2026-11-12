package store

import (
	"context"
	"testing"

	pb "ottermsg/server/internal/proto/otterv1"
)

func pushItem(t *testing.T, user []byte, token string, created int64) Item {
	it := mkItem(t, pb.RecordType_PUSH_TOKEN, user, &pb.PushToken{DeviceId: 1, Kind: pb.PushToken_FCM, Token: token})
	it.Body.CreatedMs = created
	return it
}

func TestPushTokenNewestWins(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	u := r16()
	if tok, err := s.PushToken(ctx, u, 1); err != nil || tok != "" {
		t.Fatalf("empty: %q %v", tok, err)
	}
	for _, it := range []Item{pushItem(t, u, "t2", 200), pushItem(t, u, "t1", 100)} { // older arrives second
		if err := apply(t, s, it); err != nil {
			t.Fatal(err)
		}
	}
	if tok, _ := s.PushToken(ctx, u, 1); tok != "t2" {
		t.Fatalf("newest should win, got %q", tok)
	}
	if err := s.DropPushToken(ctx, u, 1, "t1"); err != nil { // stale token: no effect
		t.Fatal(err)
	}
	if tok, _ := s.PushToken(ctx, u, 1); tok != "t2" {
		t.Fatalf("drop of a stale token removed %q", tok)
	}
	if err := s.DropPushToken(ctx, u, 1, "t2"); err != nil {
		t.Fatal(err)
	}
	if tok, _ := s.PushToken(ctx, u, 1); tok != "" {
		t.Fatalf("dropped token still there: %q", tok)
	}
	if err := apply(t, s, pushItem(t, u, "t3", 300)); err != nil {
		t.Fatal(err)
	}
	if tok, _ := s.PushToken(ctx, u, 1); tok != "t3" {
		t.Fatalf("new token after drop: %q", tok)
	}
}
