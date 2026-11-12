package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

func TestPushRegister(t *testing.T) {
	n := startNode(t)
	ctx := context.Background()
	newUser := func(name string) (*acct, *client) {
		secret := make([]byte, 32)
		rand.Read(secret)
		sum := sha256.Sum256(secret)
		inv := sign(t, pb.RecordType_INVITE, keys.ID16(n.svc.NetworkPub), &pb.Invite{InviteId: sum[:], ExpiresMs: time.Now().Add(time.Hour).UnixMilli()}, n.netPriv)
		if _, err := n.svc.ImportRecord(ctx, inv); err != nil {
			t.Fatal(err)
		}
		c := dial(t, n)
		a, req := registerReq(t, n, secret, name)
		if st, msg := c.call("register", req, nil); st != pb.Status_STATUS_OK {
			t.Fatalf("register %s: %v %s", name, st, msg)
		}
		return a, c
	}
	anna, ca := newUser("anna")
	boris, cb := newUser("boris")
	cb.c.CloseNow()
	login(t, ca, anna)

	tok := func(a *acct, token string) *pb.RecordRequest {
		return &pb.RecordRequest{Record: sign(t, pb.RecordType_PUSH_TOKEN, a.id,
			&pb.PushToken{DeviceId: 1, Kind: pb.PushToken_FCM, Token: token}, a.priv)}
	}
	if st, msg := ca.call("push.register", tok(anna, "anna-token"), nil); st != pb.Status_STATUS_OK {
		t.Fatalf("push.register: %v %s", st, msg)
	}
	if got, err := n.svc.Store.PushToken(ctx, anna.id, 1); err != nil || got != "anna-token" {
		t.Fatalf("stored token %q, %v", got, err)
	}
	if st, _ := ca.call("push.register", tok(boris, "stolen"), nil); st != pb.Status_STATUS_UNAUTHORIZED {
		t.Fatalf("token signed by another user: %v", st)
	}
	if st, _ := ca.call("push.register", &pb.RecordRequest{Record: sign(t, pb.RecordType_ACK, anna.id,
		&pb.Ack{EnvelopeIds: [][]byte{make([]byte, 32)}}, anna.priv)}, nil); st != pb.Status_STATUS_INVALID {
		t.Fatalf("non-token record: %v", st)
	}

	gw := n.svc.Notify.(*Gateway)
	if !gw.Online(anna.id, 1) {
		t.Fatal("anna is logged in: Online must be true")
	}
	if gw.Online(boris.id, 1) {
		t.Fatal("boris has no session: Online must be false")
	}
}
