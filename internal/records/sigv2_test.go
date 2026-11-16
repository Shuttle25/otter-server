package records

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

func TestSigV2CrossNetworkAndCutover(t *testing.T) {
	netA, _, _ := ed25519.GenerateKey(nil)
	netB, _, _ := ed25519.GenerateKey(nil)
	userPub, userPriv, _ := ed25519.GenerateKey(nil)
	uid := keys.ID16(userPub)
	users := fakeUsers{string(uid): {Pub: userPub}} // the same key is a member of both networks (seed reuse)
	ack := payload(&pb.Ack{EnvelopeIds: [][]byte{make([]byte, 32)}, DeviceId: 1})
	body := func(created int64) *pb.RecordBody {
		return &pb.RecordBody{Id: rid(), Type: pb.RecordType_ACK, Author: uid, CreatedMs: created, Payload: ack}
	}
	cut := now.Add(-time.Hour).UnixMilli()
	vA := &Validator{NetworkPub: netA, Users: users, Now: func() time.Time { return now }, V1Until: func() int64 { return cut }}
	vB := &Validator{NetworkPub: netB, Users: users, Now: func() time.Time { return now }, V1Until: func() int64 { return cut }}
	ctxA := SigContext{NetworkID: keys.ID16(netA), V2: true}

	recA, err := SignWith(body(now.UnixMilli()), userPriv, ctxA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vA.Validate(recA); err != nil {
		t.Fatalf("v2 for A rejected by A: %v", err)
	}
	if _, err := vB.Validate(recA); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("v2 for A accepted by B: %v", err)
	}
	if _, err := vA.Validate(mustSign(t, body(cut-1), userPriv)); err != nil {
		t.Fatalf("v1 before the cut-over rejected: %v", err)
	}
	if _, err := vA.Validate(mustSign(t, body(cut), userPriv)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("v1 at/after the cut-over accepted: %v", err)
	}
	vA.V1Until = nil // no cut-over yet: v1 is valid for everything
	if _, err := vA.Validate(mustSign(t, body(now.UnixMilli()), userPriv)); err != nil {
		t.Fatalf("v1 without cut-over rejected: %v", err)
	}
	if _, err := vA.Validate(recA); err != nil {
		t.Fatalf("v2 without cut-over rejected: %v", err)
	}
	v1 := mustSign(t, body(now.UnixMilli()), userPriv)
	if string(MessageV2(keys.ID16(netA), v1.Body)[:9]) != "otter-v2\x00" {
		t.Fatal("prefix")
	}
}

func TestSigV2VerifySig(t *testing.T) {
	net, _, _ := ed25519.GenerateKey(nil)
	pub, priv, _ := ed25519.GenerateKey(nil)
	netID := keys.ID16(net)
	body := []byte("body")
	v1 := ed25519.Sign(priv, body)
	v2 := ed25519.Sign(priv, MessageV2(netID, body))
	other := ed25519.Sign(priv, MessageV2(make([]byte, 16), body))
	cases := []struct {
		name           string
		sig            []byte
		created, until int64
		want           bool
	}{
		{"v2 no cut-over", v2, 5, 0, true},
		{"v2 after cut-over", v2, 50, 10, true},
		{"v1 no cut-over", v1, 50, 0, true},
		{"v1 before cut-over", v1, 9, 10, true},
		{"v1 at cut-over", v1, 10, 10, false},
		{"v2 for another network", other, 5, 0, false},
	}
	for _, c := range cases {
		if got := VerifySig(pub, netID, body, c.sig, c.created, c.until); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}
