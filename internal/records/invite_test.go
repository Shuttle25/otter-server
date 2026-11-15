package records

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

func TestRedeemFillsChain(t *testing.T) {
	secret := bytes.Repeat([]byte{9}, 32)
	inv, err := InvitePayload(secret, 1234)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(secret)
	if !bytes.Equal(inv.InviteId, sum[:]) || inv.ExpiresMs != 1234 || len(inv.RedeemPub) != ed25519.PublicKeySize {
		t.Fatalf("payload %v", inv)
	}
	rec := &pb.Record{Body: []byte("signed invite body"), Signature: []byte("sig")}
	acc := bytes.Repeat([]byte{3}, 32)
	e := &pb.DirectoryEntry{UserId: keys.ID16(acc), AccountPub: acc}
	if err := Redeem(e, rec, secret); err != nil {
		t.Fatal(err)
	}
	var got pb.Record
	if err := proto.Unmarshal(e.InviteRecord, &got); err != nil || !proto.Equal(&got, rec) {
		t.Fatalf("invite_record %x", e.InviteRecord)
	}
	if !ed25519.Verify(inv.RedeemPub, keys.RedeemMessage(inv.InviteId, e.UserId, e.AccountPub), e.InviteProof) {
		t.Fatal("proof does not verify with redeem_pub")
	}
	// A different secret (someone who only saw the INVITE record) cannot make a valid proof.
	other := &pb.DirectoryEntry{UserId: e.UserId, AccountPub: e.AccountPub}
	if err := Redeem(other, rec, bytes.Repeat([]byte{8}, 32)); err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(inv.RedeemPub, keys.RedeemMessage(inv.InviteId, e.UserId, e.AccountPub), other.InviteProof) {
		t.Fatal("proof from a wrong secret verifies")
	}
	if err := Redeem(e, rec, secret[:31]); err == nil {
		t.Fatal("short secret accepted")
	}
}
