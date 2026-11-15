package records

import (
	"crypto/ed25519"
	"crypto/sha256"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

// InvitePayload is the INVITE payload for a link secret (D100).
func InvitePayload(secret []byte, expiresMs int64) (*pb.Invite, error) {
	k, err := keys.InviteRedeemKey(secret)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(secret)
	return &pb.Invite{InviteId: sum[:], ExpiresMs: expiresMs, RedeemPub: k.Public().(ed25519.PublicKey)}, nil
}

// Redeem fills the invite chain of a new account's directory entry: the inviter's signed INVITE and the proof made
// with the key derived from the link secret. e.UserId and e.AccountPub must be set.
func Redeem(e *pb.DirectoryEntry, invite *pb.Record, secret []byte) error {
	k, err := keys.InviteRedeemKey(secret)
	if err != nil {
		return err
	}
	raw, err := proto.Marshal(invite)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(secret)
	e.InviteRecord = raw
	e.InviteProof = ed25519.Sign(k, keys.RedeemMessage(sum[:], e.UserId, e.AccountPub))
	return nil
}
