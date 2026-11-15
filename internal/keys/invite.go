package keys

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

const (
	InfoInviteRedeem = "otter/invite-redeem/v1"
	redeemContext    = "otter-invite-redeem-v1"
)

// InviteRedeemKey derives an invite's one-time signing key from the 32-byte secret in the link (D100). Only the
// invitee's phone holds the secret; nodes see the public key (in the INVITE) and one signature (the proof).
// Must match Android InviteKeys.redeemKey.
func InviteRedeemKey(secret []byte) (ed25519.PrivateKey, error) {
	if len(secret) != 32 {
		return nil, fmt.Errorf("invite secret must be 32 bytes, got %d", len(secret))
	}
	k, err := hkdf.Key(sha256.New, secret, nil, InfoInviteRedeem, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(k), nil
}

// RedeemMessage is what the redeem key signs: it binds one redemption to one account.
// Must match Android InviteKeys.redeemMessage.
func RedeemMessage(inviteID, userID, accountPub []byte) []byte {
	m := make([]byte, 0, len(redeemContext)+len(inviteID)+len(userID)+len(accountPub))
	m = append(m, redeemContext...)
	m = append(m, inviteID...)
	m = append(m, userID...)
	return append(m, accountPub...)
}
