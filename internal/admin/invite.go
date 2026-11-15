package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

const InvitePrefix = "otter://join/"

func EncodeInviteLink(b *pb.InviteBundle) (string, error) {
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(b)
	if err != nil {
		return "", err
	}
	return InvitePrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func DecodeInviteLink(link string) (*pb.InviteBundle, error) {
	if !strings.HasPrefix(link, InvitePrefix) {
		return nil, errors.New("not an otter invite link")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(link, InvitePrefix))
	if err != nil {
		return nil, fmt.Errorf("invite link: %w", err)
	}
	b := &pb.InviteBundle{}
	return b, proto.Unmarshal(raw, b)
}

type BootstrapResult struct {
	Record *pb.Record
	Link   string
	File   string
}

// BootstrapInvite creates a network-signed invite for the first member. The link carries the signed INVITE, so any
// node registers it; importing the record file on a node is optional.
func BootstrapInvite(dir string, pass []byte, now time.Time, ttl time.Duration) (*BootstrapResult, error) {
	if ttl <= 0 || ttl > records.MaxInviteTTL { // C8: every node refuses a longer-lived invite
		return nil, fmt.Errorf("invite ttl must be between 1s and %s", records.MaxInviteTTL)
	}
	st, err := LoadState(dir)
	if err != nil {
		return nil, err
	}
	mraw, err := os.ReadFile(filepath.Join(dir, "manifest.bin"))
	if err != nil {
		return nil, fmt.Errorf("no signed manifest (run 'manifest sign' first): %w", err)
	}
	var manifest pb.Record
	if err := proto.Unmarshal(mraw, &manifest); err != nil {
		return nil, err
	}
	priv, err := keys.ReadEncryptedKey(filepath.Join(dir, "network.key.enc"), pass)
	if err != nil {
		return nil, err
	}
	secret := make([]byte, 32)
	rand.Read(secret)
	sum := sha256.Sum256(secret)
	exp := now.Add(ttl).UnixMilli()
	inv, err := records.InvitePayload(secret, exp) // redeem_pub: the app proves the secret without sending it (D100)
	if err != nil {
		return nil, err
	}
	payload, err := proto.Marshal(inv)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 16)
	rand.Read(id)
	rec, err := records.Sign(&pb.RecordBody{Id: id, Type: pb.RecordType_INVITE, Author: keys.ID16(st.NetworkPub),
		CreatedMs: now.UnixMilli(), ExpiresMs: exp, Payload: payload}, priv)
	if err != nil {
		return nil, err
	}
	link, err := EncodeInviteLink(&pb.InviteBundle{NetworkPub: st.NetworkPub, Manifest: &manifest, Secret: secret, Invite: rec})
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "invites"), 0o700); err != nil {
		return nil, err
	}
	file := filepath.Join(dir, "invites", hex.EncodeToString(sum[:8])+".bin")
	raw, _ := proto.Marshal(rec)
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		return nil, err
	}
	return &BootstrapResult{Record: rec, Link: link, File: file}, nil
}
