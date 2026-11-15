package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

func installRec(t *testing.T, author []byte, rid uint32, inst int64, k ed25519.PrivateKey) *pb.Record {
	return sign(t, pb.RecordType_INSTALL, author, &pb.Install{RegistrationId: rid, InstalledMs: inst}, k)
}

func (f *fx) login(u *user) *pb.LoginResponse {
	nonce := make([]byte, 32)
	rand.Read(nonce)
	ts := time.Now().UnixMilli()
	resp, err := f.svc.VerifyLogin(context.Background(), nonce, &pb.LoginRequest{UserId: u.id, DeviceId: 1, TsMs: ts,
		Signature: ed25519.Sign(u.priv, keys.AuthMessage(f.svc.NodeID, nonce, ts))})
	if err != nil {
		f.t.Fatal(err)
	}
	return resp
}

// C14: a hostile peer can neither plant nor roll back an account's install; the newest signed INSTALL wins and is
// what auth.login hands to the phone.
func TestInstallRecordFromHostilePeer(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna")
	boris := f.mustRegister(f.invite(anna, time.Hour), "boris")
	now := time.Now().UnixMilli()
	_, mallory, _ := ed25519.GenerateKey(nil)

	for name, rec := range map[string]*pb.Record{
		"signed by another key":    installRec(t, anna.id, 77, now, mallory),
		"signed by another member": installRec(t, anna.id, 77, now, boris.priv),
		"far future":               installRec(t, anna.id, 77, now+time.Hour.Milliseconds(), anna.priv),
		"no registration id":       installRec(t, anna.id, 0, now, anna.priv),
		"registration id too big":  installRec(t, anna.id, 16381, now, anna.priv),
	} {
		if _, err := f.svc.ApplyReplicated(ctx, peerID, rec); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	_, ghostPriv, _ := ed25519.GenerateKey(nil)
	ghost := keys.ID16(ghostPriv.Public().(ed25519.PublicKey))
	if _, err := f.svc.ApplyReplicated(ctx, peerID, installRec(t, ghost, 7, now, ghostPriv)); !errors.Is(err, ErrRetryLater) {
		t.Fatalf("unknown author: %v", err)
	}
	if resp := f.login(anna); resp.Install != nil {
		t.Fatalf("an invalid INSTALL reached the login answer: %+v", resp)
	}

	newer := installRec(t, anna.id, 77, now, anna.priv)
	if applied, err := f.svc.ApplyReplicated(ctx, peerID, newer); err != nil || !applied {
		t.Fatalf("genuine install: %v %v", applied, err)
	}
	if _, err := f.svc.ApplyReplicated(ctx, peerID, installRec(t, anna.id, 66, now-1000, anna.priv)); err != nil {
		t.Fatalf("replayed older install: %v", err) // accepted as a record, but it must not win
	}
	resp := f.login(anna)
	if resp.Install == nil || !proto.Equal(resp.Install, newer) || resp.RegistrationId != 77 || resp.InstalledMs != now {
		t.Fatalf("login: %+v", resp)
	}
	// the replaced install's one-time prekeys are gone (D52)
	if b, err := f.svc.FetchPrekeys(ctx, &pb.PreKeyFetchRequest{UserId: anna.id, DeviceId: 1}); err == nil && b.OneTime != nil {
		t.Fatal("one-time prekey of the replaced install handed out")
	}
	// the same install published again keeps the stored record
	if _, err := f.svc.Submit(ctx, anna.id, installRec(t, anna.id, 77, now, anna.priv), pb.RecordType_INSTALL); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(f.login(anna).Install, newer) {
		t.Fatal("an equal install replaced the stored record")
	}
	// boris' install never touches anna's
	if _, err := f.svc.Submit(ctx, boris.id, installRec(t, boris.id, 5, now+1, boris.priv), pb.RecordType_INSTALL); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(f.login(anna).Install, newer) {
		t.Fatal("boris' install changed anna's")
	}
}
