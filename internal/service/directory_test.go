package service

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

func entryV(u *user, username, display string, version uint64, registered int64) *pb.DirectoryEntry {
	pub := u.priv.Public().(ed25519.PublicKey)
	return &pb.DirectoryEntry{UserId: u.id, Username: username, DisplayName: display, AccountPub: pub,
		IdentityPub: make([]byte, 33), IdentitySig: make([]byte, 64), Version: version, CanInvite: true, RegisteredMs: registered}
}

func TestUpdateDirectoryEntry(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna")
	boris := f.mustRegister(f.invite(anna, time.Hour), "boris")
	before := f.notes.dir
	upd := func(by *user, signer *user, e *pb.DirectoryEntry) error {
		return f.svc.UpdateDirectoryEntry(ctx, by.id, sign(t, pb.RecordType_DIRECTORY_ENTRY, signer.id, e, signer.priv))
	}
	if err := upd(anna, anna, entryV(anna, "anna", "Анна", 2, 1)); err != nil {
		t.Fatal(err)
	}
	if f.notes.dir != before+1 {
		t.Fatal("no directory notification")
	}
	if u, _ := f.svc.Store.UserByID(ctx, anna.id); u.Version != 2 || u.Username != "anna" {
		t.Fatalf("%+v", u)
	}
	if err := upd(anna, anna, entryV(anna, "anna", "x", 2, 1)); !errors.Is(err, ErrConflict) {
		t.Fatalf("same version: %v", err)
	}
	if err := upd(anna, anna, entryV(anna, "anya", "x", 3, 1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("username change: %v", err)
	}
	if err := upd(anna, boris, entryV(boris, "boris", "x", 2, 1)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("someone else's entry: %v", err)
	}
	ack := sign(t, pb.RecordType_ACK, anna.id, &pb.Ack{EnvelopeIds: [][]byte{make([]byte, 32)}, DeviceId: 1}, anna.priv)
	if err := f.svc.UpdateDirectoryEntry(ctx, anna.id, ack); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-directory record: %v", err)
	}
	// a valid entry of a user this node doesn't know yet
	pub, priv, _ := ed25519.GenerateKey(nil)
	ghost := &user{id: keys.ID16(pub), priv: priv}
	if err := upd(ghost, ghost, entryV(ghost, "ghost", "g", 2, 1)); !errors.Is(err, ErrRetryLater) {
		t.Fatalf("unknown user: %v", err)
	}
}

// A user whose username was suffixed by a replicated clash updates with the original username.
func TestUpdateDirectoryEntrySuffixedUser(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna")
	// another "anna" registered earlier on a peer arrives by replication: our anna becomes anna#<hex>
	pub, priv, _ := ed25519.GenerateKey(nil)
	other := &user{id: keys.ID16(pub), priv: priv}
	early := entryV(other, "anna", "Other", 1, 0)
	p, _ := proto.Marshal(early)
	body := &pb.RecordBody{Id: r16(), Type: pb.RecordType_DIRECTORY_ENTRY, Author: other.id, CreatedMs: 1, Payload: p} // registered long ago
	rec, err := records.Sign(body, other.priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.Store.ApplyReplicated(ctx, rec, body, r16()); err != nil {
		t.Fatal(err)
	}
	if u, _ := f.svc.Store.UserByID(ctx, anna.id); u.Username != "anna#"+hex.EncodeToString(anna.id[:4]) {
		t.Fatalf("setup: %s", u.Username)
	}
	if err := f.svc.UpdateDirectoryEntry(ctx, anna.id, sign(t, pb.RecordType_DIRECTORY_ENTRY, anna.id, entryV(anna, "anna", "Анна", 2, time.Now().UnixMilli()), anna.priv)); err != nil {
		t.Fatalf("suffixed user's update: %v", err)
	}
}
