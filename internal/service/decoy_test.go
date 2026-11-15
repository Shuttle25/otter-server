package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
)

func decoyMeta(u *user, salt []byte) *pb.BackupMeta {
	v := make([]byte, 32)
	rand.Read(v)
	return &pb.BackupMeta{Salt: salt, KdfMKib: 65536, KdfT: 3, KdfP: 1, AuthVerifier: v,
		BlobKey: append(append([]byte{}, u.id...), make([]byte, 16)...)}
}

// C20: a member without a backup answers backup.auth exactly like one with a backup, on every node.
func TestBackupDecoy(t *testing.T) {
	f1 := newFx(t)
	withBlobs(t, f1)
	ctx := context.Background()
	anna := f1.mustRegister(f1.invite(nil, time.Hour), "anna")
	salt := bytes.Repeat([]byte{7}, 16)
	decoy := sign(t, pb.RecordType_BACKUP_META, anna.id, decoyMeta(anna, salt), anna.priv)
	if err := f1.svc.PublishBackup(ctx, anna.id, decoy); err != nil {
		t.Fatalf("decoy: %v", err)
	}
	a1, err := f1.svc.BackupAuth(ctx, "anna")
	if err != nil || !bytes.Equal(a1.Salt, salt) || a1.KdfMKib != 65536 || a1.KdfT != 3 || a1.KdfP != 1 {
		t.Fatalf("auth: %+v %v", a1, err)
	}

	// a second node that got the entry and the decoy by replication answers the same
	f2 := newFx(t)
	f2.svc.NetworkPub = f1.svc.NetworkPub
	entry, _ := f1.svc.Store.UserByID(ctx, anna.id)
	var entryRec pb.Record
	proto.Unmarshal(entry.EntryRaw, &entryRec)
	if _, err := f2.svc.ApplyReplicated(ctx, peerID, &entryRec); err != nil {
		t.Fatal(err)
	}
	if applied, err := f2.svc.ApplyReplicated(ctx, peerID, decoy); err != nil || !applied {
		t.Fatalf("replicated decoy: %v %v", applied, err)
	}
	if a2, _ := f2.svc.BackupAuth(ctx, "anna"); !proto.Equal(a1, a2) {
		t.Fatalf("node answers differ: %+v %+v", a1, a2)
	}

	// any secret fails like a wrong password and is counted
	if _, _, err := f1.svc.BackupFetch(ctx, "anna", "203.0.113.5", make([]byte, 32)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("fetch against a decoy: %v", err)
	}
	if n, _ := f1.svc.Store.AuthFailures(ctx, "anna", 0); n != 1 {
		t.Fatalf("failures %d", n)
	}

	// shapes a hostile peer might send
	_, mallory, _ := ed25519.GenerateKey(nil)
	sized, named := decoyMeta(anna, salt), decoyMeta(anna, salt)
	sized.Size = 10
	named.BlobKey[31] = 1
	for name, rec := range map[string]*pb.Record{
		"decoy with a size":    sign(t, pb.RecordType_BACKUP_META, anna.id, sized, anna.priv),
		"decoy naming a blob":  sign(t, pb.RecordType_BACKUP_META, anna.id, named, anna.priv),
		"decoy by another key": sign(t, pb.RecordType_BACKUP_META, anna.id, decoyMeta(anna, salt), mallory),
	} {
		if _, err := f2.svc.ApplyReplicated(ctx, peerID, rec); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}

	// a real backup replaces the decoy; a later decoy never replaces a real backup
	realSalt := f1.publishBackup(anna, bytes.Repeat([]byte{1}, 32))
	later := sign(t, pb.RecordType_BACKUP_META, anna.id, decoyMeta(anna, bytes.Repeat([]byte{8}, 16)), anna.priv)
	if err := f1.svc.PublishBackup(ctx, anna.id, later); err != nil {
		t.Fatal(err)
	}
	if a3, _ := f1.svc.BackupAuth(ctx, "anna"); !bytes.Equal(a3.Salt, realSalt) {
		t.Fatalf("decoy replaced the real backup: %x", a3.Salt)
	}
}
