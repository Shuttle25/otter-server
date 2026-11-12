package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/blobs"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

func withBlobs(t *testing.T, f *fx) {
	bd, err := blobs.New(filepath.Join(t.TempDir(), "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	f.svc.Blobs = bd
}

// persistentBlob creates a one-chunk persistent blob for u and returns its key.
func (f *fx) persistentBlob(u *user) ([]byte, error) {
	h := sha256.Sum256([]byte("backup"))
	p, _ := proto.Marshal(&pb.BlobMeta{Size: 1000, ChunkSize: records.BlobChunkSize, ChunkSha256: [][]byte{h[:]}, Persistent: true})
	id := r16()
	rec, _ := records.Sign(&pb.RecordBody{Id: id, Type: pb.RecordType_BLOB_META, Author: u.id, CreatedMs: time.Now().UnixMilli(), Payload: p}, u.priv)
	if _, err := f.svc.CreateBlob(context.Background(), u.id, rec); err != nil {
		return nil, err
	}
	return append(append([]byte{}, u.id...), id...), nil
}

func backupMetaRec(t *testing.T, u *user, version uint64, salt, secret, blobKey []byte) *pb.Record {
	v := sha256.Sum256(secret)
	return sign(t, pb.RecordType_BACKUP_META, u.id, &pb.BackupMeta{Version: version, Salt: salt, KdfMKib: 65536, KdfT: 3, KdfP: 1,
		AuthVerifier: v[:], BlobKey: blobKey, Size: 1000}, u.priv)
}

// publishBackup uploads a persistent blob and a BACKUP_META whose verifier is SHA-256(secret); returns the salt.
func (f *fx) publishBackup(u *user, secret []byte) []byte {
	key, err := f.persistentBlob(u)
	if err != nil {
		f.t.Fatal(err)
	}
	salt := bytes.Repeat([]byte{3}, 16)
	if err := f.svc.PublishBackup(context.Background(), u.id, backupMetaRec(f.t, u, 1, salt, secret, key)); err != nil {
		f.t.Fatal(err)
	}
	return salt
}

func TestBackupAuthFakeSaltStable(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	a1, err := f.svc.BackupAuth(ctx, "nobody")
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := f.svc.BackupAuth(ctx, "nobody")
	b, _ := f.svc.BackupAuth(ctx, "somebody")
	if !bytes.Equal(a1.Salt, a2.Salt) || bytes.Equal(a1.Salt, b.Salt) || len(a1.Salt) != 16 {
		t.Fatalf("fake salts: %x %x %x", a1.Salt, a2.Salt, b.Salt)
	}
	if a1.KdfMKib != 65536 || a1.KdfT != 3 || a1.KdfP != 1 {
		t.Fatalf("params: %+v", a1)
	}
	// a registered user without a backup looks the same as an unknown name
	f.mustRegister(f.invite(nil, time.Hour), "anna")
	if a, _ := f.svc.BackupAuth(ctx, "anna"); !bytes.Equal(a.Salt, f.svc.fakeSalt("anna")) {
		t.Fatal("user without backup: not the fake salt")
	}
}

func TestBackupFetchAndRateLimit(t *testing.T) {
	f := newFx(t)
	withBlobs(t, f)
	ctx := context.Background()
	u := f.mustRegister(f.invite(nil, time.Hour), "anna")
	secret := bytes.Repeat([]byte{9}, 32)
	salt := f.publishBackup(u, secret)
	got, err := f.svc.BackupAuth(ctx, "anna")
	if err != nil || !bytes.Equal(got.Salt, salt) {
		t.Fatalf("auth: %v", err)
	}
	res, blobKey, err := f.svc.BackupFetch(ctx, "anna", secret)
	if err != nil || res.BackupMeta == nil || res.BlobMeta == nil || len(blobKey) != 32 {
		t.Fatalf("fetch: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, _, err := f.svc.BackupFetch(ctx, "anna", make([]byte, 32)); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("wrong secret %d: %v", i, err)
		}
	}
	if _, _, err := f.svc.BackupFetch(ctx, "anna", secret); !errors.Is(err, ErrRetryLater) {
		t.Fatalf("6th attempt in an hour must be limited even with the right secret: %v", err)
	}
	f.svc.Now = func() time.Time { return time.Now().Add(61 * time.Minute) }
	if _, _, err := f.svc.BackupFetch(ctx, "anna", secret); err != nil {
		t.Fatalf("after an hour: %v", err)
	}
}

func TestBackupFetchNodeLimit(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	for i := 0; i < MaxFailuresPerNode; i++ {
		if err := f.svc.Store.AddAuthFailure(ctx, string(rune('a'+i)), time.Now().UnixMilli()); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := f.svc.BackupFetch(ctx, "fresh", make([]byte, 32)); !errors.Is(err, ErrRetryLater) {
		t.Fatalf("21st failure on the node: %v", err)
	}
}

func TestBackupFetchUnknownCountsFailure(t *testing.T) {
	f := newFx(t)
	if _, _, err := f.svc.BackupFetch(context.Background(), "ghost", make([]byte, 32)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unknown user: %v", err)
	}
	if n, _ := f.svc.Store.AuthFailures(context.Background(), "ghost", 0); n != 1 {
		t.Fatal("failure not counted")
	}
}

func TestPublishBackupRules(t *testing.T) {
	f := newFx(t)
	withBlobs(t, f)
	ctx := context.Background()
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna")
	boris := f.mustRegister(f.invite(anna, time.Hour), "boris")
	salt, secret := make([]byte, 16), make([]byte, 32)
	borisBlob, err := f.persistentBlob(boris)
	if err != nil {
		t.Fatal(err)
	}
	// a meta pointing at someone else's blob can't even be signed validly (blob key must start with the author)
	if err := f.svc.PublishBackup(ctx, anna.id, backupMetaRec(t, anna, 1, salt, secret, borisBlob)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("foreign blob: %v", err)
	}
	// unknown blob
	if err := f.svc.PublishBackup(ctx, anna.id, backupMetaRec(t, anna, 1, salt, secret, append(append([]byte{}, anna.id...), r16()...))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown blob: %v", err)
	}
	// someone else's meta
	if err := f.svc.PublishBackup(ctx, boris.id, backupMetaRec(t, anna, 1, salt, secret, borisBlob)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("other author: %v", err)
	}
	// at most 3 live persistent blobs
	for i := 0; i < MaxPersistentBlobs-1; i++ {
		if _, err := f.persistentBlob(boris); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.persistentBlob(boris); !errors.Is(err, ErrQuota) {
		t.Fatalf("4th persistent blob: %v", err)
	}
}
