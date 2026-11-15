package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/blobs"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
	"ottermsg/server/internal/store"
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

func TestBackupFetch(t *testing.T) {
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
	res, blobKey, err := f.svc.BackupFetch(ctx, "anna", owner, secret)
	if err != nil || res.BackupMeta == nil || res.BlobMeta == nil || len(blobKey) != 32 {
		t.Fatalf("fetch: %v", err)
	}
	if n, _ := f.svc.Store.AuthFailures(ctx, "anna", 0); n != 0 {
		t.Fatalf("a correct attempt left %d rows", n)
	}
}

const owner, stranger = "198.51.100.7", "203.0.113.66"

// A stranger hammering one name is limited to his own source; the owner still gets in (C4).
func TestBackupFetchStrangerCannotLock(t *testing.T) {
	f := newFx(t)
	withBlobs(t, f)
	ctx := context.Background()
	u := f.mustRegister(f.invite(nil, time.Hour), "anna")
	secret := bytes.Repeat([]byte{9}, 32)
	f.publishBackup(u, secret)
	now := time.Now()
	f.svc.Now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		if _, _, err := f.svc.BackupFetch(ctx, "anna", stranger, make([]byte, 32)); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("wrong secret %d: %v", i, err)
		}
	}
	if _, _, err := f.svc.BackupFetch(ctx, "anna", stranger, secret); !errors.Is(err, ErrRetryLater) {
		t.Fatalf("6th attempt from the same source in an hour, even with the right secret: %v", err)
	}
	if _, _, err := f.svc.BackupFetch(ctx, "anna", owner, secret); err != nil {
		t.Fatalf("owner from another source must get in: %v", err)
	}
	if n, _ := f.svc.Store.AuthFailures(ctx, "anna", 0); n != 5 {
		t.Fatalf("a correct attempt must not count: %d failures", n)
	}
	now = now.Add(time.Hour)
	if _, _, err := f.svc.BackupFetch(ctx, "anna", stranger, secret); err != nil {
		t.Fatalf("after an hour: %v", err)
	}
}

// Many sources slow a name down but never lock it longer than MaxDelay.
func TestBackupFetchSlowsDownAcrossSources(t *testing.T) {
	f := newFx(t)
	withBlobs(t, f)
	ctx := context.Background()
	u := f.mustRegister(f.invite(nil, time.Hour), "anna")
	secret := bytes.Repeat([]byte{9}, 32)
	f.publishBackup(u, secret)
	now := time.Now()
	f.svc.Now = func() time.Time { return now }
	for i := 0; i < RestoreLimits.FreePerName; i++ {
		src := fmt.Sprintf("203.0.113.%d", i+1)
		if _, _, err := f.svc.BackupFetch(ctx, "anna", src, make([]byte, 32)); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("failure %d: %v", i, err)
		}
	}
	_, _, err := f.svc.BackupFetch(ctx, "anna", owner, secret)
	if !errors.Is(err, ErrRetryLater) || !strings.Contains(err.Error(), "retry in") {
		t.Fatalf("11th attempt right away must wait: %v", err)
	}
	now = now.Add(RestoreLimits.BaseDelay)
	if _, _, err := f.svc.BackupFetch(ctx, "anna", owner, secret); err != nil {
		t.Fatalf("after the delay: %v", err)
	}
	for i := 0; i < 40; i++ { // a long attack: the wait stays capped
		if err := f.svc.Store.AddAuthFailure(ctx, "anna", fmt.Sprintf("192.0.2.%d", i), now.UnixMilli()); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err = f.svc.BackupFetch(ctx, "anna", owner, secret)
	var sd *store.SlowDown
	if !errors.As(err, &sd) || sd.Wait > RestoreLimits.MaxDelay {
		t.Fatalf("during the attack: %v", err)
	}
	now = now.Add(RestoreLimits.MaxDelay)
	if _, _, err := f.svc.BackupFetch(ctx, "anna", owner, secret); err != nil {
		t.Fatalf("never locked longer than MaxDelay: %v", err)
	}
}

// One source trying many names is slowed down after FreePerSource failures a day.
func TestBackupFetchSlowsDownOneSource(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	now := time.Now()
	f.svc.Now = func() time.Time { return now }
	for i := 0; i < RestoreLimits.FreePerSource; i++ {
		if _, _, err := f.svc.BackupFetch(ctx, fmt.Sprintf("ghost%d", i), stranger, make([]byte, 32)); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("failure %d: %v", i, err)
		}
	}
	if _, _, err := f.svc.BackupFetch(ctx, "next", stranger, make([]byte, 32)); !errors.Is(err, ErrRetryLater) {
		t.Fatalf("source past its daily allowance: %v", err)
	}
	if _, _, err := f.svc.BackupFetch(ctx, "next", owner, make([]byte, 32)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("another source is not slowed: %v", err)
	}
}

// Parallel wrong attempts are reserved one by one: never more than the limit get compared (C10).
func TestBackupFetchParallelAttemptsReserved(t *testing.T) {
	f := newFx(t)
	withBlobs(t, f)
	ctx := context.Background()
	u := f.mustRegister(f.invite(nil, time.Hour), "anna")
	f.publishBackup(u, bytes.Repeat([]byte{9}, 32))
	var wg sync.WaitGroup
	var mu sync.Mutex
	unauthorized, later := 0, 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := f.svc.BackupFetch(ctx, "anna", stranger, make([]byte, 32))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case errors.Is(err, ErrUnauthorized):
				unauthorized++
			case errors.Is(err, ErrRetryLater):
				later++
			default:
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	wg.Wait()
	if unauthorized != RestoreLimits.PerSourceHour || later != 20-RestoreLimits.PerSourceHour {
		t.Fatalf("compared %d, refused %d", unauthorized, later)
	}
	if n, _ := f.svc.Store.AuthFailures(ctx, "anna", 0); n != RestoreLimits.PerSourceHour {
		t.Fatalf("%d failures counted", n)
	}
}

func TestBackupFetchUnknownCountsFailure(t *testing.T) {
	f := newFx(t)
	if _, _, err := f.svc.BackupFetch(context.Background(), "ghost", "203.0.113.5", make([]byte, 32)); !errors.Is(err, ErrUnauthorized) {
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

// C12 (D103): a clashed plain name never resolves to one account: backup.auth lists the candidates (no salt) and
// backup.fetch refuses; each "name#tag" resolves to its own account.
func TestBackupAuthAmbiguousName(t *testing.T) {
	f := newFx(t)
	withBlobs(t, f)
	ctx := context.Background()
	f.withManifest(1)
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna")
	secret := bytes.Repeat([]byte{9}, 32)
	salt := f.publishBackup(anna, secret)
	other, rec := f.replicatedEntry(f.invite(anna, time.Hour), "anna", nil) // a clash from another partition
	if _, err := f.svc.ApplyReplicated(ctx, r16(), rec); err != nil {
		t.Fatal(err)
	}
	res, err := f.svc.BackupAuth(ctx, "anna")
	if err != nil || len(res.Candidates) != 2 || len(res.Salt) != 0 {
		t.Fatalf("ambiguous: %+v %v", res, err)
	}
	want := map[string]bool{"anna#" + hex.EncodeToString(anna.id[:4]): true, "anna#" + hex.EncodeToString(other.id[:4]): true}
	for _, c := range res.Candidates {
		if !want[c] {
			t.Fatalf("unexpected candidate %q in %v", c, res.Candidates)
		}
		r, err := f.svc.BackupAuth(ctx, c)
		if err != nil || len(r.Candidates) != 0 || len(r.Salt) == 0 {
			t.Fatalf("%s: %+v %v", c, r, err)
		}
	}
	annaTag := "anna#" + hex.EncodeToString(anna.id[:4])
	if r, _ := f.svc.BackupAuth(ctx, annaTag); !bytes.Equal(r.Salt, salt) {
		t.Fatalf("%s does not resolve to anna's backup", annaTag)
	}
	if _, _, err := f.svc.BackupFetch(ctx, "anna", owner, secret); !errors.Is(err, ErrConflict) {
		t.Fatalf("fetch by an ambiguous name: %v", err)
	}
	if res, _, err := f.svc.BackupFetch(ctx, annaTag, owner, secret); err != nil || res.BackupMeta == nil {
		t.Fatalf("fetch by anna's tag: %v", err)
	}
}
