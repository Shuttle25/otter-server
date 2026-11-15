package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	pb "ottermsg/server/internal/proto/otterv1"
)

type tUser struct {
	id    []byte
	items map[string]Item
}

func newUser(t *testing.T, s *Store, name string) *tUser {
	t.Helper()
	u := &tUser{id: r16(), items: map[string]Item{}}
	if err := apply(t, s, mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, u.id, entry(u.id, name, 1), t0)); err != nil {
		t.Fatal(err)
	}
	return u
}

func (u *tUser) put(t *testing.T, s *Store, it Item) []byte {
	t.Helper()
	if _, _, err := s.Apply(context.Background(), it.Record, it.Body); err != nil {
		t.Fatal(err)
	}
	k := keyOf(it)
	u.items[string(k)] = it
	return k
}

func (u *tUser) persistentBlob(t *testing.T, s *Store, size uint64) []byte {
	n := (size + 262143) / 262144
	hashes := make([][]byte, n)
	for i := range hashes {
		hashes[i] = make([]byte, 32)
	}
	return u.put(t, s, mkItemAt(t, pb.RecordType_BLOB_META, u.id,
		&pb.BlobMeta{Size: size, ChunkSize: 262144, ChunkSha256: hashes, Persistent: true}, time.Now().UnixMilli()))
}

func (u *tUser) backupMeta(t *testing.T, s *Store, version uint64, blob []byte) []byte {
	return u.put(t, s, mkItemAt(t, pb.RecordType_BACKUP_META, u.id, &pb.BackupMeta{Version: version, Salt: make([]byte, 16),
		KdfMKib: 65536, KdfT: 3, KdfP: 1, AuthVerifier: make([]byte, 32), BlobKey: blob, Size: 1000}, t0))
}

// reapply re-sends a stored record as a lagging peer would.
func (u *tUser) reapply(t *testing.T, s *Store, key []byte) {
	t.Helper()
	if err := apply(t, s, u.items[string(key)]); err != nil {
		t.Fatal(err)
	}
}

func (u *tUser) prekeys(t *testing.T, s *Store, rid uint32, installed int64, oneTime []uint32) {
	t.Helper()
	p := &pb.PreKeys{DeviceId: 1, RegistrationId: rid, InstalledMs: installed,
		SignedPrekey: &pb.SignedPreKey{Id: 1, PublicKey: make([]byte, 33), Signature: make([]byte, 64)},
		KyberPrekey:  &pb.SignedPreKey{Id: 1, PublicKey: make([]byte, 1000), Signature: make([]byte, 64)}}
	for _, id := range oneTime {
		p.OneTime = append(p.OneTime, &pb.OneTimePreKey{Id: id, PublicKey: make([]byte, 33), OwnerNode: []byte("me-me-me-me-me-1")})
	}
	u.put(t, s, mkItemAt(t, pb.RecordType_PREKEYS, u.id, p, t0))
}

func countPrekeys(t *testing.T, s *Store, user []byte) int {
	t.Helper()
	var n int
	if err := s.r.QueryRow(`SELECT COUNT(*) FROM prekeys WHERE user_id=?`, user).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestBackupLatestWins(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	u := newUser(t, s, "anna")
	b1 := u.persistentBlob(t, s, 1000)
	b2 := u.persistentBlob(t, s, 2000)
	m1 := u.backupMeta(t, s, 1, b1)
	u.backupMeta(t, s, 2, b2)
	got, err := s.BackupFor(ctx, "anna")
	if err != nil || got.Version != 2 || !bytes.Equal(got.BlobKey, b2) || len(got.Raw) == 0 {
		t.Fatalf("BackupFor: %+v %v", got, err)
	}
	if _, err := s.Blob(ctx, b1); !errors.Is(err, ErrNotFound) {
		t.Fatal("superseded blob still live")
	}
	if gone, _ := s.BlobGone(ctx, b1); !gone {
		t.Fatal("superseded blob not tombstoned")
	}
	if _, err := s.Get(ctx, m1); !errors.Is(err, ErrNotFound) {
		t.Fatal("superseded meta record kept")
	}
	if _, err := s.Blob(ctx, b2); err != nil {
		t.Fatalf("current blob: %v", err)
	}
	// a lagging peer re-sends v1 and its blob: nothing changes
	u.reapply(t, s, m1)
	u.reapply(t, s, b1)
	if got, _ := s.BackupFor(ctx, "anna"); got.Version != 2 {
		t.Fatal("old version won")
	}
	if _, err := s.Blob(ctx, b1); !errors.Is(err, ErrNotFound) {
		t.Fatal("superseded blob resurrected")
	}
	if _, err := s.BackupFor(ctx, "boris"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestBackupOlderArrivesFirst(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	u := newUser(t, s, "anna")
	b1 := u.persistentBlob(t, s, 1000)
	b2 := u.persistentBlob(t, s, 2000)
	m1 := mkItemAt(t, pb.RecordType_BACKUP_META, u.id, &pb.BackupMeta{Version: 1, Salt: make([]byte, 16),
		KdfMKib: 65536, KdfT: 3, KdfP: 1, AuthVerifier: make([]byte, 32), BlobKey: b1, Size: 1000}, t0)
	u.backupMeta(t, s, 2, b2)
	if err := apply(t, s, m1); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.BackupFor(ctx, "anna"); got == nil || got.Version != 2 {
		t.Fatalf("v1 after v2 won: %+v", got)
	}
	if _, err := s.Get(ctx, keyOf(m1)); !errors.Is(err, ErrNotFound) {
		t.Fatal("losing meta record kept")
	}
}

func TestPersistentBlobSurvivesReadGCAndAge(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	u := newUser(t, s, "anna")
	b := u.persistentBlob(t, s, 1000)
	u.backupMeta(t, s, 1, b)
	if _, err := s.Expire(ctx, time.Now().Add(400*24*time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Blob(ctx, b); err != nil {
		t.Fatalf("referenced persistent blob deleted: %v", err)
	}
	if got, err := s.BackupFor(ctx, "anna"); err != nil || got.Version != 1 {
		t.Fatalf("backup record aged out: %v", err)
	}
}

func TestUnreferencedPersistentBlobCollected(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	u := newUser(t, s, "anna")
	b := u.persistentBlob(t, s, 1000)
	if _, err := s.Expire(ctx, time.Now().Add(6*24*time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Blob(ctx, b); err != nil {
		t.Fatal("collected before 7 days")
	}
	if _, err := s.Expire(ctx, time.Now().Add(8*24*time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Blob(ctx, b); !errors.Is(err, ErrNotFound) {
		t.Fatal("unreferenced persistent blob kept")
	}
}

func TestInstallOrdering(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	u := newUser(t, s, "anna")
	u.prekeys(t, s, 111, 0, []uint32{1, 2}) // pre-M6 install
	u.prekeys(t, s, 222, 5000, []uint32{1}) // restore
	rid, inst, err := s.DeviceInstall(ctx, u.id, 1)
	if err != nil || rid != 222 || inst != 5000 {
		t.Fatalf("after restore: %d %d %v", rid, inst, err)
	}
	if n := countPrekeys(t, s, u.id); n != 3 { // signed + kyber + one one-time key of the new install
		t.Fatalf("old install's keys kept: %d rows", n)
	}
	u.prekeys(t, s, 111, 0, []uint32{3}) // old phone refills late
	if rid, _, _ := s.DeviceInstall(ctx, u.id, 1); rid != 222 {
		t.Fatal("older install took over")
	}
	if n := countPrekeys(t, s, u.id); n != 3 {
		t.Fatalf("older install's keys added: %d rows", n)
	}
	u.prekeys(t, s, 222, 5000, []uint32{4}) // same install refills: merged as before
	if n := countPrekeys(t, s, u.id); n != 4 {
		t.Fatalf("same install refill: %d rows", n)
	}
	if _, _, err := s.DeviceInstall(ctx, r16(), 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown device: %v", err)
	}
}

func TestAuthFailures(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := s.AddAuthFailure(ctx, "anna", "203.0.113.1", 1000+int64(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AddAuthFailure(ctx, "boris", "203.0.113.1", 1005); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.AuthFailures(ctx, "anna", 1001); n != 2 {
		t.Fatalf("anna since 1001: %d", n)
	}
	if n, _ := s.PersistentBlobs(ctx, r16()); n != 0 {
		t.Fatalf("persistent blobs of nobody: %d", n)
	}
}
