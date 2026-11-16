package meshsim

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	pb "ottermsg/server/internal/proto/otterv1"
)

func (s *sim) publishBackup(c *client, a *account, version uint64, data []byte) (blob, meta []byte) {
	blob = s.putPersistentBlob(c, a, data)
	v := sha256.Sum256(bytes.Repeat([]byte{5}, 32))
	rec := s.signAs(a, pb.RecordType_BACKUP_META, &pb.BackupMeta{Version: version, Salt: bytes.Repeat([]byte{1}, 16), KdfMKib: 65536,
		KdfT: 3, KdfP: 1, AuthVerifier: v[:], BlobKey: blob, Size: uint64(len(data))})
	c.mustCall("backup.publish", &pb.RecordRequest{Record: rec}, &pb.Empty{})
	return blob, recordKey(rec)
}

// D113 (limit 1, storage half), hostile side: a node with no_backups keeps what a phone uploaded until two foreign
// nodes hold it (one confirmation is not enough), serves no restore, and never receives a backup made abroad.
func TestNoBackupsNodeHandoff(t *testing.T) {
	s := newSimWith(t, map[string]nodeOpts{"ru": {noBackups: true}}, "ru", "f1", "f2")
	ru, f1, f2 := s.node("ru"), s.node("f1"), s.node("f2")
	anna := s.register(ru, "anna")
	eventually(t, "abroad knows anna", func() bool { return f1.knows(anna) && f2.knows(anna) })
	s.stop(f2) // only one foreign node can confirm now

	c := s.login(ru, anna)
	data := randomBytes(1 << 20)
	blob, meta := s.publishBackup(c, anna, 1, data)
	c.close()
	if st, _ := s.dial(ru).call("backup.auth", &pb.BackupAuthRequest{Username: "anna"}, &pb.BackupAuthResponse{}); st != pb.Status_STATUS_UNAVAILABLE {
		t.Fatalf("a node with no_backups answered backup.auth: %v", st)
	}
	eventuallyWithin(t, time.Minute, "f1 holds the backup", func() bool { return f1.hasChunks(blob, 4) && f1.has(meta) })
	time.Sleep(20 * 50 * time.Millisecond) // ~20 handoff rounds
	if !ru.has(meta) || !ru.hasChunks(blob, 4) {
		t.Fatal("ru dropped its copy on one confirmation (need 2)")
	}
	s.start(f2)
	eventuallyWithin(t, time.Minute, "ru hands off", func() bool { return ru.blobGone(blob) && !ru.has(meta) })
	if !f2.has(meta) || !f2.hasChunks(blob, 4) {
		t.Fatal("f2 confirmed without holding")
	}

	// a backup published abroad never reaches ru
	cf := s.login(f1, anna)
	blob2, meta2 := s.publishBackup(cf, anna, 2, data[:1000])
	cf.close()
	eventuallyWithin(t, time.Minute, "f2 has v2", func() bool { return f2.has(meta2) && f2.hasChunks(blob2, 1) })
	time.Sleep(500 * time.Millisecond)
	if ru.has(meta2) || ru.has(blob2) {
		t.Fatal("a backup was replicated to the node with no_backups")
	}
	if st, _ := s.dial(f1).call("backup.auth", &pb.BackupAuthRequest{Username: "anna"}, &pb.BackupAuthResponse{}); st != pb.Status_STATUS_OK {
		t.Fatalf("f1 backup.auth: %v", st)
	}
}

// A backup uploaded through the node with no_backups and superseded abroad before the handoff finished is still
// dropped there: the foreign nodes count the superseded copy as held (D50, D113).
func TestNoBackupsNodeHandoffSuperseded(t *testing.T) {
	s := newSimWith(t, map[string]nodeOpts{"ru": {noBackups: true}}, "ru", "f1", "f2")
	ru, f1, f2 := s.node("ru"), s.node("f1"), s.node("f2")
	anna := s.register(ru, "anna")
	eventually(t, "abroad knows anna", func() bool { return f1.knows(anna) && f2.knows(anna) })
	s.stop(f2)

	c := s.login(ru, anna)
	blob, meta := s.publishBackup(c, anna, 1, randomBytes(1000))
	c.close()
	eventuallyWithin(t, time.Minute, "f1 holds the backup", func() bool { return f1.hasChunks(blob, 1) && f1.has(meta) })
	cf := s.login(f1, anna)
	_, meta2 := s.publishBackup(cf, anna, 2, randomBytes(1000))
	cf.close()
	eventually(t, "f1 dropped v1", func() bool { return !f1.has(meta) && f1.blobGone(blob) })
	time.Sleep(10 * 50 * time.Millisecond)
	if !ru.has(meta) {
		t.Fatal("ru dropped its copy on one confirmation (need 2)")
	}
	s.start(f2)
	eventuallyWithin(t, time.Minute, "ru drops the superseded copy", func() bool { return ru.blobGone(blob) && !ru.has(meta) })
	eventually(t, "f2 has v2", func() bool { return f2.has(meta2) })
}
