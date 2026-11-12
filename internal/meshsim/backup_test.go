package meshsim

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

// putPersistentBlob is putBlob for a backup blob (D50): no readers, no expiry.
func (s *sim) putPersistentBlob(c *client, a *account, data []byte) []byte {
	m := &pb.BlobMeta{Size: uint64(len(data)), ChunkSize: chunk, Persistent: true}
	for off := 0; off < len(data); off += chunk {
		h := sha256.Sum256(data[off:min(off+chunk, len(data))])
		m.ChunkSha256 = append(m.ChunkSha256, h[:])
	}
	p, _ := proto.Marshal(m)
	id := make([]byte, 16)
	rand.Read(id)
	rec, err := records.Sign(&pb.RecordBody{Id: id, Type: pb.RecordType_BLOB_META, Author: a.id, CreatedMs: time.Now().UnixMilli(), Payload: p}, a.priv)
	if err != nil {
		s.t.Fatal(err)
	}
	var st pb.BlobStatus
	c.mustCall("blob.create", &pb.RecordRequest{Record: rec}, &st)
	key := append(append([]byte{}, a.id...), id...)
	for _, i := range st.Missing {
		c.mustCall("blob.put", &pb.BlobPutRequest{BlobKey: key, Index: i, Data: data[int(i)*chunk : min((int(i)+1)*chunk, len(data))]}, nil)
	}
	return key
}

// loginInstall logs a in on n and returns the node's answer (D52).
func (s *sim) loginInstall(n *simNode, a *account) *pb.LoginResponse {
	c := s.dial(n)
	defer c.close()
	ts := time.Now().UnixMilli()
	var r pb.LoginResponse
	if st, _ := c.call("auth.login", &pb.LoginRequest{UserId: a.id, DeviceId: 1, TsMs: ts,
		Signature: ed25519.Sign(a.priv, keys.AuthMessage(c.hello.NodeId, c.hello.Nonce, ts))}, &r); st != pb.Status_STATUS_OK {
		return nil
	}
	return &r
}

// Acceptance (M6, nodes): a backup uploaded through A restores through C while A is down; a newer backup published
// meanwhile makes A drop the old blob when it comes back.
func TestBackupRestoreThroughOtherNode(t *testing.T) {
	s := newSim(t, "a", "b", "c")
	a, c := s.node("a"), s.node("c")
	anna := s.register(a, "anna")
	eventually(t, "anna on c", func() bool { return c.knows(anna) })
	ca := s.login(a, anna)
	data := randomBytes(3 << 20)
	blob := s.putPersistentBlob(ca, anna, data)
	secret := bytes.Repeat([]byte{5}, 32)
	v := sha256.Sum256(secret)
	salt := bytes.Repeat([]byte{1}, 16)
	meta := s.signAs(anna, pb.RecordType_BACKUP_META, &pb.BackupMeta{Version: 1, Salt: salt, KdfMKib: 65536, KdfT: 3, KdfP: 1,
		AuthVerifier: v[:], BlobKey: blob, Size: uint64(len(data))})
	ca.mustCall("backup.publish", &pb.RecordRequest{Record: meta}, &pb.Empty{})
	ca.close()
	eventuallyWithin(t, time.Minute, "c holds the backup", func() bool { return c.hasChunks(blob, 12) && c.has(recordKey(meta)) })
	s.stop(a)

	fresh := s.dial(c)
	var auth pb.BackupAuthResponse
	fresh.mustCall("backup.auth", &pb.BackupAuthRequest{Username: "anna"}, &auth)
	if !bytes.Equal(auth.Salt, salt) {
		t.Fatal("salt")
	}
	var res pb.BackupFetchResponse
	fresh.mustCall("backup.fetch", &pb.BackupFetchRequest{Username: "anna", AuthSecret: secret}, &res)
	got, st := s.getBlob(fresh, blob, 12)
	if st != pb.Status_STATUS_OK || !bytes.Equal(got, data) {
		t.Fatalf("restore via C with A down: %v", st)
	}
	fresh.close()

	// v2 via c while a is down; a must drop v1 when it comes back
	cc := s.login(c, anna)
	blob2 := s.putPersistentBlob(cc, anna, data[:1<<20])
	meta2 := s.signAs(anna, pb.RecordType_BACKUP_META, &pb.BackupMeta{Version: 2, Salt: salt, KdfMKib: 65536, KdfT: 3, KdfP: 1,
		AuthVerifier: v[:], BlobKey: blob2, Size: 1 << 20})
	cc.mustCall("backup.publish", &pb.RecordRequest{Record: meta2}, &pb.Empty{})
	cc.close()
	s.start(a)
	eventuallyWithin(t, time.Minute, "a forgets v1 and holds v2", func() bool {
		return a.blobGone(blob) && a.has(recordKey(meta2)) && !a.has(recordKey(meta)) && a.hasChunks(blob2, 4)
	})
	if !c.blobGone(blob) {
		t.Fatal("c still holds v1")
	}
}

// D52: a refill from the replaced install, submitted through another node after the restore, never wins.
func TestNewerInstallWinsAcrossNodes(t *testing.T) {
	s := newSim(t, "a", "b", "c")
	a, b, c := s.node("a"), s.node("b"), s.node("c")
	anna := s.register(a, "anna") // registration id 4, installed_ms 0
	eventually(t, "anna everywhere", func() bool { return b.knows(anna) && c.knows(anna) })
	cb := s.login(b, anna)
	cb.mustCall("prekeys.upload", &pb.RecordRequest{Record: s.signAs(anna, pb.RecordType_PREKEYS, &pb.PreKeys{DeviceId: 1,
		RegistrationId: 2, InstalledMs: 5000,
		SignedPrekey: &pb.SignedPreKey{Id: 7, PublicKey: make([]byte, 33), Signature: make([]byte, 64)},
		KyberPrekey:  &pb.SignedPreKey{Id: 7, PublicKey: make([]byte, 1569), Signature: make([]byte, 64)}})}, nil)
	cb.close()
	cc := s.login(c, anna)
	cc.mustCall("prekeys.upload", &pb.RecordRequest{Record: s.signAs(anna, pb.RecordType_PREKEYS, &pb.PreKeys{DeviceId: 1,
		RegistrationId: 4, OneTime: []*pb.OneTimePreKey{{Id: 99, PublicKey: make([]byte, 33), OwnerNode: c.id}}})}, nil)
	cc.close()
	eventually(t, "every node reports install 2", func() bool {
		return s.all(func(n *simNode) bool {
			r := s.loginInstall(n, anna)
			return r != nil && r.RegistrationId == 2 && r.InstalledMs == 5000
		})
	})
}
