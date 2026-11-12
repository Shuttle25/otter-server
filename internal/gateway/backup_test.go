package gateway

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

// persistentMeta signs a persistent BLOB_META (backup, D50) for data.
func persistentMeta(t *testing.T, a *acct, data []byte) (*pb.Record, []byte) {
	m := &pb.BlobMeta{Size: uint64(len(data)), ChunkSize: chunk, Persistent: true}
	for off := 0; off < len(data); off += chunk {
		h := sha256.Sum256(data[off:min(off+chunk, len(data))])
		m.ChunkSha256 = append(m.ChunkSha256, h[:])
	}
	p, _ := proto.Marshal(m)
	id := r16()
	rec, err := records.Sign(&pb.RecordBody{Id: id, Type: pb.RecordType_BLOB_META, Author: a.id, CreatedMs: time.Now().UnixMilli(), Payload: p}, a.priv)
	if err != nil {
		t.Fatal(err)
	}
	return rec, append(append([]byte{}, a.id...), id...)
}

func TestLoginReturnsInstall(t *testing.T) {
	n := startNode(t)
	as, _ := members(t, n, "anna")
	c := dial(t, n)
	ts := time.Now().UnixMilli()
	var resp pb.LoginResponse
	st, msg := c.call("auth.login", &pb.LoginRequest{UserId: as[0].id, DeviceId: 1, TsMs: ts,
		Signature: ed25519.Sign(as[0].priv, keys.AuthMessage(c.hello.NodeId, c.hello.Nonce, ts))}, &resp)
	if st != pb.Status_STATUS_OK || resp.RegistrationId != 9 || resp.InstalledMs != 0 {
		t.Fatalf("login: %v %s %+v", st, msg, &resp)
	}
}

func TestBackupRestoreFlow(t *testing.T) {
	n := startNode(t)
	as, cs := members(t, n, "anna", "boris")
	anna, ca := as[0], cs[0]
	data := make([]byte, 300<<10)
	rand.Read(data)
	meta, key := persistentMeta(t, anna, data)
	if s, msg := ca.call("blob.create", &pb.RecordRequest{Record: meta}, nil); s != pb.Status_STATUS_OK {
		t.Fatalf("create: %v %s", s, msg)
	}
	for i := 0; i*chunk < len(data); i++ {
		part := data[i*chunk : min((i+1)*chunk, len(data))]
		if s, msg := ca.call("blob.put", &pb.BlobPutRequest{BlobKey: key, Index: uint32(i), Data: part}, nil); s != pb.Status_STATUS_OK {
			t.Fatalf("put %d: %v %s", i, s, msg)
		}
	}
	secret := bytes.Repeat([]byte{4}, 32)
	salt := bytes.Repeat([]byte{5}, 16)
	v := sha256.Sum256(secret)
	bm := sign(t, pb.RecordType_BACKUP_META, anna.id, &pb.BackupMeta{Version: 1, Salt: salt, KdfMKib: 65536, KdfT: 3, KdfP: 1,
		AuthVerifier: v[:], BlobKey: key, Size: uint64(len(data))}, anna.priv)
	fresh := dial(t, n)
	if s, _ := fresh.call("backup.publish", &pb.RecordRequest{Record: bm}, nil); s != pb.Status_STATUS_UNAUTHORIZED {
		t.Fatalf("publish without login: %v", s)
	}
	if s, msg := ca.call("backup.publish", &pb.RecordRequest{Record: bm}, nil); s != pb.Status_STATUS_OK {
		t.Fatalf("publish: %v %s", s, msg)
	}

	// a wiped phone: a new connection, not logged in
	var auth pb.BackupAuthResponse
	if s, msg := fresh.call("backup.auth", &pb.BackupAuthRequest{Username: "anna"}, &auth); s != pb.Status_STATUS_OK || !bytes.Equal(auth.Salt, salt) {
		t.Fatalf("auth: %v %s %x", s, msg, auth.Salt)
	}
	if s, _ := fresh.call("blob.get", &pb.BlobGetRequest{BlobKey: key, Index: 0}, nil); s != pb.Status_STATUS_UNAUTHORIZED {
		t.Fatalf("get before fetch: %v", s)
	}
	if s, _ := fresh.call("backup.fetch", &pb.BackupFetchRequest{Username: "anna", AuthSecret: make([]byte, 32)}, nil); s != pb.Status_STATUS_UNAUTHORIZED {
		t.Fatalf("wrong secret: %v", s)
	}
	var res pb.BackupFetchResponse
	if s, msg := fresh.call("backup.fetch", &pb.BackupFetchRequest{Username: "anna", AuthSecret: secret}, &res); s != pb.Status_STATUS_OK || res.BackupMeta == nil || res.BlobMeta == nil {
		t.Fatalf("fetch: %v %s", s, msg)
	}
	var got pb.BlobChunk
	if s, msg := fresh.call("blob.get", &pb.BlobGetRequest{BlobKey: key, Index: 1}, &got); s != pb.Status_STATUS_OK || !bytes.Equal(got.Data, data[chunk:]) {
		t.Fatalf("get granted chunk: %v %s", s, msg)
	}
	if s, _ := fresh.call("blob.get", &pb.BlobGetRequest{BlobKey: append(append([]byte{}, anna.id...), r16()...), Index: 0}, nil); s != pb.Status_STATUS_UNAUTHORIZED {
		t.Fatalf("get of another blob: %v", s)
	}
	if s, _ := fresh.call("msg.fetch", &pb.Empty{}, nil); s != pb.Status_STATUS_UNAUTHORIZED {
		t.Fatalf("other methods after fetch: %v", s)
	}
	third := dial(t, n)
	if s, _ := third.call("blob.get", &pb.BlobGetRequest{BlobKey: key, Index: 0}, nil); s != pb.Status_STATUS_UNAUTHORIZED {
		t.Fatalf("get on another connection: %v", s)
	}
}
