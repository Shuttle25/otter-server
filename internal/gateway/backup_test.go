package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/coder/websocket"
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

// D52: a phone that stays online while its account is restored elsewhere is cut off before it can take (and ack) the
// new install's mail; the restored phone's own session survives its prekey upload.
func TestReplacedInstallIsDisconnected(t *testing.T) {
	n := startNode(t)
	as, cs := members(t, n, "anna", "boris")
	anna, boris := as[0], as[1]
	oldPhone, cb := cs[0], cs[1]
	newPhone := dial(t, n)
	login(t, newPhone, anna)
	pk := sign(t, pb.RecordType_PREKEYS, anna.id, &pb.PreKeys{DeviceId: 1, RegistrationId: 77, InstalledMs: time.Now().UnixMilli(),
		SignedPrekey: &pb.SignedPreKey{Id: 2, PublicKey: make([]byte, 33), Signature: make([]byte, 64)},
		KyberPrekey:  &pb.SignedPreKey{Id: 2, PublicKey: make([]byte, 1569), Signature: make([]byte, 64)}}, anna.priv)
	if s, msg := newPhone.call("prekeys.upload", &pb.RecordRequest{Record: pk}, nil); s != pb.Status_STATUS_OK {
		t.Fatalf("upload: %v %s", s, msg)
	}
	ack := sign(t, pb.RecordType_ACK, anna.id, &pb.Ack{EnvelopeIds: [][]byte{make([]byte, 32)}, DeviceId: 1}, anna.priv)
	if s, _ := oldPhone.call("msg.ack", &pb.RecordRequest{Record: ack}, nil); s != pb.Status_STATUS_UNAUTHORIZED {
		t.Fatalf("ack from the replaced install: %v", s)
	}
	env := sign(t, pb.RecordType_ENVELOPE, boris.id, &pb.Envelope{SenderUser: boris.id, SenderDevice: 1, Kind: pb.Envelope_PREKEY_SIGNAL,
		Recipients: []*pb.Recipient{{User: anna.id, Device: 1, Content: []byte("hello")}}}, boris.priv)
	if s, msg := cb.call("msg.send", &pb.RecordRequest{Record: env}, nil); s != pb.Status_STATUS_OK {
		t.Fatalf("send: %v %s", s, msg)
	}
	var batch pb.RecordBatch
	proto.Unmarshal(newPhone.nextEvent("envelopes").Body, &batch)
	if len(batch.Records) != 1 {
		t.Fatalf("new install got %d envelopes", len(batch.Records))
	}
	// the replaced install's connection is closed: writes start failing
	closed := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline) && !closed; time.Sleep(20 * time.Millisecond) {
		closed = oldPhone.c.Write(context.Background(), websocket.MessageBinary, []byte{0}) != nil
	}
	if !closed {
		t.Fatal("the replaced install is still connected")
	}
	// a fresh login of the old phone learns that it was replaced
	var resp pb.LoginResponse
	c := dial(t, n)
	ts := time.Now().UnixMilli()
	c.call("auth.login", &pb.LoginRequest{UserId: anna.id, DeviceId: 1, TsMs: ts,
		Signature: ed25519.Sign(anna.priv, keys.AuthMessage(c.hello.NodeId, c.hello.Nonce, ts))}, &resp)
	if resp.RegistrationId != 77 || resp.InstalledMs == 0 {
		t.Fatalf("login response: %+v", &resp)
	}
}
