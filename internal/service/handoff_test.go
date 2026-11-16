package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

// markNoBackups publishes a manifest listing this node with no_backups (D113).
func (f *fx) markNoBackups(version uint64) {
	self := &pb.NodeInfo{NodeId: f.svc.NodeID, NodePub: f.svc.NodeKeyPriv.Public().(ed25519.PublicKey), Label: "self", NoBackups: true}
	m := &pb.Manifest{Version: version, NetworkPub: f.svc.NetworkPub, Nodes: []*pb.NodeInfo{self}}
	if _, err := f.svc.ImportRecord(context.Background(), sign(f.t, pb.RecordType_MANIFEST, keys.ID16(f.svc.NetworkPub), m, f.netPriv)); err != nil {
		f.t.Fatal(err)
	}
}

// A node with no_backups serves no restores and takes no backups from peers (D113).
func TestNoBackupsNode(t *testing.T) {
	f := newFx(t)
	withBlobs(t, f)
	ctx := context.Background()
	f.withManifest(1)
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna")
	bob := f.mustRegister(f.invite(nil, time.Hour), "bob")
	secret := bytes.Repeat([]byte{7}, 32)
	f.publishBackup(anna, secret) // uploaded by a phone before the flag: handed off later, never served
	if held, err := f.svc.Holds(ctx, r16()); err != nil || held {
		t.Fatalf("unknown key held: %v %v", held, err)
	}
	f.markNoBackups(2)
	if !f.svc.NoBackups() {
		t.Fatal("flag not seen")
	}
	if _, err := f.svc.BackupAuth(ctx, "anna"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("backup.auth: %v", err)
	}
	if _, _, err := f.svc.BackupFetch(ctx, "anna", "src", secret); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("backup.fetch: %v", err)
	}
	if n, _ := f.svc.Store.AuthFailures(ctx, "anna", 0); n != 0 {
		t.Fatalf("a refused fetch was counted: %d", n)
	}

	// an older peer still replicates bob's backup: dropped
	h := sha256.Sum256([]byte("backup"))
	p, _ := proto.Marshal(&pb.BlobMeta{Size: 1000, ChunkSize: records.BlobChunkSize, ChunkSha256: [][]byte{h[:]}, Persistent: true})
	blob, _ := records.Sign(&pb.RecordBody{Id: r16(), Type: pb.RecordType_BLOB_META, Author: bob.id, CreatedMs: time.Now().UnixMilli(), Payload: p}, bob.priv)
	meta := backupMetaRec(t, bob, 1, bytes.Repeat([]byte{3}, 16), secret, append(append([]byte{}, bob.id...), r16()...))
	for _, rec := range []*pb.Record{blob, meta} {
		applied, err := f.svc.ApplyReplicated(ctx, r16(), rec)
		if err != nil || applied {
			t.Fatalf("backup record from a peer: applied=%v %v", applied, err)
		}
	}
	// a blob for a chat still replicates
	p, _ = proto.Marshal(&pb.BlobMeta{Size: 1000, ChunkSize: records.BlobChunkSize, ChunkSha256: [][]byte{h[:]}, Readers: [][]byte{anna.id}})
	chat, _ := records.Sign(&pb.RecordBody{Id: r16(), Type: pb.RecordType_BLOB_META, Author: bob.id, CreatedMs: time.Now().UnixMilli(),
		ExpiresMs: time.Now().Add(time.Hour).UnixMilli(), Payload: p}, bob.priv)
	if applied, err := f.svc.ApplyReplicated(ctx, r16(), chat); err != nil || !applied {
		t.Fatalf("chat blob: applied=%v %v", applied, err)
	}
	b, err := f.svc.Store.BackupFor(ctx, "anna")
	if err != nil {
		t.Fatal(err)
	}
	if held, _ := f.svc.Holds(ctx, b.RecordKey); held {
		t.Fatal("a node with no_backups vouched for a backup")
	}
}
