package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

var peerID = []byte("peer-peer-peer-1")

func TestReplicatedEnvelopeWaitsForAuthor(t *testing.T) {
	// Node 1 knows anna and boris; node 2 (f2) has only anna and receives boris' envelope before his entry.
	f1 := newFx(t)
	ctx := context.Background()
	anna := f1.mustRegister(f1.invite(nil, time.Hour), "anna")
	boris, req := f1.registerReq(f1.invite(anna, time.Hour), "boris")
	if _, err := f1.svc.Register(ctx, req); err != nil {
		t.Fatal(err)
	}

	f2 := newFx(t)
	f2.svc.NetworkPub = f1.svc.NetworkPub
	annaEntry, _ := f1.svc.Store.UserByID(ctx, anna.id)
	var annaRec pb.Record
	proto.Unmarshal(annaEntry.EntryRaw, &annaRec)
	if applied, err := f2.svc.ApplyReplicated(ctx, peerID, &annaRec); err != nil || !applied {
		t.Fatalf("anna entry: %v %v", applied, err)
	}

	env := sign(t, pb.RecordType_ENVELOPE, boris.id, &pb.Envelope{SenderUser: boris.id, SenderDevice: 1, Kind: pb.Envelope_SIGNAL,
		Recipients: []*pb.Recipient{{User: anna.id, Device: 1, Content: []byte("x")}}}, boris.priv)
	if _, err := f2.svc.ApplyReplicated(ctx, peerID, env); !errors.Is(err, ErrRetryLater) {
		t.Fatalf("unknown author: %v", err)
	}
	if applied, err := f2.svc.ApplyReplicated(ctx, peerID, req.DirectoryEntry); err != nil || !applied {
		t.Fatalf("boris entry: %v %v", applied, err)
	}
	if f2.notes.dir != 2 {
		t.Fatalf("directory notifications %d", f2.notes.dir)
	}
	if applied, err := f2.svc.ApplyReplicated(ctx, peerID, env); err != nil || !applied {
		t.Fatalf("envelope after entry: %v %v", applied, err)
	}
	if f2.notes.env != 1 {
		t.Fatalf("envelope notifications %d", f2.notes.env)
	}
	if applied, _ := f2.svc.ApplyReplicated(ctx, peerID, env); applied {
		t.Fatal("duplicate applied again")
	}
	box, _ := f2.svc.Mailbox(ctx, anna.id, 1, 10)
	if len(box) != 1 {
		t.Fatalf("mailbox %d", len(box))
	}
	// tampered record from a peer is invalid, not retryable
	bad := proto.Clone(env).(*pb.Record)
	bad.Signature = make([]byte, 64)
	if _, err := f2.svc.ApplyReplicated(ctx, peerID, bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered: %v", err)
	}
}

func TestManifestReplicationAndPublish(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	f.withManifest(1)
	if f.svc.CurrentManifest().Version != 1 {
		t.Fatal("v1 not cached")
	}
	var seen []uint64
	f.svc.OnManifest(func(m *pb.Manifest) { seen = append(seen, m.Version) })
	if applied, err := f.svc.ApplyReplicated(ctx, peerID, f.manifestRec(2)); err != nil || !applied {
		t.Fatalf("peer manifest: %v %v", applied, err)
	}
	if f.svc.CurrentManifest().Version != 2 || len(seen) != 1 || seen[0] != 2 {
		t.Fatalf("cache %d callbacks %v", f.svc.CurrentManifest().Version, seen)
	}
	if len(f.notes.manifests) == 0 || f.notes.manifests[len(f.notes.manifests)-1] != 2 {
		t.Fatalf("notified %v", f.notes.manifests)
	}
	if err := f.svc.PublishManifest(ctx, f.manifestRec(2)); !errors.Is(err, ErrConflict) {
		t.Fatalf("same version: %v", err)
	}
	if err := f.svc.PublishManifest(ctx, f.manifestRec(3)); err != nil || f.svc.CurrentManifest().Version != 3 {
		t.Fatalf("publish v3: %v", err)
	}
	_, other, _ := ed25519.GenerateKey(nil)
	forged := sign(t, pb.RecordType_MANIFEST, keys.ID16(f.svc.NetworkPub), &pb.Manifest{Version: 9, NetworkPub: f.svc.NetworkPub}, other)
	if err := f.svc.PublishManifest(ctx, forged); !errors.Is(err, ErrInvalid) {
		t.Fatalf("forged: %v", err)
	}
}

func TestPrekeyConsumptionAndStatus(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	nodeB := &pb.NodeInfo{NodeId: []byte("node-B-node-B-01"), NodePub: make([]byte, 32), Label: "b"}
	f.withManifest(1, nodeB)
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna") // 12 one-time keys owned by this node

	low, err := f.svc.PrekeyStatus(ctx, anna.id, 1)
	if err != nil || len(low) != 1 || !bytes.Equal(low[0].Node, nodeB.NodeId) || low[0].Remaining != 0 {
		t.Fatalf("status %+v %v", low, err)
	}
	if _, err := f.svc.FetchPrekeys(ctx, &pb.PreKeyFetchRequest{UserId: anna.id, DeviceId: 1}); err != nil {
		t.Fatal(err)
	}
	log, _ := f.svc.Store.Since(ctx, 0, 100)
	consumed := 0
	for _, e := range log {
		var r pb.Record
		var b pb.RecordBody
		proto.Unmarshal(e.Raw, &r)
		proto.Unmarshal(r.Body, &b)
		if b.Type == pb.RecordType_PREKEY_CONSUMED && bytes.Equal(b.Author, f.svc.NodeID) {
			consumed++
		}
	}
	if consumed != 1 {
		t.Fatalf("PREKEY_CONSUMED records: %d", consumed)
	}
	for i := 0; i < 2; i++ {
		f.svc.FetchPrekeys(ctx, &pb.PreKeyFetchRequest{UserId: anna.id, DeviceId: 1})
	}
	// 12 - 3 = 9 left on this node: low, reported with this node as owner
	if len(f.notes.lowOwner) == 0 || !bytes.Equal(f.notes.lowOwner[len(f.notes.lowOwner)-1], f.svc.NodeID) {
		t.Fatalf("prekeys_low owner %x", f.notes.lowOwner)
	}
	if low, _ := f.svc.PrekeyStatus(ctx, anna.id, 1); len(low) != 2 {
		t.Fatalf("both nodes low now: %+v", low)
	}
}

func TestJanitorRuns(t *testing.T) {
	f := newFx(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.svc.RunJanitor(ctx, 10*time.Millisecond); close(done) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("janitor did not stop")
	}
}

func TestPrekeyConsumedFromUnknownNodeIsSkipped(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	f.withManifest(1)
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna")
	_, ghostPriv, _ := ed25519.GenerateKey(nil)
	ghostID := keys.ID16(ghostPriv.Public().(ed25519.PublicKey))
	rec := sign(t, pb.RecordType_PREKEY_CONSUMED, ghostID,
		&pb.PrekeyConsumed{UserId: anna.id, DeviceId: 1, KeyIds: []uint32{1}}, ghostPriv)
	applied, err := f.svc.ApplyReplicated(ctx, peerID, rec)
	if err != nil || applied {
		t.Fatalf("unknown node consumption: applied=%v err=%v", applied, err)
	}
	// other record types from unknown authors still wait for their author
	env := sign(t, pb.RecordType_ENVELOPE, ghostID, &pb.Envelope{SenderUser: ghostID, SenderDevice: 1, Kind: pb.Envelope_SIGNAL,
		Recipients: []*pb.Recipient{{User: anna.id, Device: 1, Content: []byte("x")}}}, ghostPriv)
	if _, err := f.svc.ApplyReplicated(ctx, peerID, env); !errors.Is(err, ErrRetryLater) {
		t.Fatalf("unknown user envelope: %v", err)
	}
}
