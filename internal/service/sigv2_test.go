package service

import (
	"context"
	"crypto/ed25519"
	"testing"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

// emitConsumed signs v1 until the manifest sets sig_v1_until_ms, then v2 (D109): with a cut-over in the past, a v1
// PREKEY_CONSUMED would fail the node's own validation.
func TestSigV2EmitConsumed(t *testing.T) {
	f := newFx(t)
	f.withManifest(1)
	if f.svc.sigContext().V2 {
		t.Fatal("v2 before the cut-over")
	}
	ctx := context.Background()
	if err := f.svc.emitConsumed(ctx, make([]byte, 16), 1, 1); err != nil {
		t.Fatalf("before the cut-over: %v", err)
	}
	cut := f.svc.Now().UnixMilli() - 3_600_000
	m := &pb.Manifest{Version: 2, NetworkPub: f.svc.NetworkPub, SigV1UntilMs: cut,
		Nodes: []*pb.NodeInfo{{NodeId: f.svc.NodeID, NodePub: f.svc.NodeKeyPriv.Public().(ed25519.PublicKey), Label: "self"}}}
	p, _ := proto.Marshal(m)
	rec, err := records.SignWith(&pb.RecordBody{Id: keys.ID16(p), Type: pb.RecordType_MANIFEST, Author: keys.ID16(f.svc.NetworkPub),
		CreatedMs: f.svc.Now().UnixMilli(), Payload: p}, f.netPriv, records.ContextFor(f.svc.NetworkPub, m))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ImportRecord(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if f.svc.CurrentManifest().GetSigV1UntilMs() != cut || !f.svc.sigContext().V2 {
		t.Fatal("cut-over manifest not loaded")
	}
	if err := f.svc.emitConsumed(ctx, make([]byte, 16), 1, 2); err != nil {
		t.Fatalf("after the cut-over: %v", err)
	}
}
