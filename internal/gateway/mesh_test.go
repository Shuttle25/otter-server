package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

func manifestRec(t *testing.T, n *node, version uint64) *pb.Record {
	self := &pb.NodeInfo{NodeId: n.svc.NodeID, NodePub: n.svc.NodeKeyPriv.Public().(ed25519.PublicKey), Label: "self"}
	return sign(t, pb.RecordType_MANIFEST, keys.ID16(n.svc.NetworkPub), &pb.Manifest{Version: version, NetworkPub: n.svc.NetworkPub,
		Nodes: []*pb.NodeInfo{self}}, n.netPriv)
}

func TestManifestPublishAndEvents(t *testing.T) {
	n := startNode(t)
	ctx := context.Background()
	if _, err := n.svc.ImportRecord(ctx, manifestRec(t, n, 1)); err != nil {
		t.Fatal(err)
	}
	watcher := dial(t, n) // not logged in
	admin := dial(t, n)
	if st, msg := admin.call("manifest.publish", &pb.RecordRequest{Record: manifestRec(t, n, 2)}, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("publish: %v %s", st, msg)
	}
	var mr pb.ManifestResponse
	proto.Unmarshal(watcher.nextEvent("manifest").Body, &mr)
	var body pb.RecordBody
	var m pb.Manifest
	proto.Unmarshal(mr.Manifest.Body, &body)
	proto.Unmarshal(body.Payload, &m)
	if m.Version != 2 {
		t.Fatalf("event manifest v%d", m.Version)
	}
	if st, _ := admin.call("manifest.publish", &pb.RecordRequest{Record: manifestRec(t, n, 2)}, nil); st != pb.Status_STATUS_CONFLICT {
		t.Fatalf("republish: %v", st)
	}
	if st, _ := admin.call("manifest.publish", &pb.RecordRequest{}, nil); st != pb.Status_STATUS_INVALID {
		t.Fatalf("empty publish: %v", st)
	}
}

func TestLoginReportsLowPrekeysWithOwner(t *testing.T) {
	n := startNode(t)
	ctx := context.Background()
	if _, err := n.svc.ImportRecord(ctx, manifestRec(t, n, 1)); err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	rand.Read(secret)
	sum := sha256.Sum256(secret)
	inv := sign(t, pb.RecordType_INVITE, keys.ID16(n.svc.NetworkPub), &pb.Invite{InviteId: sum[:], ExpiresMs: time.Now().Add(time.Hour).UnixMilli()}, n.netPriv)
	if _, err := n.svc.ImportRecord(ctx, inv); err != nil {
		t.Fatal(err)
	}
	c := dial(t, n)
	anna, req := registerReq(t, n, secret, "anna") // 11 one-time keys owned by this node
	if st, msg := c.call("register", req, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("register: %v %s", st, msg)
	}
	login(t, c, anna)
	for i := 0; i < 2; i++ { // 11 -> 9
		if st, msg := c.call("prekeys.fetch", &pb.PreKeyFetchRequest{UserId: anna.id, DeviceId: 1}, &pb.PreKeyBundle{}); st != pb.Status_STATUS_OK {
			t.Fatalf("fetch: %v %s", st, msg)
		}
	}
	c2 := dial(t, n)
	login(t, c2, anna)
	var low pb.PrekeysLow
	proto.Unmarshal(c2.nextEvent("prekeys_low").Body, &low)
	if low.Remaining != 9 || !bytes.Equal(low.OwnerNode, n.svc.NodeID) {
		t.Fatalf("prekeys_low %v", &low)
	}
	// an unknown user logging in is told to retry (may not be replicated yet)
	c3 := dial(t, n)
	ghostPub, ghostPriv, _ := ed25519.GenerateKey(nil)
	ts := time.Now().UnixMilli()
	st, _ := c3.call("auth.login", &pb.LoginRequest{UserId: keys.ID16(ghostPub), DeviceId: 1, TsMs: ts,
		Signature: ed25519.Sign(ghostPriv, keys.AuthMessage(c3.hello.NodeId, c3.hello.Nonce, ts))}, nil)
	if st != pb.Status_STATUS_RETRY_LATER {
		t.Fatalf("unknown user login: %v", st)
	}
}
