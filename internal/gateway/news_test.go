package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

func TestNewsMethods(t *testing.T) {
	n := startNode(t)
	ctx := context.Background()
	newsPub, newsPriv, _ := ed25519.GenerateKey(nil)
	self := &pb.NodeInfo{NodeId: n.svc.NodeID, NodePub: n.svc.NodeKeyPriv.Public().(ed25519.PublicKey), Label: "self"}
	m := sign(t, pb.RecordType_MANIFEST, keys.ID16(n.svc.NetworkPub), &pb.Manifest{Version: 1, NetworkPub: n.svc.NetworkPub,
		Nodes: []*pb.NodeInfo{self}, NewsKeys: [][]byte{newsPub}}, n.netPriv)
	if err := n.svc.PublishManifest(ctx, m); err != nil {
		t.Fatal(err)
	}
	announce := func(text string) *pb.RecordRequest {
		return &pb.RecordRequest{Record: sign(t, pb.RecordType_ANNOUNCEMENT, keys.ID16(newsPub), &pb.Announcement{TextRu: text}, newsPriv)}
	}

	// the admin publishes without logging in
	admin := dial(t, n)
	if st, msg := admin.call("news.publish", announce("Привет"), nil); st != pb.Status_STATUS_OK {
		t.Fatalf("news.publish: %v %s", st, msg)
	}
	_, other, _ := ed25519.GenerateKey(nil)
	bad := &pb.RecordRequest{Record: sign(t, pb.RecordType_ANNOUNCEMENT, keys.ID16(other.Public().(ed25519.PublicKey)), &pb.Announcement{TextRu: "x"}, other)}
	if st, _ := admin.call("news.publish", bad, nil); st != pb.Status_STATUS_INVALID {
		t.Fatalf("unknown news key: %v", st)
	}
	if st, _ := admin.call("news.list", &pb.Empty{}, nil); st != pb.Status_STATUS_UNAUTHORIZED {
		t.Fatalf("news.list without login: %v", st)
	}

	secret := make([]byte, 32)
	rand.Read(secret)
	sum := sha256.Sum256(secret)
	inv := sign(t, pb.RecordType_INVITE, keys.ID16(n.svc.NetworkPub), &pb.Invite{InviteId: sum[:], ExpiresMs: time.Now().Add(time.Hour).UnixMilli()}, n.netPriv)
	if _, err := n.svc.ImportRecord(ctx, inv); err != nil {
		t.Fatal(err)
	}
	c := dial(t, n)
	anna, req := registerReq(t, n, secret, "anna")
	if st, msg := c.call("register", req, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("register: %v %s", st, msg)
	}
	login(t, c, anna)
	var batch pb.RecordBatch
	if st, msg := c.call("news.list", &pb.Empty{}, &batch); st != pb.Status_STATUS_OK || len(batch.Records) != 1 {
		t.Fatalf("news.list: %v %s, %d records", st, msg, len(batch.Records))
	}

	if st, msg := admin.call("news.publish", announce("Ещё"), nil); st != pb.Status_STATUS_OK {
		t.Fatalf("second news.publish: %v %s", st, msg)
	}
	c.nextEvent("news")
	admin.noEvent("news", 200*time.Millisecond) // not logged in

	var chunk pb.ApkChunk
	if st, _ := c.call("apk.get", &pb.ApkGetRequest{Sha256: make([]byte, 32)}, &chunk); st != pb.Status_STATUS_NOT_FOUND {
		t.Fatalf("apk.get without apks: %v", st)
	}
}
