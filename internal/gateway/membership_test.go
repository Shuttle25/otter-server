package gateway

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

func revocation(t *testing.T, n *node, user []byte) *pb.Record {
	return sign(t, pb.RecordType_REVOCATION, keys.ID16(n.svc.NetworkPub), &pb.Revocation{UserId: user, Reason: "test"}, n.netPriv)
}

// C2: a logged-in session of a revoked user is refused for any request, even when the revocation was stored without
// the session being closed (the close raced the request).
func TestRevokedSessionRefusedEvenIfCloseRaced(t *testing.T) {
	n := startNode(t)
	as, cs := members(t, n, "anna")
	rec := revocation(t, n, as[0].id)
	var body pb.RecordBody
	if err := proto.Unmarshal(rec.Body, &body); err != nil {
		t.Fatal(err)
	}
	if _, _, err := n.svc.Store.ApplyFrom(context.Background(), rec, &body, n.svc.NodeID); err != nil { // no notification
		t.Fatal(err)
	}
	if st, ok := tryCall(cs[0], "ping", &pb.Empty{}); !ok || st != pb.Status_STATUS_REVOKED {
		t.Fatalf("request of a revoked session: %v answered=%v", st, ok)
	}
	waitClosed(t, cs[0])
}

// network.publish closes the revoked user's open sessions at once.
func TestNetworkPublishClosesSessions(t *testing.T) {
	n := startNode(t)
	as, cs := members(t, n, "anna", "boris")
	pub := dial(t, n)
	if st, msg := pub.call("network.publish", &pb.RecordRequest{Record: revocation(t, n, as[0].id)}, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("publish: %v %s", st, msg)
	}
	waitClosed(t, cs[0])
	if st, msg := cs[1].call("ping", &pb.Empty{}, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("other member: %v %s", st, msg)
	}
	if st, _ := pub.call("network.publish", &pb.RecordRequest{}, nil); st != pb.Status_STATUS_INVALID {
		t.Fatalf("empty publish: %v", st)
	}
}

func waitClosed(t *testing.T, c *client) {
	t.Helper()
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if c.c.Write(context.Background(), websocket.MessageBinary, []byte{0}) != nil {
			return
		}
	}
	t.Fatal("the revoked user's connection is still open after 1 s")
}

// admin.users answers only the network key signing this connection's nonce: a member, a replayed signature from
// another connection or a stale timestamp get UNAUTHORIZED (C2, the admin's member list).
func TestAdminUsersNeedsNetworkKeyOverNonce(t *testing.T) {
	n := startNode(t)
	as, _ := members(t, n, "anna", "boris")
	if st, msg := dial(t, n).call("network.publish", &pb.RecordRequest{Record: revocation(t, n, as[1].id)}, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("revoke: %v %s", st, msg)
	}
	adminReq := func(c *client, k ed25519.PrivateKey, nonce []byte, ts int64) *pb.AdminRequest {
		return &pb.AdminRequest{TsMs: ts, Signature: ed25519.Sign(k, keys.AdminAuthMessage(c.hello.NodeId, nonce, ts))}
	}
	now := time.Now().UnixMilli()
	c := dial(t, n)
	other := dial(t, n)
	for name, r := range map[string]*pb.AdminRequest{
		"empty":         {},
		"member key":    adminReq(c, as[0].priv, c.hello.Nonce, now),
		"other nonce":   adminReq(c, n.netPriv, other.hello.Nonce, now),
		"stale":         adminReq(c, n.netPriv, c.hello.Nonce, now-int64(time.Hour/time.Millisecond)),
		"login message": {TsMs: now, Signature: ed25519.Sign(n.netPriv, keys.AuthMessage(c.hello.NodeId, c.hello.Nonce, now))},
	} {
		if st, _ := c.call("admin.users", r, nil); st != pb.Status_STATUS_UNAUTHORIZED {
			t.Fatalf("%s: %v", name, st)
		}
	}
	var batch pb.RecordBatch
	if st, msg := c.call("admin.users", adminReq(c, n.netPriv, c.hello.Nonce, now), &batch); st != pb.Status_STATUS_OK {
		t.Fatalf("admin.users: %v %s", st, msg)
	}
	types := map[pb.RecordType]int{}
	for _, r := range batch.Records {
		var b pb.RecordBody
		proto.Unmarshal(r.Body, &b)
		types[b.Type]++
	}
	if types[pb.RecordType_DIRECTORY_ENTRY] != 2 || types[pb.RecordType_REVOCATION] != 1 {
		t.Fatalf("batch: %v", types)
	}
}
