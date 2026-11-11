package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

func TestDirectoryUpdate(t *testing.T) {
	n := startNode(t)
	ctx := context.Background()
	secret := make([]byte, 32)
	rand.Read(secret)
	sum := sha256.Sum256(secret)
	inv := sign(t, pb.RecordType_INVITE, keys.ID16(n.svc.NetworkPub), &pb.Invite{InviteId: sum[:], ExpiresMs: time.Now().Add(time.Hour).UnixMilli()}, n.netPriv)
	if _, err := n.svc.ImportRecord(ctx, inv); err != nil {
		t.Fatal(err)
	}
	ca := dial(t, n)
	anna, req := registerReq(t, n, secret, "anna")
	if st, msg := ca.call("register", req, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("register: %v %s", st, msg)
	}
	login(t, ca, anna)
	watcher := dial(t, n) // a second session of anna stands in for "another member's app"
	login(t, watcher, anna)

	entry := func(username, display string, version uint64) *pb.Record {
		var cur pb.DirectoryEntry
		var body pb.RecordBody
		proto.Unmarshal(req.DirectoryEntry.Body, &body)
		proto.Unmarshal(body.Payload, &cur)
		cur.Username, cur.DisplayName, cur.Version, cur.RegisteredMs = username, display, version, body.CreatedMs
		return sign(t, pb.RecordType_DIRECTORY_ENTRY, anna.id, &cur, anna.priv)
	}
	if st, msg := ca.call("directory.update", &pb.RecordRequest{Record: entry("anna", "Анна Петровна", 2)}, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("update: %v %s", st, msg)
	}
	watcher.nextEvent("directory")
	var dir pb.RecordBatch
	ca.call("directory.sync", &pb.Empty{}, &dir)
	if got := displayNameOf(t, dir.Records, anna.id); got != "Анна Петровна" {
		t.Fatalf("directory shows %q", got)
	}
	if st, _ := ca.call("directory.update", &pb.RecordRequest{Record: entry("anna", "Старое", 2)}, nil); st != pb.Status_STATUS_CONFLICT {
		t.Fatalf("same version: %v", st)
	}
	if st, _ := ca.call("directory.update", &pb.RecordRequest{Record: entry("anya", "Аня", 3)}, nil); st != pb.Status_STATUS_INVALID {
		t.Fatalf("username change: %v", st)
	}
	ack := sign(t, pb.RecordType_ACK, anna.id, &pb.Ack{EnvelopeIds: [][]byte{make([]byte, 32)}}, anna.priv)
	if st, _ := ca.call("directory.update", &pb.RecordRequest{Record: ack}, nil); st != pb.Status_STATUS_INVALID {
		t.Fatalf("non-directory record: %v", st)
	}

	// someone else's entry: boris (invited by anna) re-signs his own v2; anna's session submits it
	s2 := make([]byte, 32)
	rand.Read(s2)
	sum2 := sha256.Sum256(s2)
	invRec := sign(t, pb.RecordType_INVITE, anna.id, &pb.Invite{InviteId: sum2[:], ExpiresMs: time.Now().Add(time.Hour).UnixMilli()}, anna.priv)
	if st, msg := ca.call("invite.create", &pb.RecordRequest{Record: invRec}, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("invite: %v %s", st, msg)
	}
	cb := dial(t, n)
	boris, req2 := registerReq(t, n, s2, "boris")
	if st, msg := cb.call("register", req2, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("register boris: %v %s", st, msg)
	}
	var be pb.DirectoryEntry
	var bb pb.RecordBody
	proto.Unmarshal(req2.DirectoryEntry.Body, &bb)
	proto.Unmarshal(bb.Payload, &be)
	be.Version, be.DisplayName = 2, "Not Boris"
	if st, _ := ca.call("directory.update", &pb.RecordRequest{Record: sign(t, pb.RecordType_DIRECTORY_ENTRY, boris.id, &be, boris.priv)}, nil); st != pb.Status_STATUS_UNAUTHORIZED {
		t.Fatalf("someone else's entry: %v", st)
	}
	if st, _ := cb.call("directory.update", &pb.RecordRequest{Record: entry("anna", "x", 5)}, nil); st != pb.Status_STATUS_UNAUTHORIZED {
		t.Fatalf("before login: %v", st)
	}
}

func displayNameOf(t *testing.T, recs []*pb.Record, id []byte) string {
	for _, r := range recs {
		var b pb.RecordBody
		var e pb.DirectoryEntry
		proto.Unmarshal(r.Body, &b)
		proto.Unmarshal(b.Payload, &e)
		if bytes.Equal(e.UserId, id) {
			return e.DisplayName
		}
	}
	t.Fatal("user not in directory")
	return ""
}
