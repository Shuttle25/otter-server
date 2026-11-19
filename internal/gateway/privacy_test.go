package gateway

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/service"
)

// hasEntry reports whether recs carry a DIRECTORY_ENTRY of id.
func hasEntry(t *testing.T, recs []*pb.Record, id []byte) bool {
	t.Helper()
	for _, r := range recs {
		var b pb.RecordBody
		if err := proto.Unmarshal(r.Body, &b); err != nil {
			t.Fatal(err)
		}
		if b.Type == pb.RecordType_DIRECTORY_ENTRY && bytes.Equal(b.Author, id) {
			return true
		}
	}
	return false
}

// M9.5 (D135, D137) over the wire: sync and list give the same filtered set, admin.users all, lookup and get find an
// unrelated member, lookups are limited.
func TestPrivacyMethods(t *testing.T) {
	n := startNode(t)
	as, cs := members(t, n, "anna", "boris") // both network-invited: unrelated, unlisted
	anna, boris, ca := as[0], as[1], cs[0]
	var listResp, syncResp pb.RecordBatch
	if st, msg := ca.call("directory.list", &pb.Empty{}, &listResp); st != pb.Status_STATUS_OK {
		t.Fatalf("list: %v %s", st, msg)
	}
	if st, msg := ca.call("directory.sync", &pb.Empty{}, &syncResp); st != pb.Status_STATUS_OK {
		t.Fatalf("sync: %v %s", st, msg)
	}
	if len(listResp.Records) != len(syncResp.Records) || !hasEntry(t, listResp.Records, anna.id) {
		t.Fatalf("list %d != sync %d, or anna's own entry missing", len(listResp.Records), len(syncResp.Records))
	}
	if hasEntry(t, listResp.Records, boris.id) || hasEntry(t, syncResp.Records, boris.id) {
		t.Fatal("anna sees unrelated, unlisted boris")
	}

	adm := dial(t, n)
	now := time.Now().UnixMilli()
	var all pb.RecordBatch
	areq := &pb.AdminRequest{TsMs: now, Signature: ed25519.Sign(n.netPriv, keys.AdminAuthMessage(adm.hello.NodeId, adm.hello.Nonce, now))}
	if st, msg := adm.call("admin.users", areq, &all); st != pb.Status_STATUS_OK {
		t.Fatalf("admin.users: %v %s", st, msg)
	}
	if !hasEntry(t, all.Records, anna.id) || !hasEntry(t, all.Records, boris.id) {
		t.Fatal("admin.users is filtered")
	}

	var found pb.RecordBatch
	if st, msg := ca.call("directory.lookup", &pb.DirectoryLookupRequest{Username: "@Boris"}, &found); st != pb.Status_STATUS_OK {
		t.Fatalf("lookup: %v %s", st, msg)
	}
	if !hasEntry(t, found.Records, boris.id) {
		t.Fatal("lookup did not return boris")
	}
	if st, _ := ca.call("directory.lookup", &pb.DirectoryLookupRequest{Username: "nobody"}, nil); st != pb.Status_STATUS_NOT_FOUND {
		t.Fatalf("unknown: %v", st)
	}
	var got pb.RecordBatch
	if st, _ := ca.call("directory.get", &pb.DirectoryGetRequest{UserIds: [][]byte{boris.id}}, &got); st != pb.Status_STATUS_OK || len(got.Records) != 1 {
		t.Fatalf("get: %v %d", st, len(got.Records))
	}
	if st, _ := ca.call("directory.get", &pb.DirectoryGetRequest{UserIds: make([][]byte, service.MaxDirectoryGet+1)}, nil); st != pb.Status_STATUS_INVALID {
		t.Fatalf("get too many: %v", st)
	}
	for i := 2; i < service.LookupsPerHour; i++ { // two lookups above
		if st, msg := ca.call("directory.lookup", &pb.DirectoryLookupRequest{Username: fmt.Sprintf("nobody%d", i)}, nil); st != pb.Status_STATUS_NOT_FOUND {
			t.Fatalf("lookup %d: %v %s", i+1, st, msg)
		}
	}
	if st, _ := ca.call("directory.lookup", &pb.DirectoryLookupRequest{Username: "boris"}, nil); st != pb.Status_STATUS_QUOTA {
		t.Fatalf("lookup %d: %v, want quota", service.LookupsPerHour+1, st)
	}
	if !userWrites["directory.lookup"] {
		t.Fatal("directory.lookup is not in the per-user write bucket")
	}
}

// D139: a logged-in member learns the node's version from the login answer; hello (before login) does not carry it.
func TestLoginVersion(t *testing.T) {
	n := startNode(t, func(g *Gateway) { g.Version = "9.9.9" })
	secret := netInvite(t, n)
	c := dial(t, n)
	a, req := registerReq(t, n, secret, "anna")
	if st, msg := c.call("register", req, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("register: %v %s", st, msg)
	}
	if raw, _ := proto.Marshal(c.hello); bytes.Contains(raw, []byte("9.9.9")) {
		t.Fatal("hello carries the version")
	}
	if resp := loginResp(t, c, a); resp.ServerVersion != "9.9.9" {
		t.Fatalf("server_version %q", resp.ServerVersion)
	}
}
