package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

// D111 on one node: the person registers again under the revoked name, the REKEY revokes the old account like a
// REVOCATION (sessions closed, "revocation applied" with reason rekey), hands over the name and is served by
// directory.sync; a REKEY by the old account (the thief) is refused and moves nothing.
func TestRekeyThroughNetworkPublish(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	var logs bytes.Buffer
	f.svc.Log = slog.New(slog.NewTextHandler(&logs, nil))
	f.notes.sessions = 1
	f.svc.LoadRevoked(ctx)
	old := f.mustRegister(f.invite(nil, time.Hour), "anna")

	// a non-revoked owner's name is still taken
	_, req := f.registerReq(f.invite(nil, time.Hour), "anna")
	if _, err := f.svc.Register(ctx, req); !errors.Is(err, ErrConflict) {
		t.Fatalf("taken name: %v", err)
	}
	// the admin's re-key invite is network-authored and goes through network.publish (Task 53)
	tk := f.newTicket(nil, 7*24*time.Hour)
	if err := f.svc.PublishNetworkRecord(ctx, tk.rec); err != nil {
		t.Fatalf("network invite: %v", err)
	}
	// a member's own invite is not a network record
	member := f.newTicket(old, time.Hour)
	if err := f.svc.PublishNetworkRecord(ctx, member.rec); !errors.Is(err, ErrInvalid) {
		t.Fatalf("member invite through network.publish: %v", err)
	}
	// a REVOCATION by the admin (step 1) makes the name registrable again
	f.netRecord(pb.RecordType_REVOCATION, &pb.Revocation{UserId: old.id, Reason: "lost phone"})
	nw := f.mustRegister(tk, "anna")
	if u, _ := f.svc.Store.UserByID(ctx, nw.id); u.Username != "anna#"+hex.EncodeToString(nw.id[:4]) {
		t.Fatalf("before REKEY: %q", u.Username)
	}

	// hostile: the thief holds old's key and signs a REKEY to an account of its own
	thief := sign(t, pb.RecordType_REKEY, old.id, &pb.Rekey{OldUserId: old.id, NewUserId: r16()}, old.priv)
	if err := f.svc.PublishNetworkRecord(ctx, thief); !errors.Is(err, ErrInvalid) {
		t.Fatalf("thief's REKEY: %v", err)
	}
	if _, err := f.svc.ApplyReplicated(ctx, r16(), thief); !errors.Is(err, ErrInvalid) {
		t.Fatalf("thief's REKEY replicated: %v", err)
	}
	// hostile: a node key signs a REKEY claiming the network as author
	nodeSigned := sign(t, pb.RecordType_REKEY, keys.ID16(f.svc.NetworkPub), &pb.Rekey{OldUserId: old.id, NewUserId: r16()}, f.svc.NodeKeyPriv)
	if _, err := f.svc.ApplyReplicated(ctx, r16(), nodeSigned); !errors.Is(err, ErrInvalid) {
		t.Fatalf("node-signed REKEY replicated: %v", err)
	}
	if owner, _ := f.svc.Store.UsernameOwner(ctx, "anna"); !bytes.Equal(owner, old.id) {
		t.Fatal("a refused REKEY moved the name")
	}

	logs.Reset()
	dirBefore := f.notes.dir
	f.netRecord(pb.RecordType_REKEY, &pb.Rekey{OldUserId: old.id, NewUserId: nw.id})
	if owner, _ := f.svc.Store.UsernameOwner(ctx, "anna"); !bytes.Equal(owner, nw.id) {
		t.Fatal("REKEY did not hand over the name")
	}
	recs, err := f.svc.Directory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var last pb.RecordBody
	if err := proto.Unmarshal(recs[len(recs)-1].Body, &last); err != nil || last.Type != pb.RecordType_REKEY {
		t.Fatalf("directory.sync does not end with the REKEY: %v", last.Type)
	}
	if f.notes.dir == dirBefore {
		t.Fatal("no directory event")
	}

	// a REKEY of an account not revoked before: the same effects as a REVOCATION, logged with reason rekey
	boris := f.mustRegister(f.invite(nil, time.Hour), "boris")
	f.netRecord(pb.RecordType_REKEY, &pb.Rekey{OldUserId: boris.id, NewUserId: r16()})
	if u, _ := f.svc.Store.UserByID(ctx, boris.id); !u.Revoked {
		t.Fatal("REKEY did not revoke the old account")
	}
	if n := strings.Count(logs.String(), `msg="revocation applied" user=`+userTag(boris.id)+` reason=rekey sessions_closed=1`); n != 1 {
		t.Fatalf("revocation lines: %d\n%s", n, logs.String())
	}
}

// A replicated entry without an invite chain is admitted when a REKEY names the account (the admin confirmed it).
func TestRekeyTargetAdmittedWithoutChain(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	old := f.mustRegister(f.invite(nil, time.Hour), "anna")
	nw, entry := f.replicatedEntry(nil, "anna", nil)
	if _, err := f.svc.ApplyReplicated(ctx, r16(), entry); !errors.Is(err, ErrInvalid) {
		t.Fatalf("chainless entry before the REKEY: %v", err)
	}
	f.netRecord(pb.RecordType_REKEY, &pb.Rekey{OldUserId: old.id, NewUserId: nw.id})
	if _, err := f.svc.ApplyReplicated(ctx, r16(), entry); err != nil {
		t.Fatalf("chainless REKEY target: %v", err)
	}
	if owner, _ := f.svc.Store.UsernameOwner(ctx, "anna"); !bytes.Equal(owner, nw.id) {
		t.Fatal("the REKEY target did not take the name")
	}
}
