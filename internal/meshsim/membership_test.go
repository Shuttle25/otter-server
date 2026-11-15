package meshsim

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/service"
	"ottermsg/server/internal/turnsrv"
)

var turnTag = turnsrv.UserTag

// tryLogin dials n and returns the status of a login as a.
func (s *sim) tryLogin(n *simNode, a *account) pb.Status {
	c := s.dial(n)
	defer c.close()
	ts := time.Now().UnixMilli()
	st, _ := c.call("auth.login", &pb.LoginRequest{UserId: a.id, DeviceId: 1, TsMs: ts,
		Signature: ed25519.Sign(a.priv, keys.AuthMessage(c.hello.NodeId, c.hello.Nonce, ts))}, nil)
	return st
}

// closed waits until the node closes c's connection.
func closed(t *testing.T, c *client) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-c.events:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("session of a revoked user still open")
		}
	}
}

func (s *sim) revoke(a *account) *pb.Record {
	return s.sign(pb.RecordType_REVOCATION, keys.ID16(s.netPub), &pb.Revocation{UserId: a.id, Reason: "left the family"}, s.netPriv)
}

// C2: an admin-signed revocation published on one node reaches all; the account loses login, mail, sessions and TURN.
func TestRevocationReplicatesAndBlocks(t *testing.T) {
	s := newSimWith(t, map[string]nodeOpts{"c": {turn: true}}, "a", "b", "c")
	a, b, c := s.node("a"), s.node("b"), s.node("c")
	anna := s.register(a, "anna")
	boris := s.register(a, "boris")
	eventually(t, "users everywhere", func() bool { return s.all(func(n *simNode) bool { return n.knows(anna) && n.knows(boris) }) })
	borisC := s.login(c, boris)
	var creds pb.TurnCredentials
	borisC.mustCall("turn.credentials", &pb.Empty{}, &creds)

	pub := s.dial(a)
	pub.mustCall("network.publish", &pb.RecordRequest{Record: s.revoke(boris)}, nil)
	pub.mustCall("network.publish", &pb.RecordRequest{Record: s.revoke(boris)}, nil) // another record, same effect: still OK
	ctx := context.Background()
	eventually(t, "revoked everywhere", func() bool {
		return s.all(func(n *simNode) bool { u, _ := n.st.UserByID(ctx, boris.id); return u != nil && u.Revoked })
	})
	closed(t, borisC)
	for _, n := range s.nodes {
		if st := s.tryLogin(n, boris); st != pb.Status_STATUS_REVOKED {
			t.Fatalf("%s: login of a revoked user: %v", n.label, st)
		}
	}
	annaB := s.login(b, anna)
	r := s.signAs(anna, pb.RecordType_ENVELOPE, &pb.Envelope{SenderUser: anna.id, SenderDevice: 1, Kind: pb.Envelope_SIGNAL,
		Recipients: []*pb.Recipient{{User: boris.id, Device: 1, Content: []byte("x")}}})
	if st, _ := annaB.call("msg.send", &pb.RecordRequest{Record: r}, nil); st != pb.Status_STATUS_NOT_FOUND {
		t.Fatalf("send to revoked: %v", st)
	}
	if !c.svc.TurnTagRevoked(turnTag(boris.id)) {
		t.Fatal("TURN still accepts the revoked user's tag")
	}
	if _, err := turnClient(t, "udp", c.turnAddr, &creds); err == nil {
		t.Fatal("TURN allocated with the revoked user's earlier credentials")
	}
	var batch pb.RecordBatch
	annaB.mustCall("directory.sync", &pb.Empty{}, &batch)
	if countType(&batch, pb.RecordType_REVOCATION) != 2 || countType(&batch, pb.RecordType_DIRECTORY_ENTRY) != 2 {
		t.Fatal("directory.sync must carry the entries and the revocations")
	}
}

// Threat model: a hostile node cannot revoke (or un-revoke) a member; its records are refused everywhere.
func TestForgedRevocationRefused(t *testing.T) {
	s := newSim(t, "a", "b")
	a, b := s.node("a"), s.node("b")
	anna := s.register(a, "anna")
	boris := s.register(a, "boris")
	eventually(t, "users on b", func() bool { return b.knows(anna) && b.knows(boris) })
	ctx := context.Background()
	forged := []*pb.Record{
		s.sign(pb.RecordType_REVOCATION, keys.ID16(s.netPub), &pb.Revocation{UserId: anna.id}, a.key), // network author, node key
		s.sign(pb.RecordType_REVOCATION, a.id, &pb.Revocation{UserId: anna.id}, a.key),                // node-authored
		s.signAs(boris, pb.RecordType_REVOCATION, &pb.Revocation{UserId: anna.id}),                    // member-authored
		s.sign(pb.RecordType_INVITE_RIGHTS, keys.ID16(s.netPub), &pb.InviteRights{UserId: boris.id, CanInvite: true, Version: 9}, a.key),
	}
	for i, r := range forged {
		if _, err := b.svc.ApplyReplicated(ctx, a.id, r); !errors.Is(err, service.ErrInvalid) {
			t.Fatalf("forged #%d replicated: %v", i, err)
		}
		cl := s.dial(b)
		if st, _ := cl.call("network.publish", &pb.RecordRequest{Record: r}, nil); st != pb.Status_STATUS_INVALID {
			t.Fatalf("forged #%d published: %v", i, st)
		}
		cl.close()
	}
	// a genuine record of another type is not published through network.publish
	cl := s.dial(b)
	if st, _ := cl.call("network.publish", &pb.RecordRequest{Record: s.signManifest(99, s.nodeInfos())}, nil); st != pb.Status_STATUS_INVALID {
		t.Fatalf("manifest through network.publish: %v", st)
	}
	cl.close()
	if st := s.tryLogin(b, anna); st != pb.Status_STATUS_OK {
		t.Fatalf("anna locked out by a forgery: %v", st)
	}
	// once really revoked, a newer entry by the account cannot bring it back
	pub := s.dial(b)
	pub.mustCall("network.publish", &pb.RecordRequest{Record: s.revoke(anna)}, nil)
	newer := s.signAs(anna, pb.RecordType_DIRECTORY_ENTRY, &pb.DirectoryEntry{UserId: anna.id, Username: "anna", DisplayName: "A",
		AccountPub: anna.priv.Public().(ed25519.PublicKey), IdentityPub: make([]byte, 33), IdentitySig: make([]byte, 64), Version: 2})
	if applied, err := b.svc.ApplyReplicated(ctx, a.id, newer); err != nil || applied {
		t.Fatalf("revoked author's record: applied=%v err=%v (must be skipped without error)", applied, err)
	}
	if st := s.tryLogin(b, anna); st != pb.Status_STATUS_REVOKED {
		t.Fatalf("revocation undone: %v", st)
	}
}

func countType(b *pb.RecordBatch, t pb.RecordType) int {
	n := 0
	for _, r := range b.Records {
		var body pb.RecordBody
		if proto.Unmarshal(r.Body, &body) == nil && body.Type == t {
			n++
		}
	}
	return n
}
