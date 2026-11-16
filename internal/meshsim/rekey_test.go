package meshsim

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/service"
)

func (s *sim) networkPublish(n *simNode, rec *pb.Record) pb.Status {
	c := s.dial(n)
	defer c.close()
	st, _ := c.call("network.publish", &pb.RecordRequest{Record: rec}, &pb.Empty{})
	return st
}

func (n *simNode) owner(name string) []byte {
	id, _ := n.st.UsernameOwner(context.Background(), name)
	return id
}

// D111 (limit 2): the admin revokes a lost phone's account, the person registers again under the same name on
// another node, and the admin's REKEY hands the name over on every node. Forged REKEYs (by the thief holding the
// old key, by a node key) are refused through network.publish and through replication.
func TestRekeyMovesUsernameEverywhere(t *testing.T) {
	s := newSim(t, "a", "b")
	a, b := s.node("a"), s.node("b")
	ctx := context.Background()
	old := s.register(a, "anna")
	eventually(t, "b knows anna", func() bool { return b.knows(old) })
	netID := keys.ID16(s.netPub)

	// hostile: the thief holds old's key and signs a REKEY to an account of its own
	_, thiefPriv, _ := ed25519.GenerateKey(nil)
	thiefID := keys.ID16(thiefPriv.Public().(ed25519.PublicKey))
	forged := s.sign(pb.RecordType_REKEY, old.id, &pb.Rekey{OldUserId: old.id, NewUserId: thiefID}, old.priv)
	if st := s.networkPublish(a, forged); st != pb.Status_STATUS_INVALID {
		t.Fatalf("forged REKEY via network.publish: %v", st)
	}
	// hostile: a node signs a REKEY in the network's name and injects it through replication
	nodeSigned := s.sign(pb.RecordType_REKEY, netID, &pb.Rekey{OldUserId: old.id, NewUserId: thiefID}, a.key)
	if _, err := b.svc.ApplyReplicated(ctx, a.id, nodeSigned); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("node-signed REKEY replicated: %v", err)
	}

	// a non-revoked owner's name stays taken
	if _, st, _ := s.tryRegister(b, "anna", s.invite(b)); st != pb.Status_STATUS_CONFLICT {
		t.Fatalf("taken name: %v", st)
	}
	// step 1: the admin revokes old — then the person registers again with the same name on b
	if st := s.networkPublish(a, s.sign(pb.RecordType_REVOCATION, netID, &pb.Revocation{UserId: old.id, Reason: "rekey"}, s.netPriv)); st != pb.Status_STATUS_OK {
		t.Fatalf("REVOCATION: %v", st)
	}
	eventually(t, "old revoked on b", func() bool { u, _ := b.st.UserByID(ctx, old.id); return u != nil && u.Revoked })
	nw := s.register(b, "anna")
	eventually(t, "a knows new", func() bool { return a.knows(nw) })
	if !bytes.Equal(a.owner("anna"), old.id) || !bytes.Equal(b.owner("anna"), old.id) {
		t.Fatal("before the REKEY the name stays with old")
	}

	// step 2: REKEY
	if st := s.networkPublish(a, s.sign(pb.RecordType_REKEY, netID, &pb.Rekey{OldUserId: old.id, NewUserId: nw.id}, s.netPriv)); st != pb.Status_STATUS_OK {
		t.Fatalf("REKEY: %v", st)
	}
	for _, n := range []*simNode{a, b} {
		eventually(t, n.label+": anna is the new account", func() bool { return bytes.Equal(n.owner("anna"), nw.id) })
	}
	c := s.login(b, nw)
	defer c.close()
	var batch pb.RecordBatch
	c.mustCall("directory.sync", &pb.Empty{}, &batch)
	found := false
	for _, r := range batch.Records {
		var body pb.RecordBody
		if proto.Unmarshal(r.Body, &body) == nil && body.Type == pb.RecordType_REKEY {
			found = true
		}
	}
	if !found {
		t.Fatal("directory.sync without the REKEY")
	}
}
