package meshsim

import (
	"context"
	"errors"
	"testing"
	"time"

	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
	"ottermsg/server/internal/service"
)

// TestSigCutover: after the cut-over manifest (D109/D110) a v1 signature on a record created after sig_v1_until_ms
// is refused from a client and from a hostile peer; v1 records created before it still replicate; v2 is accepted.
func TestSigCutover(t *testing.T) {
	s := newSim(t, "a", "b")
	a, b := s.node("a"), s.node("b")
	anna, bob := s.register(a, "anna"), s.register(a, "bobby")
	eventually(t, "b knows both", func() bool { return b.knows(anna) && b.knows(bob) })
	ack := func() *pb.Ack { return &pb.Ack{EnvelopeIds: [][]byte{make([]byte, 32)}, DeviceId: 1} }
	before := time.Now().UnixMilli()
	old := s.signAsWith(anna, pb.RecordType_ACK, ack(), before, records.SigContext{})

	cut := time.Now().UnixMilli() + 1
	v2ctx := records.SigContext{NetworkID: keys.ID16(s.netPub), V2: true}
	m := &pb.Manifest{Version: 2, IssuedMs: cut, NetworkPub: s.netPub, Nodes: s.nodeInfos(), SigV1UntilMs: cut}
	s.manifest = s.signWith(pb.RecordType_MANIFEST, keys.ID16(s.netPub), m, s.netPriv, v2ctx)
	for _, n := range s.nodes {
		if _, err := n.svc.ImportRecord(context.Background(), s.manifest); err != nil {
			t.Fatal(err)
		}
		eventually(t, n.label+" loads the cut-over manifest", func() bool { return n.svc.CurrentManifest().GetSigV1UntilMs() == cut })
	}

	late := s.signAsWith(anna, pb.RecordType_ACK, ack(), cut+1, records.SigContext{})
	c := s.login(a, anna)
	if st, msg := c.call("msg.ack", &pb.RecordRequest{Record: late}, &pb.Empty{}); st != pb.Status_STATUS_INVALID {
		t.Fatalf("v1 after cut-over from a client: %v %s", st, msg)
	}
	// a hostile peer injects the same record into b
	if _, err := b.svc.ApplyReplicated(context.Background(), a.id, late); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("v1 after cut-over from a peer: %v", err)
	}
	if _, err := b.svc.ApplyReplicated(context.Background(), a.id, old); err != nil {
		t.Fatalf("v1 before cut-over refused: %v", err)
	}
	// a v2 record signed for another network is refused
	otherNet := records.SigContext{NetworkID: make([]byte, 16), V2: true}
	foreign := s.signAsWith(anna, pb.RecordType_ACK, ack(), cut+2, otherNet)
	if _, err := b.svc.ApplyReplicated(context.Background(), a.id, foreign); !errors.Is(err, service.ErrInvalid) {
		t.Fatalf("v2 for another network from a peer: %v", err)
	}
	v2 := s.signAsWith(anna, pb.RecordType_ACK, ack(), cut+2, v2ctx)
	c.mustCall("msg.ack", &pb.RecordRequest{Record: v2}, &pb.Empty{})
}
