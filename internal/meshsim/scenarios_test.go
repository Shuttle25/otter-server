package meshsim

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
)

func (s *sim) all(cond func(n *simNode) bool) bool {
	for _, n := range s.nodes {
		if !cond(n) {
			return false
		}
	}
	return true
}

// 1. Register on A → visible on B and C; message via B to a user on C; ACK on C removes the envelope everywhere.
func TestRegisterReplicateDeliverAck(t *testing.T) {
	s := newSim(t, "a", "b", "c")
	a, b, c := s.node("a"), s.node("b"), s.node("c")
	anna := s.register(a, "anna")
	boris := s.register(a, "boris")
	eventually(t, "anna and boris on B and C", func() bool { return b.knows(anna) && c.knows(anna) && b.knows(boris) && c.knows(boris) })
	annaC := s.login(c, anna)
	borisB := s.login(b, boris)
	k := s.send(borisB, boris, anna, "hi")
	got := annaC.envelopes()
	if !contains(got, k) {
		t.Fatal("not delivered on C")
	}
	eventually(t, "envelope on A", func() bool { return a.has(k) })
	s.ack(annaC, anna, k)
	eventually(t, "envelope gone on A, B, C", func() bool { return s.all(func(n *simNode) bool { return !n.has(k) && n.mailbox(anna) == 0 }) })
}

// 2. A↔C blocked, both reach B → a message from an A-user to a C-user arrives via B.
func TestTransitiveViaB(t *testing.T) {
	s := newSim(t, "a", "b", "c")
	a, b, c := s.node("a"), s.node("b"), s.node("c")
	s.part.Block(a, c)
	anna := s.register(a, "anna")
	boris := s.register(c, "boris")
	eventually(t, "users known everywhere", func() bool {
		return s.all(func(n *simNode) bool { return n.knows(anna) && n.knows(boris) })
	})
	borisC := s.login(c, boris)
	annaA := s.login(a, anna)
	k := s.send(annaA, anna, boris, "via b")
	if !contains(borisC.envelopes(), k) {
		t.Fatal("not delivered")
	}
	if !b.has(k) {
		t.Fatal("B must carry it")
	}
}

// 3. Stop B; A and C keep exchanging; start B → B catches up; envelopes ACKed meanwhile are absent on B.
func TestRestartCatchesUp(t *testing.T) {
	s := newSim(t, "a", "b", "c")
	a, b, c := s.node("a"), s.node("b"), s.node("c")
	anna := s.register(a, "anna")
	boris := s.register(c, "boris")
	eventually(t, "users everywhere", func() bool { return s.all(func(n *simNode) bool { return n.knows(anna) && n.knows(boris) }) })
	s.stop(b)
	annaA := s.login(a, anna)
	borisC := s.login(c, boris)
	acked := s.send(annaA, anna, boris, "1")
	if !contains(borisC.envelopes(), acked) {
		t.Fatal("A→C without B")
	}
	s.ack(borisC, boris, acked)
	pending := s.send(borisC, boris, anna, "2")
	if !contains(annaA.envelopes(), pending) {
		t.Fatal("C→A without B")
	}
	eventually(t, "ack applied on A", func() bool { return !a.has(acked) })
	vera := s.register(c, "vera")
	s.start(b)
	eventually(t, "B caught up", func() bool { return b.knows(vera) && b.has(pending) && b.mailbox(anna) == 1 })
	time.Sleep(300 * time.Millisecond)
	if b.has(acked) || b.mailbox(boris) != 0 {
		t.Fatal("acked envelope resurrected on B")
	}
}

// 4. Split {A} / {B,C}: traffic inside each side works, cross-side messages queue; heal → delivered and all nodes converge.
func TestSplitAndHeal(t *testing.T) {
	s := newSim(t, "a", "b", "c")
	a, b, c := s.node("a"), s.node("b"), s.node("c")
	anna, dina := s.register(a, "anna"), s.register(a, "dina")
	boris, vera := s.register(b, "boris"), s.register(c, "vera")
	eventually(t, "users everywhere", func() bool {
		return s.all(func(n *simNode) bool { return n.knows(anna) && n.knows(dina) && n.knows(boris) && n.knows(vera) })
	})
	s.part.Block(a, b)
	s.part.Block(a, c)
	annaA, dinaA := s.login(a, anna), s.login(a, dina)
	borisB, veraC := s.login(b, boris), s.login(c, vera)

	inA := s.send(annaA, anna, dina, "inside A")
	if !contains(dinaA.envelopes(), inA) {
		t.Fatal("inside A")
	}
	inBC := s.send(borisB, boris, vera, "inside BC")
	if !contains(veraC.envelopes(), inBC) {
		t.Fatal("inside BC")
	}
	cross := s.send(annaA, anna, vera, "cross")
	veraC.noEnvelopes(500 * time.Millisecond)
	if c.has(cross) || b.has(cross) {
		t.Fatal("crossed the partition")
	}
	s.part.Heal(a, b)
	s.part.Heal(a, c)
	if !contains(veraC.envelopes(), cross) {
		t.Fatal("not delivered after heal")
	}
	eventually(t, "same record keys on all nodes", func() bool {
		ka := a.recordKeys()
		return ka == b.recordKeys() && ka == c.recordKeys()
	})
}

// 5. "anna" registered on A and C by different users during a split → after heal every node agrees on the owner.
func TestUsernameClashAcrossSplit(t *testing.T) {
	s := newSim(t, "a", "b", "c")
	a, b, c := s.node("a"), s.node("b"), s.node("c")
	s.part.Block(a, b)
	s.part.Block(a, c)
	first := s.register(a, "anna")
	time.Sleep(5 * time.Millisecond) // a later entry created_ms
	second := s.register(c, "anna")
	s.part.Heal(a, b)
	s.part.Heal(a, c)
	ctx := context.Background()
	want := "anna#" + hex.EncodeToString(second.id[:4])
	eventually(t, "all nodes: first owns anna, second renamed", func() bool {
		return s.all(func(n *simNode) bool {
			owner, _ := n.st.UsernameOwner(ctx, "anna")
			u, _ := n.st.UserByID(ctx, second.id)
			return bytes.Equal(owner, first.id) && u != nil && u.Username == want
		})
	})
}

// 6. A one-time key handed out by A is consumed on B too (PREKEY_CONSUMED replicates).
func TestPrekeyConsumptionReplicates(t *testing.T) {
	s := newSim(t, "a", "b", "c")
	a, b := s.node("a"), s.node("b")
	anna := s.register(a, "anna", a, b) // 11 keys owned by A and 11 by B
	boris := s.register(a, "boris")
	ctx := context.Background()
	counts := func(n *simNode) map[string]int { m, _ := n.st.PrekeyCounts(ctx, anna.id, 1); return m }
	eventually(t, "keys on B", func() bool { return counts(b)[string(a.id)] == 11 })
	borisA := s.login(a, boris)
	var bundle pb.PreKeyBundle
	borisA.mustCall("prekeys.fetch", &pb.PreKeyFetchRequest{UserId: anna.id, DeviceId: 1}, &bundle)
	if bundle.OneTime == nil || !bytes.Equal(bundle.OneTime.OwnerNode, a.id) {
		t.Fatalf("bundle %v", &bundle)
	}
	eventually(t, "counts equal on A and B", func() bool {
		ca, cb := counts(a), counts(b)
		return ca[string(a.id)] == 10 && cb[string(a.id)] == 10 && ca[string(b.id)] == 11 && cb[string(b.id)] == 11
	})
}

// 7. Manifest v2 published on A reaches B and C; a client logged in on C receives the manifest event.
func TestManifestPropagates(t *testing.T) {
	s := newSim(t, "a", "b", "c")
	a, b, c := s.node("a"), s.node("b"), s.node("c")
	vera := s.register(c, "vera")
	veraC := s.login(c, vera)
	var body pb.RecordBody
	var m pb.Manifest
	proto.Unmarshal(s.manifest.Body, &body)
	proto.Unmarshal(body.Payload, &m)
	v2 := s.signManifest(2, m.Nodes)
	admin := s.dial(a)
	admin.mustCall("manifest.publish", &pb.RecordRequest{Record: v2}, nil)
	eventually(t, "v2 on B and C", func() bool {
		return b.svc.CurrentManifest().Version == 2 && c.svc.CurrentManifest().Version == 2
	})
	var mr pb.ManifestResponse
	proto.Unmarshal(veraC.nextEvent("manifest").Body, &mr)
	if !proto.Equal(mr.Manifest, v2) {
		t.Fatal("event carries a different manifest")
	}
}

// 8. The same envelope pushed by two nodes carries the same record key (clients deduplicate by it).
func TestSameEnvelopeFromTwoNodes(t *testing.T) {
	s := newSim(t, "a", "b", "c")
	a, b := s.node("a"), s.node("b")
	anna, boris := s.register(a, "anna"), s.register(a, "boris")
	eventually(t, "users on B", func() bool { return b.knows(anna) && b.knows(boris) })
	borisA := s.login(a, boris)
	k := s.send(borisA, boris, anna, "twice")
	eventually(t, "envelope on B", func() bool { return b.mailbox(anna) == 1 })
	onA := s.login(a, anna).envelopes()
	onB := s.login(b, anna).envelopes()
	if !contains(onA, k) || !contains(onB, k) {
		t.Fatalf("keys differ: %x vs %x", onA, onB)
	}
}
