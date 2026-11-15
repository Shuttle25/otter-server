package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

type stubTurn struct{}

func (stubTurn) Issue([]byte, time.Time) *pb.TurnCredentials {
	return &pb.TurnCredentials{Username: "u"}
}

func TestRevokedGetsNoTurnAndRecordsAreSkipped(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	f.svc.Turn = stubTurn{}
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna")
	if _, err := f.svc.TurnCredentials(ctx, anna.id); err != nil {
		t.Fatal(err)
	}
	rev := sign(t, pb.RecordType_REVOCATION, keys.ID16(f.svc.NetworkPub), &pb.Revocation{UserId: anna.id}, f.netPriv)
	if err := f.svc.PublishNetworkRecord(ctx, rev); err != nil {
		t.Fatal(err)
	}
	if len(f.notes.revoked) != 1 || string(f.notes.revoked[0]) != string(anna.id) {
		t.Fatalf("sessions of the revoked user not closed: %x", f.notes.revoked)
	}
	if err := f.svc.PublishNetworkRecord(ctx, rev); err != nil { // the same record again: idempotent
		t.Fatal(err)
	}
	if _, err := f.svc.TurnCredentials(ctx, anna.id); !errors.Is(err, ErrRevoked) {
		t.Fatalf("turn for revoked: %v", err)
	}
	if _, err := f.svc.TurnCredentials(ctx, r16()); !errors.Is(err, ErrRevoked) {
		t.Fatalf("turn for an unknown user: %v", err)
	}
	inv := sign(t, pb.RecordType_INVITE, anna.id, &pb.Invite{InviteId: make([]byte, 32), ExpiresMs: time.Now().Add(time.Hour).UnixMilli()}, anna.priv)
	if applied, err := f.svc.ApplyReplicated(ctx, r16(), inv); err != nil || applied {
		t.Fatalf("revoked author's invite: applied=%v err=%v", applied, err)
	}
	if err := f.svc.PublishNetworkRecord(ctx, f.manifestRec(5)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("manifest through network.publish: %v", err)
	}
}

// replicatedEntry builds a version-1 entry for a fresh account, chained to tk (nil = no chain).
func (f *fx) replicatedEntry(tk *ticket, name string, mod func(*pb.DirectoryEntry)) (*user, *pb.Record) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	u := &user{id: keys.ID16(pub), priv: priv}
	e := &pb.DirectoryEntry{UserId: u.id, Username: name, DisplayName: name, AccountPub: pub, IdentityPub: make([]byte, 33),
		IdentitySig: make([]byte, 64), Version: 1, CanInvite: true, RegisteredMs: time.Now().UnixMilli()}
	if tk != nil {
		if err := records.Redeem(e, tk.rec, tk.secret); err != nil {
			f.t.Fatal(err)
		}
	}
	if mod != nil {
		mod(e)
	}
	return u, sign(f.t, pb.RecordType_DIRECTORY_ENTRY, u.id, e, priv)
}

// netRecord signs a REVOCATION or INVITE_RIGHTS with the network key and publishes it.
func (f *fx) netRecord(typ pb.RecordType, payload proto.Message) {
	if err := f.svc.PublishNetworkRecord(context.Background(), sign(f.t, typ, keys.ID16(f.svc.NetworkPub), payload, f.netPriv)); err != nil {
		f.t.Fatal(err)
	}
}

func TestAdmissionChain(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	f.withManifest(1)
	peer := r16()
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna")
	if u, _ := f.svc.Store.UserByID(ctx, anna.id); !u.CanInvite {
		t.Fatal("network-invited account must be able to invite")
	}
	// a member's invitee may invite by default (D101); the entry's own claim is ignored (C6)
	boris, req := f.registerReqWith(f.invite(anna, time.Hour), "boris", func(e *pb.DirectoryEntry, _ *pb.PreKeys, _ *pb.InviteUsed) { e.CanInvite = false })
	if _, err := f.svc.Register(ctx, req); err != nil {
		t.Fatal(err)
	}
	if u, _ := f.svc.Store.UserByID(ctx, boris.id); !u.CanInvite {
		t.Fatal("a member's invitee must be able to invite by default (D101)")
	}

	// a hostile peer: a self-signed account without any chain
	_, bare := f.replicatedEntry(nil, "mallory", nil)
	if _, err := f.svc.ApplyReplicated(ctx, peer, bare); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no chain: %v", err)
	}
	// boris's chain copied into another account: the proof binds boris's key
	borisRaw, _ := f.svc.Store.UserByID(ctx, boris.id)
	stolen := chainOf(t, borisRaw.EntryRaw)
	_, copied := f.replicatedEntry(nil, "mallory", func(e *pb.DirectoryEntry) { e.InviteRecord, e.InviteProof = stolen.InviteRecord, stolen.InviteProof })
	if _, err := f.svc.ApplyReplicated(ctx, peer, copied); !errors.Is(err, ErrInvalid) {
		t.Fatalf("copied chain: %v", err)
	}
	// an INVITE "by the network" signed with another key
	_, nodeKey, _ := ed25519.GenerateKey(nil)
	inv, _ := records.InvitePayload(bytes.Repeat([]byte{3}, 32), time.Now().Add(time.Hour).UnixMilli())
	fake := &ticket{secret: bytes.Repeat([]byte{3}, 32), rec: sign(t, pb.RecordType_INVITE, keys.ID16(f.svc.NetworkPub), inv, nodeKey)}
	_, forged := f.replicatedEntry(fake, "mallory", nil)
	if _, err := f.svc.ApplyReplicated(ctx, peer, forged); !errors.Is(err, ErrInvalid) {
		t.Fatalf("forged invite: %v", err)
	}
	// a proof made with a key other than the invite's redeem key
	_, wrongKey := f.replicatedEntry(f.newTicket(anna, time.Hour), "mallory", func(e *pb.DirectoryEntry) {
		other := f.newTicket(anna, time.Hour)
		raw := e.InviteRecord
		if err := records.Redeem(e, other.rec, other.secret); err != nil {
			t.Fatal(err)
		}
		e.InviteRecord = raw
	})
	if _, err := f.svc.ApplyReplicated(ctx, peer, wrongKey); !errors.Is(err, ErrInvalid) {
		t.Fatalf("proof by a wrong key: %v", err)
	}
	// an inviter this node does not know yet: retried after its entry arrives
	pubX, privX, _ := ed25519.GenerateKey(nil)
	_, early := f.replicatedEntry(f.newTicket(&user{id: keys.ID16(pubX), priv: privX}, time.Hour), "early", nil)
	if _, err := f.svc.ApplyReplicated(ctx, peer, early); !errors.Is(err, ErrRetryLater) {
		t.Fatalf("unknown inviter: %v", err)
	}
	// registered outside the invite's lifetime
	_, late := f.replicatedEntry(f.newTicket(anna, time.Hour), "late", func(e *pb.DirectoryEntry) { e.RegisteredMs = time.Now().Add(2 * time.Hour).UnixMilli() })
	if _, err := f.svc.ApplyReplicated(ctx, peer, late); !errors.Is(err, ErrInvalid) {
		t.Fatalf("outside lifetime: %v", err)
	}
	_, before := f.replicatedEntry(f.newTicket(anna, time.Hour), "before", func(e *pb.DirectoryEntry) { e.RegisteredMs = time.Now().Add(-time.Hour).UnixMilli() })
	if _, err := f.svc.ApplyReplicated(ctx, peer, before); !errors.Is(err, ErrInvalid) {
		t.Fatalf("registered before the invite: %v", err)
	}

	// the admin withdraws boris's rights: his later invite admits nobody, even arriving by replication
	f.netRecord(pb.RecordType_INVITE_RIGHTS, &pb.InviteRights{UserId: boris.id, CanInvite: false, Version: 1})
	_, byBoris := f.replicatedEntry(f.newTicket(boris, time.Hour), "vera", nil)
	if _, err := f.svc.ApplyReplicated(ctx, peer, byBoris); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invite without rights: %v", err)
	}
	_, regByBoris := f.registerReq(f.newTicket(boris, time.Hour), "vera")
	if _, err := f.svc.Register(ctx, regByBoris); !errors.Is(err, ErrInvalid) {
		t.Fatalf("registration with an invite without rights: %v", err)
	}
	// rights restored later apply to invites made after that
	time.Sleep(2 * time.Millisecond)
	f.netRecord(pb.RecordType_INVITE_RIGHTS, &pb.InviteRights{UserId: boris.id, CanInvite: true, Version: 2})
	if u, _ := f.svc.Store.UserByID(ctx, boris.id); !u.CanInvite {
		t.Fatal("INVITE_RIGHTS not applied")
	}
	vera, ok := f.replicatedEntry(f.newTicket(boris, time.Hour), "vera", nil)
	if _, err := f.svc.ApplyReplicated(ctx, peer, ok); err != nil {
		t.Fatal(err)
	}
	if u, _ := f.svc.Store.UserByID(ctx, vera.id); u == nil || !u.CanInvite {
		t.Fatalf("vera: %+v", u)
	}
	if _, err := f.svc.ApplyReplicated(ctx, peer, byBoris); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an invite made while withdrawn stays invalid: %v", err)
	}

	// revocation: invites made before it still count (every node agrees), invites made after it do not
	kira := f.mustRegister(f.invite(anna, time.Hour), "kira")
	earlier := f.newTicket(kira, time.Hour)
	time.Sleep(2 * time.Millisecond)
	f.netRecord(pb.RecordType_REVOCATION, &pb.Revocation{UserId: kira.id, Reason: "test"})
	time.Sleep(2 * time.Millisecond)
	_, afterRev := f.replicatedEntry(f.newTicket(kira, time.Hour), "gleb", nil)
	if _, err := f.svc.ApplyReplicated(ctx, peer, afterRev); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invite by a revoked inviter: %v", err)
	}
	_, beforeRev := f.replicatedEntry(earlier, "dina", nil)
	if _, err := f.svc.ApplyReplicated(ctx, peer, beforeRev); err != nil {
		t.Fatalf("invite made before the inviter's revocation: %v", err)
	}
	_, regByKira := f.registerReq(f.newTicket(kira, time.Hour), "egor")
	if _, err := f.svc.Register(ctx, regByKira); !errors.Is(err, ErrInvalid) {
		t.Fatalf("registration with a revoked inviter: %v", err)
	}
}

func TestFoundingMembersNeedNoChain(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	old, bare := f.replicatedEntry(nil, "mama", nil)
	m := &pb.Manifest{Version: 2, NetworkPub: f.svc.NetworkPub, FoundingMembers: [][]byte{old.id},
		Nodes: []*pb.NodeInfo{{NodeId: f.svc.NodeID, NodePub: f.svc.NodeKeyPriv.Public().(ed25519.PublicKey), Label: "self"}}}
	if _, err := f.svc.ImportRecord(ctx, sign(t, pb.RecordType_MANIFEST, keys.ID16(f.svc.NetworkPub), m, f.netPriv)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ImportRecord(ctx, bare); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ImportRecord of a directory entry: %v", err)
	}
	if _, err := f.svc.ApplyReplicated(ctx, r16(), bare); err != nil {
		t.Fatalf("founding member refused: %v", err)
	}
	if u, _ := f.svc.Store.UserByID(ctx, old.id); u == nil || !u.CanInvite {
		t.Fatalf("founding member: %+v", u)
	}
	_, other := f.replicatedEntry(nil, "papa", nil)
	if _, err := f.svc.ApplyReplicated(ctx, r16(), other); !errors.Is(err, ErrInvalid) {
		t.Fatalf("not a founding member: %v", err)
	}
}

func TestInviteNeedsRedeemKey(t *testing.T) {
	f := newFx(t)
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna")
	old := sign(t, pb.RecordType_INVITE, anna.id, &pb.Invite{InviteId: make([]byte, 32), ExpiresMs: time.Now().Add(time.Hour).UnixMilli()}, anna.priv)
	if _, err := f.svc.Submit(context.Background(), anna.id, old, pb.RecordType_INVITE); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invite without redeem_pub: %v", err)
	}
}

func chainOf(t *testing.T, raw []byte) *pb.DirectoryEntry {
	var r pb.Record
	var b pb.RecordBody
	var e pb.DirectoryEntry
	if proto.Unmarshal(raw, &r) != nil || proto.Unmarshal(r.Body, &b) != nil || proto.Unmarshal(b.Payload, &e) != nil {
		t.Fatal("bad entry")
	}
	return &e
}
