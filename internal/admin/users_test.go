package admin

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

func signed(t *testing.T, typ pb.RecordType, author []byte, m proto.Message, k ed25519.PrivateKey) *pb.Record {
	p, _ := proto.Marshal(m)
	r, err := records.Sign(&pb.RecordBody{Id: make([]byte, 16), Type: typ, Author: author, CreatedMs: time.Now().UnixMilli(), Payload: p}, k)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A hostile node answering admin.users cannot alter or fake records: whatever does not verify is dropped, and an
// account without a verified invite chain (or founding entry) is shown as not admitted.
func TestMembersVerifiesEverything(t *testing.T) {
	netPub, netPriv, _ := ed25519.GenerateKey(nil)
	_, nodePriv, _ := ed25519.GenerateKey(nil)
	netID := keys.ID16(netPub)
	type inviter struct {
		id   []byte
		priv ed25519.PrivateKey
	}
	mk := func(name string, by *inviter) (*pb.Record, []byte, ed25519.PrivateKey) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		id := keys.ID16(pub)
		e := &pb.DirectoryEntry{UserId: id, Username: name, DisplayName: name, AccountPub: pub, Version: 1}
		if by != nil {
			secret := bytes.Repeat([]byte(name[:1]), 32)
			inv, _ := records.InvitePayload(secret, time.Now().Add(time.Hour).UnixMilli())
			if err := records.Redeem(e, signed(t, pb.RecordType_INVITE, by.id, inv, by.priv), secret); err != nil {
				t.Fatal(err)
			}
		}
		return signed(t, pb.RecordType_DIRECTORY_ENTRY, id, e, priv), id, priv
	}
	anna, annaID, annaPriv := mk("anna", nil) // founding: no chain
	boris, borisID, _ := mk("boris", &inviter{annaID, annaPriv})
	vera, veraID, _ := mk("vera", &inviter{netID, netPriv})
	ghost, ghostID, _ := mk("ghost", nil)               // made up by the node: no chain, not founding
	fake, _, _ := mk("fake", &inviter{netID, nodePriv}) // "network" invite signed by the node
	tampered := proto.Clone(boris).(*pb.Record)
	tampered.Signature[0] ^= 1
	// an entry the node signed itself for an account key it made up, claiming boris's id
	fakePub, _, _ := ed25519.GenerateKey(nil)
	forged := signed(t, pb.RecordType_DIRECTORY_ENTRY, borisID, &pb.DirectoryEntry{UserId: borisID, Username: "evil",
		AccountPub: fakePub, Version: 2}, nodePriv)
	rev := signed(t, pb.RecordType_REVOCATION, keys.ID16(netPub), &pb.Revocation{UserId: borisID, Reason: "x"}, netPriv)
	fakeRev := signed(t, pb.RecordType_REVOCATION, keys.ID16(netPub), &pb.Revocation{UserId: annaID}, nodePriv)
	rights := signed(t, pb.RecordType_INVITE_RIGHTS, keys.ID16(netPub), &pb.InviteRights{UserId: borisID, CanInvite: true, Version: 4}, netPriv)
	off := signed(t, pb.RecordType_INVITE_RIGHTS, keys.ID16(netPub), &pb.InviteRights{UserId: veraID, CanInvite: false, Version: 2}, netPriv)
	on := signed(t, pb.RecordType_INVITE_RIGHTS, keys.ID16(netPub), &pb.InviteRights{UserId: veraID, CanInvite: true, Version: 2}, netPriv)
	fakeOff := signed(t, pb.RecordType_INVITE_RIGHTS, keys.ID16(netPub), &pb.InviteRights{UserId: annaID, CanInvite: false, Version: 9}, nodePriv)
	ms := Members([]*pb.Record{anna, tampered, forged, boris, rev, fakeRev, rights, vera, on, off, fakeOff, ghost, fake}, netPub, [][]byte{annaID}, 0)
	if len(ms) != 5 {
		t.Fatalf("%d members: %+v", len(ms), ms)
	}
	if ms[1].Username != "boris" || !ms[1].Admitted || ms[4].Username != "vera" || !ms[4].Admitted {
		t.Fatalf("chains: %+v", ms)
	}
	// shown (so the admin can 'user found' accounts from before M9.2), but marked
	if ms[2].Username != "fake" || ms[2].Admitted || ms[3].Username != "ghost" || ms[3].Admitted || !bytes.Equal(ms[3].UserID, ghostID) {
		t.Fatalf("unadmitted: %+v", ms)
	}
	// D101 (owner 2026-11-15): every member may invite by default
	if !ms[0].Admitted || !ms[0].Founding || ms[0].Revoked || !ms[0].CanInvite || ms[0].RightsVersion != 0 {
		t.Fatalf("anna: %+v", ms[0])
	}
	if ms[1].Username != "boris" || !ms[1].Revoked || ms[1].Reason != "x" || ms[1].RightsVersion != 4 || ms[1].Founding {
		t.Fatalf("boris: %+v", ms[1])
	}
	if ms[4].CanInvite || ms[4].RightsVersion != 2 { // equal versions: "no" wins
		t.Fatalf("vera: %+v", ms[4])
	}
	if _, err := Find(ms, "boris"); err != nil {
		t.Fatal(err)
	}
	if m, err := Find(ms, ms[4].Tag()); err != nil || m.Username != "vera" {
		t.Fatalf("tag: %v", err)
	}
	if _, err := Find(ms, "nobody"); err == nil {
		t.Fatal("unknown name resolved")
	}
}

func TestFindAmbiguous(t *testing.T) {
	a := Member{UserID: bytes.Repeat([]byte{1}, 16), Username: "anna"}
	b := Member{UserID: bytes.Repeat([]byte{2}, 16), Username: "anna"}
	if _, err := Find([]Member{a, b}, "anna"); err == nil {
		t.Fatal("ambiguous name resolved")
	}
	if m, err := Find([]Member{a, b}, "anna#02020202"); err != nil || m.UserID[0] != 2 {
		t.Fatalf("name#tag: %v", err)
	}
	if m, err := Find([]Member{a, b}, "01010101010101010101010101010101"); err != nil || m.UserID[0] != 1 {
		t.Fatalf("user id: %v", err)
	}
}

func TestSignedAdminRecordsAndFounding(t *testing.T) {
	dir := t.TempDir()
	if err := InitNetwork(dir, pass); err != nil {
		t.Fatal(err)
	}
	if _, err := AddNode(dir, NodeSpec{Label: "dev", WSSHost: "10.0.2.2", WSSPort: 8080, Plain: true}); err != nil {
		t.Fatal(err)
	}
	st, _ := LoadState(dir)
	priv, err := keys.ReadEncryptedKey(filepath.Join(dir, "network.key.enc"), pass)
	if err != nil {
		t.Fatal(err)
	}
	user := bytes.Repeat([]byte{7}, 16)
	v := &records.Validator{NetworkPub: st.NetworkPub, Users: noUsers{}, Now: time.Now}
	rev, err := SignRevocation(dir, priv, user, "spam", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if body, err := v.Validate(rev); err != nil || body.Type != pb.RecordType_REVOCATION {
		t.Fatalf("revocation: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "revocations", "07070707070707070707070707070707.bin")); err != nil {
		t.Fatal(err)
	}
	ir, err := SignInviteRights(dir, priv, user, false, 3, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	body, err := v.Validate(ir)
	var p pb.InviteRights
	proto.Unmarshal(body.Payload, &p)
	if err != nil || body.Type != pb.RecordType_INVITE_RIGHTS || p.CanInvite || p.Version != 3 {
		t.Fatalf("invite rights: %v %+v", err, &p)
	}

	if got, err := LoadFounding(dir); err != nil || got != nil {
		t.Fatalf("empty founding: %v %v", got, err)
	}
	other := bytes.Repeat([]byte{8}, 16)
	if err := AddFounding(dir, [][]byte{user}); err != nil {
		t.Fatal(err)
	}
	if err := AddFounding(dir, [][]byte{other, user}); err != nil {
		t.Fatal(err)
	}
	rec, err := SignManifest(dir, pass, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	mb, _ := v.Validate(rec)
	var m pb.Manifest
	proto.Unmarshal(mb.Payload, &m)
	if len(m.FoundingMembers) != 2 || !bytes.Equal(m.FoundingMembers[0], user) || !bytes.Equal(m.FoundingMembers[1], other) {
		t.Fatalf("founding_members: %x", m.FoundingMembers)
	}
	os.WriteFile(filepath.Join(dir, "founding.json"), []byte(`["zz"]`), 0o600)
	if _, err := SignManifest(dir, pass, time.Now()); err == nil {
		t.Fatal("bad founding.json accepted")
	}
}

func TestSavedRightsVersion(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(nil)
	user := bytes.Repeat([]byte{5}, 16)
	if v := SavedRightsVersion(dir, user); v != 0 {
		t.Fatalf("none: %d", v)
	}
	if _, err := SignInviteRights(dir, priv, user, true, 7, time.Now()); err != nil {
		t.Fatal(err)
	}
	if v := SavedRightsVersion(dir, user); v != 7 {
		t.Fatalf("saved: %d", v)
	}
}
