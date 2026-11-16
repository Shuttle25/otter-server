package admin

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

type noUsersT struct{}

func (noUsersT) UserKey([]byte) (records.UserKey, bool) { return records.UserKey{}, false }

// D111: step 1 revokes the lost account and invites the new install, step 2 signs REKEY{old, new}.
func TestRekeyTwoSteps(t *testing.T) {
	dir := t.TempDir()
	pass := []byte("pw")
	if err := InitNetwork(dir, pass); err != nil {
		t.Fatal(err)
	}
	if _, err := SignManifest(dir, pass, time.Now()); err != nil {
		t.Fatal(err)
	}
	st, _ := LoadState(dir)
	priv, err := keys.ReadEncryptedKey(filepath.Join(dir, "network.key.enc"), pass)
	if err != nil {
		t.Fatal(err)
	}
	old := bytes.Repeat([]byte{1}, 16)
	nw := bytes.Repeat([]byte{2}, 16)
	if _, err := RekeyFinish(dir, priv, "anna", nw, time.Now()); err == nil {
		t.Fatal("finish without a start")
	}
	if _, err := RekeyStart(dir, priv, "Anna!", old, time.Now()); err == nil {
		t.Fatal("bad username accepted")
	}
	start, err := RekeyStart(dir, priv, "anna", old, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	v := &records.Validator{NetworkPub: st.NetworkPub, Users: noUsersT{}, Now: time.Now}
	body, err := v.Validate(start.Revocation)
	if err != nil || body.Type != pb.RecordType_REVOCATION {
		t.Fatalf("revocation %v %v", body, err)
	}
	var rv pb.Revocation
	proto.Unmarshal(body.Payload, &rv)
	if !bytes.Equal(rv.UserId, old) || rv.Reason != "rekey" {
		t.Fatalf("revocation payload %+v", &rv)
	}
	ib, err := v.Validate(start.Invite.Record)
	if err != nil || ib.Type != pb.RecordType_INVITE || !bytes.Equal(ib.Author, keys.ID16(st.NetworkPub)) {
		t.Fatalf("invite %v %v", ib, err)
	}
	if d := time.Duration(ib.ExpiresMs-ib.CreatedMs) * time.Millisecond; d != 7*24*time.Hour {
		t.Fatalf("invite ttl %v", d)
	}
	if b, err := DecodeInviteLink(start.Invite.Link); err != nil || !proto.Equal(b.Invite, start.Invite.Record) {
		t.Fatalf("link: %v", err)
	}
	// nothing is pending until both records were published
	if _, err := RekeyFinish(dir, priv, "anna", nw, time.Now()); err == nil {
		t.Fatal("finish before the start was recorded")
	}
	if err := RekeyStarted(dir, "anna", old, start.Invite.InviteID, time.Now()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "rekeys", "anna.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", fi, err)
	}
	var s map[string]any
	raw, _ := os.ReadFile(filepath.Join(dir, "rekeys", "anna.json"))
	if json.Unmarshal(raw, &s) != nil || s["old"] != hex.EncodeToString(old) || s["invite_id"] != hex.EncodeToString(start.Invite.InviteID) {
		t.Fatalf("state %s", raw)
	}
	// a second start for another account under the same name is refused; the same account may restart
	if _, err := RekeyStart(dir, priv, "anna", nw, time.Now()); err == nil {
		t.Fatal("second re-key of anna for another account accepted")
	}
	if _, err := RekeyStart(dir, priv, "anna", old, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := RekeyPending(dir, "anna"); err != nil || !bytes.Equal(got, old) {
		t.Fatalf("pending %x %v", got, err)
	}

	if _, err := RekeyFinish(dir, priv, "anna", old, time.Now()); err == nil {
		t.Fatal("new == old accepted")
	}
	rec, err := RekeyFinish(dir, priv, "anna", nw, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	body, err = v.Validate(rec)
	if err != nil || body.Type != pb.RecordType_REKEY || !bytes.Equal(body.Author, keys.ID16(st.NetworkPub)) {
		t.Fatalf("rekey %v %v", body, err)
	}
	var k pb.Rekey
	proto.Unmarshal(body.Payload, &k)
	if !bytes.Equal(k.OldUserId, old) || !bytes.Equal(k.NewUserId, nw) {
		t.Fatalf("payload %x→%x", k.OldUserId, k.NewUserId)
	}
	if err := RekeyDone(dir, "anna", nw, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "rekeys", "anna.json")); !os.IsNotExist(err) {
		t.Fatalf("pending file left: %v", err)
	}
	raw, err = os.ReadFile(filepath.Join(dir, "rekeys", "anna.done.json"))
	if err != nil || json.Unmarshal(raw, &s) != nil || s["new"] != hex.EncodeToString(nw) {
		t.Fatalf("done file %s %v", raw, err)
	}

	if _, err := ParseUserCode("0102 0304 0506 0708 090a 0b0c 0d0e 0f10"); err != nil {
		t.Fatal(err)
	}
	if c, err := ParseUserCode(" 0102-0304-0506-0708-090A-0B0C-0D0E-0F10\n"); err != nil || c[15] != 0x10 {
		t.Fatalf("dashes/upper case: %x %v", c, err)
	}
	if _, err := ParseUserCode(hex.EncodeToString(nw)[:30]); err == nil {
		t.Fatal("short code accepted")
	}
	if _, err := ParseUserCode("zz" + hex.EncodeToString(nw)[2:]); err == nil {
		t.Fatal("non-hex code accepted")
	}
}

// The admin sees a REKEY on 'user list': the old account re-keyed (revoked) to the new one, the new one admitted by
// the REKEY without an invite chain. A REKEY the node forged is dropped; of two REKEYs of one account the later wins.
func TestMembersRekey(t *testing.T) {
	netPub, netPriv, _ := ed25519.GenerateKey(nil)
	_, nodePriv, _ := ed25519.GenerateKey(nil)
	netID := keys.ID16(netPub)
	mk := func(name string, inviter []byte, ipriv ed25519.PrivateKey) (*pb.Record, []byte, ed25519.PrivateKey) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		id := keys.ID16(pub)
		e := &pb.DirectoryEntry{UserId: id, Username: name, DisplayName: name, AccountPub: pub, Version: 1}
		if inviter != nil {
			secret := bytes.Repeat([]byte{byte(len(name))}, 32)
			inv, _ := records.InvitePayload(secret, time.Now().Add(time.Hour).UnixMilli())
			if err := records.Redeem(e, signed(t, pb.RecordType_INVITE, inviter, inv, ipriv), secret); err != nil {
				t.Fatal(err)
			}
		}
		return signed(t, pb.RecordType_DIRECTORY_ENTRY, id, e, priv), id, priv
	}
	rekey := func(old, nw []byte, created int64, k ed25519.PrivateKey) *pb.Record {
		p, _ := proto.Marshal(&pb.Rekey{OldUserId: old, NewUserId: nw})
		r, err := records.Sign(&pb.RecordBody{Id: bytes.Repeat([]byte{byte(created)}, 16), Type: pb.RecordType_REKEY,
			Author: netID, CreatedMs: created, Payload: p}, k)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	oldE, oldID, _ := mk("anna", nil, nil)       // founding
	newE, newID, newPriv := mk("anna", nil, nil) // no chain: admitted by the REKEY only
	wrongE, wrongID, _ := mk("anna", nil, nil)   // the code was misheard first
	kidE, kidID, _ := mk("kid", newID, newPriv)  // invited by the new account
	evilE, evilID, _ := mk("evil", nil, nil)     // named by a forged REKEY
	now := time.Now().UnixMilli()
	batch := []*pb.Record{oldE, newE, wrongE, kidE, evilE,
		rekey(oldID, newID, now, netPriv), rekey(oldID, wrongID, now-1000, netPriv), rekey(evilID, evilID, now, nodePriv)}
	ms := Members(batch, netPub, [][]byte{oldID}, 0)
	by := map[string]Member{}
	for _, m := range ms {
		by[string(m.UserID)] = m
	}
	o := by[string(oldID)]
	if !o.Revoked || o.Reason != "rekey" || !bytes.Equal(o.RekeyedTo, newID) || !o.Admitted {
		t.Fatalf("old: %+v", o)
	}
	n := by[string(newID)]
	if n.Revoked || !n.Admitted || !bytes.Equal(n.RekeyedFrom, oldID) || n.RekeyedTo != nil {
		t.Fatalf("new: %+v", n)
	}
	if k := by[string(kidID)]; !k.Admitted {
		t.Fatalf("kid (invited by the new account): %+v", k)
	}
	if w := by[string(wrongID)]; w.Admitted || w.RekeyedFrom != nil {
		t.Fatalf("losing REKEY's account: %+v", w)
	}
	if e := by[string(evilID)]; e.Admitted || e.Revoked || e.RekeyedFrom != nil {
		t.Fatalf("forged REKEY applied: %+v", e)
	}
	// an explicit REVOCATION keeps its reason; the REKEY still links the accounts
	rev := signed(t, pb.RecordType_REVOCATION, netID, &pb.Revocation{UserId: oldID, Reason: "lost phone"}, netPriv)
	for _, m := range Members(append([]*pb.Record{rev}, batch...), netPub, [][]byte{oldID}, 0) {
		if bytes.Equal(m.UserID, oldID) && (m.Reason != "lost phone" || !bytes.Equal(m.RekeyedTo, newID)) {
			t.Fatalf("old with revocation: %+v", m)
		}
	}
}
