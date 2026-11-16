package admin

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

func isV1(pub ed25519.PublicKey, r *pb.Record) bool { return ed25519.Verify(pub, r.Body, r.Signature) }

func isV2(pub, netPub ed25519.PublicKey, r *pb.Record) bool {
	return ed25519.Verify(pub, records.MessageV2(keys.ID16(netPub), r.Body), r.Signature)
}

func TestManifestCutoverSignsV2AndIsMonotonic(t *testing.T) {
	dir := t.TempDir()
	pass := []byte("pw")
	if err := InitNetwork(dir, pass); err != nil {
		t.Fatal(err)
	}
	newsPub, err := NewsInit(dir)
	if err != nil {
		t.Fatal(err)
	}
	netPriv, err := keys.ReadEncryptedKey(filepath.Join(dir, "network.key.enc"), pass)
	if err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(1_800_000_000_000)
	st, _ := LoadState(dir)
	signAll := func() (man, inv, news, rev *pb.Record) {
		t.Helper()
		man, err := SignManifest(dir, pass, now)
		if err != nil {
			t.Fatal(err)
		}
		b, err := BootstrapInvite(dir, pass, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		news, err = SignAnnouncement(dir, &pb.Announcement{TextRu: "Привет"}, now)
		if err != nil {
			t.Fatal(err)
		}
		rev, err = SignRevocation(dir, netPriv, make([]byte, 16), "lost", now)
		if err != nil {
			t.Fatal(err)
		}
		return man, b.Record, news, rev
	}

	man, inv, news, rev := signAll()
	if !isV1(st.NetworkPub, man) || !isV1(st.NetworkPub, inv) || !isV1(newsPub, news) || !isV1(st.NetworkPub, rev) {
		t.Fatal("before the cut-over everything must be v1 (0.9.x phones)")
	}
	until := now.Add(48 * time.Hour).UnixMilli()
	if err := SetSigV1Until(dir, until); err != nil {
		t.Fatal(err)
	}
	if err := SetSigV1Until(dir, until); err != nil {
		t.Fatalf("setting the same value again: %v", err)
	}
	man, inv, news, rev = signAll()
	var body pb.RecordBody
	var m pb.Manifest
	proto.Unmarshal(man.Body, &body)
	proto.Unmarshal(body.Payload, &m)
	if m.SigV1UntilMs != until {
		t.Fatalf("until = %d", m.SigV1UntilMs)
	}
	if !isV2(st.NetworkPub, st.NetworkPub, man) || isV1(st.NetworkPub, man) {
		t.Fatal("cut-over manifest not v2")
	}
	if !isV2(st.NetworkPub, st.NetworkPub, inv) || !isV2(newsPub, st.NetworkPub, news) || !isV2(st.NetworkPub, st.NetworkPub, rev) {
		t.Fatal("invite, announcement or revocation not v2 after the cut-over")
	}
	man2, err := SignManifest(dir, pass, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	proto.Unmarshal(man2.Body, &body)
	proto.Unmarshal(body.Payload, &m)
	if m.SigV1UntilMs != until || !isV2(st.NetworkPub, st.NetworkPub, man2) {
		t.Fatal("a later manifest dropped the cut-over")
	}
	if err := SetSigV1Until(dir, until-1); err == nil {
		t.Fatal("lowering accepted")
	}
	if err := SetSigV1Until(dir, until+1); err == nil {
		t.Fatal("raising accepted")
	}
	if err := SetSigV1Until(dir, 0); err == nil {
		t.Fatal("clearing accepted")
	}
	if SigV1Until(dir) != until {
		t.Fatal("stored value changed")
	}
}

// After the cut-over a node cannot feed the admin a v1 record created after it, nor a v2 record of another network;
// v1 records from before the cut-over and v2 records of this network still count (D109).
func TestMembersCutover(t *testing.T) {
	netPub, netPriv, _ := ed25519.GenerateKey(nil)
	netID := keys.ID16(netPub)
	until := time.Now().Add(-time.Hour).UnixMilli()
	at := func(typ pb.RecordType, author []byte, m proto.Message, k ed25519.PrivateKey, created int64, sc records.SigContext) *pb.Record {
		p, _ := proto.Marshal(m)
		id := make([]byte, 16)
		copy(id, author)
		id[15] ^= byte(created)
		r, err := records.SignWith(&pb.RecordBody{Id: id, Type: typ, Author: author, CreatedMs: created, Payload: p}, k, sc)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	v2 := records.SigContext{NetworkID: netID, V2: true}
	other := records.SigContext{NetworkID: make([]byte, 16), V2: true}
	var batch []*pb.Record
	ids := map[string][]byte{}
	for _, c := range []struct {
		name    string
		created int64
		sc      records.SigContext
	}{{"old_v1", until - 1, records.SigContext{}}, {"late_v1", until, records.SigContext{}}, {"new_v2", until + 5, v2}, {"other_v2", until + 5, other}} {
		pub, priv, _ := ed25519.GenerateKey(nil)
		id := keys.ID16(pub)
		ids[c.name] = id
		batch = append(batch, at(pb.RecordType_DIRECTORY_ENTRY, id, &pb.DirectoryEntry{UserId: id, Username: c.name, AccountPub: pub, Version: 1}, priv, c.created, c.sc))
		batch = append(batch, at(pb.RecordType_REVOCATION, netID, &pb.Revocation{UserId: id, Reason: c.name}, netPriv, c.created, c.sc))
	}
	ms := Members(batch, netPub, [][]byte{ids["old_v1"], ids["new_v2"]}, until)
	got := map[string]bool{}
	for _, m := range ms {
		got[m.Username] = m.Revoked
	}
	if len(got) != 2 || !got["old_v1"] || !got["new_v2"] {
		t.Fatalf("members: %v", got)
	}
}
