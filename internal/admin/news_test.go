package admin

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

// TestMain replaces the desktop keyring with an in-memory one for every test in this package:
// no test may ever touch the owner's real keyring.
func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

func TestNewsKeyLifecycle(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	if err := InitNetwork(dir, []byte("correct horse battery")); err != nil {
		t.Fatal(err)
	}
	pub, err := NewsInit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewsInit(dir); !errors.Is(err, ErrExists) {
		t.Fatalf("second init: %v", err)
	}
	ks, _ := LoadNewsKeys(dir)
	if len(ks) != 1 || !bytes.Equal(ks[0], pub) {
		t.Fatalf("news_keys.json: %x", ks)
	}
	if !bytes.Equal(LocalNewsKey(dir), pub) {
		t.Fatal("LocalNewsKey does not return the keyring key")
	}
	rec, err := SignManifest(dir, []byte("correct horse battery"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var body pb.RecordBody
	var m pb.Manifest
	proto.Unmarshal(rec.Body, &body)
	proto.Unmarshal(body.Payload, &m)
	if len(m.NewsKeys) != 1 || !bytes.Equal(m.NewsKeys[0], pub) {
		t.Fatal("manifest lacks the news key")
	}
	a, err := SignAnnouncement(dir, &pb.Announcement{TextRu: "Привет"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	v := &records.Validator{NetworkPub: ed25519.PublicKey(m.NetworkPub), Users: nil, News: staticNews{pub}, Now: time.Now}
	if _, err := v.Validate(a); err != nil {
		t.Fatal("announcement does not verify:", err)
	}
	sent, _ := ListAnnouncements(dir)
	if len(sent) != 1 || sent[0].ID != NewsID(a) || sent[0].Key != RecordKeyHex(a) || sent[0].A.TextRu != "Привет" {
		t.Fatalf("saved: %+v", sent)
	}
	if _, err := SignAnnouncementDeleted(dir, "zz", time.Now()); err == nil {
		t.Fatal("deletion with a non-matching prefix")
	}
	d, err := SignAnnouncementDeleted(dir, sent[0].ID[:6], time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Validate(d); err != nil {
		t.Fatal("deletion does not verify:", err)
	}
	if sent, _ := ListAnnouncements(dir); !sent[0].Deleted {
		t.Fatal("deletion not recorded")
	}
	if err := ForgetSent(dir, d); err != nil {
		t.Fatal(err)
	}
	if sent, _ := ListAnnouncements(dir); sent[0].Deleted {
		t.Fatal("ForgetSent kept the deletion")
	}
	// a second announcement by the same key gets a distinct id prefix
	a2, err := SignAnnouncement(dir, &pb.Announcement{TextEn: "Hello"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if NewsID(a2)[:6] == NewsID(a)[:6] {
		t.Skip("random ids collided in 24 bits")
	}
	if err := ForgetSent(dir, a2); err != nil {
		t.Fatal(err)
	}
	if sent, _ := ListAnnouncements(dir); len(sent) != 1 {
		t.Fatal("ForgetSent kept the announcement")
	}
	if err := NewsRevoke(dir, "00"+fmtHex(pub)[2:]); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke unknown: %v", err)
	}
	if err := NewsRevoke(dir, fmtHex(pub)); err != nil {
		t.Fatal(err)
	}
	if ks, _ := LoadNewsKeys(dir); len(ks) != 0 {
		t.Fatal("not revoked")
	}
	if _, err := SignAnnouncement(dir, &pb.Announcement{TextRu: "x"}, time.Now()); err == nil {
		t.Fatal("signed with a revoked key")
	}
	// the local key was removed from the keyring as well, so a new one can be created
	pub2, err := NewsInit(dir)
	if err != nil || bytes.Equal(pub2, pub) {
		t.Fatalf("re-init after revoke: %v", err)
	}
}

func TestNewsKeyringUnavailable(t *testing.T) {
	defer keyring.MockInit()
	dir := t.TempDir()
	if err := InitNetwork(dir, []byte("correct horse battery")); err != nil {
		t.Fatal(err)
	}
	keyring.MockInitWithError(errors.New("dbus: no session"))
	if _, err := NewsInit(dir); err == nil {
		t.Fatal("init succeeded without a keyring")
	}
	if ks, _ := LoadNewsKeys(dir); len(ks) != 0 {
		t.Fatal("key listed although the keyring failed")
	}
}

type staticNews struct{ pub ed25519.PublicKey }

func (s staticNews) NewsKey(id []byte) (ed25519.PublicKey, bool) {
	return s.pub, bytes.Equal(id, keys.ID16(s.pub))
}
