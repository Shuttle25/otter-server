package service

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

// withNewsManifest publishes manifest `version` listing newsKeys; this node is push-capable.
func (f *fx) withNewsManifest(t *testing.T, version uint64, newsKeys ...ed25519.PublicKey) {
	t.Helper()
	m := &pb.Manifest{Version: version, NetworkPub: f.svc.NetworkPub,
		Nodes: []*pb.NodeInfo{{NodeId: f.svc.NodeID, NodePub: f.svc.NodeKeyPriv.Public().(ed25519.PublicKey), Label: "a", PushCapable: true}}}
	for _, k := range newsKeys {
		m.NewsKeys = append(m.NewsKeys, k)
	}
	if err := f.svc.PublishManifest(context.Background(), sign(t, pb.RecordType_MANIFEST, keys.ID16(f.svc.NetworkPub), m, f.netPriv)); err != nil {
		t.Fatal(err)
	}
}

// registerPushToken stores a push token for device 1 of u.
func (f *fx) registerPushToken(t *testing.T, u *user) {
	t.Helper()
	r := sign(t, pb.RecordType_PUSH_TOKEN, u.id, &pb.PushToken{DeviceId: 1, Kind: pb.PushToken_FCM, Token: "tok"}, u.priv)
	if _, err := f.svc.Submit(context.Background(), u.id, r, pb.RecordType_PUSH_TOKEN); err != nil {
		t.Fatal(err)
	}
}

func recordKey(t *testing.T, r *pb.Record) []byte {
	var body pb.RecordBody
	if err := proto.Unmarshal(r.Body, &body); err != nil {
		t.Fatal(err)
	}
	return append(append([]byte{}, body.Author...), body.Id...)
}

func TestPublishNews(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(nil)
	f.withNewsManifest(t, 1, pub)
	w := &wakeRec{}
	f.svc.Waker = w
	u := f.mustRegister(f.invite(nil, time.Hour), "anna")
	f.registerPushToken(t, u)

	a := sign(t, pb.RecordType_ANNOUNCEMENT, keys.ID16(pub), &pb.Announcement{TextRu: "Привет"}, priv)
	if err := f.svc.PublishNews(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.PublishNews(ctx, a); err != nil { // idempotent
		t.Fatal(err)
	}
	if got, _ := f.svc.News(ctx); len(got) != 1 {
		t.Fatalf("news: %d", len(got))
	}
	if f.notes.news != 1 || len(w.woke) != 1 || w.woke[0] != string(u.id) {
		t.Fatalf("news events %d, wakes %q", f.notes.news, w.woke)
	}
	_, other, _ := ed25519.GenerateKey(nil)
	bad := sign(t, pb.RecordType_ANNOUNCEMENT, keys.ID16(other.Public().(ed25519.PublicKey)), &pb.Announcement{TextRu: "x"}, other)
	if err := f.svc.PublishNews(ctx, bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown key: %v", err)
	}
	if err := f.svc.PublishNews(ctx, f.manifestRec(9)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("manifest via news.publish: %v", err)
	}
	// deletion: an event, no push
	del := sign(t, pb.RecordType_ANNOUNCEMENT_DELETED, keys.ID16(pub), &pb.AnnouncementDeleted{Target: recordKey(t, a)}, priv)
	if err := f.svc.PublishNews(ctx, del); err != nil {
		t.Fatal(err)
	}
	if len(w.woke) != 1 || f.notes.news != 2 {
		t.Fatalf("deletion: wakes %d, events %d", len(w.woke), f.notes.news)
	}
	// an announcement whose deletion arrived first is never shown: no event, no push
	late := sign(t, pb.RecordType_ANNOUNCEMENT, keys.ID16(pub), &pb.Announcement{TextRu: "поздно"}, priv)
	del2 := sign(t, pb.RecordType_ANNOUNCEMENT_DELETED, keys.ID16(pub), &pb.AnnouncementDeleted{Target: recordKey(t, late)}, priv)
	if err := f.svc.PublishNews(ctx, del2); err != nil {
		t.Fatal(err)
	}
	events := f.notes.news
	if err := f.svc.PublishNews(ctx, late); err != nil {
		t.Fatal(err)
	}
	if len(w.woke) != 1 || f.notes.news != events {
		t.Fatalf("deleted announcement: wakes %d, events %d (was %d)", len(w.woke), f.notes.news, events)
	}
	// a stale announcement (late publish) is stored but pushes nobody
	p, _ := proto.Marshal(&pb.Announcement{TextEn: "old"})
	stale, err := records.Sign(&pb.RecordBody{Id: r16(), Type: pb.RecordType_ANNOUNCEMENT, Author: keys.ID16(pub),
		CreatedMs: time.Now().Add(-11 * time.Minute).UnixMilli(), Payload: p}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.PublishNews(ctx, stale); err != nil {
		t.Fatal(err)
	}
	if len(w.woke) != 1 {
		t.Fatalf("stale announcement pushed")
	}
	// revocation
	events = f.notes.news
	f.withNewsManifest(t, 2)
	if got, _ := f.svc.News(ctx); len(got) != 0 {
		t.Fatalf("revoked news kept: %d", len(got))
	}
	if f.notes.news != events+1 {
		t.Fatalf("revocation sent %d news events", f.notes.news-events)
	}
}

func TestNewsPushSkipsOnlineAndNonCapable(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(nil)
	f.withNewsManifest(t, 1, pub)
	w := &wakeRec{}
	f.svc.Waker = w
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna")
	boris := f.mustRegister(f.invite(nil, time.Hour), "boris")
	f.registerPushToken(t, anna)
	f.registerPushToken(t, boris)
	f.svc.Notify = onlineNotifier{online: string(anna.id)}
	a := sign(t, pb.RecordType_ANNOUNCEMENT, keys.ID16(pub), &pb.Announcement{TextRu: "x"}, priv)
	if err := f.svc.PublishNews(ctx, a); err != nil {
		t.Fatal(err)
	}
	if len(w.woke) != 1 || w.woke[0] != string(boris.id) {
		t.Fatalf("woke %q, want only boris", w.woke)
	}
	// replicated from a push-capable peer: the origin pushed (D58)
	peer := r16()
	m := &pb.Manifest{Version: 2, NetworkPub: f.svc.NetworkPub, NewsKeys: [][]byte{pub}, Nodes: []*pb.NodeInfo{
		{NodeId: f.svc.NodeID, NodePub: f.svc.NodeKeyPriv.Public().(ed25519.PublicKey), Label: "a", PushCapable: true},
		{NodeId: peer, NodePub: pub, Label: "b", PushCapable: true}}}
	if err := f.svc.PublishManifest(ctx, sign(t, pb.RecordType_MANIFEST, keys.ID16(f.svc.NetworkPub), m, f.netPriv)); err != nil {
		t.Fatal(err)
	}
	b := sign(t, pb.RecordType_ANNOUNCEMENT, keys.ID16(pub), &pb.Announcement{TextRu: "y"}, priv)
	if ok, err := f.svc.ApplyReplicated(ctx, peer, b); !ok || err != nil {
		t.Fatalf("replicated: %v %v", ok, err)
	}
	if len(w.woke) != 1 {
		t.Fatalf("replicated from a capable origin pushed: %q", w.woke)
	}
}

func TestReplicatedNewsFromUnknownKeySkipped(t *testing.T) {
	f := newFx(t)
	f.withNewsManifest(t, 1)
	pub, priv, _ := ed25519.GenerateKey(nil)
	a := sign(t, pb.RecordType_ANNOUNCEMENT, keys.ID16(pub), &pb.Announcement{TextRu: "x"}, priv)
	ok, err := f.svc.ApplyReplicated(context.Background(), make([]byte, 16), a)
	if ok || err != nil {
		t.Fatalf("got %v %v", ok, err)
	}
}

type fakeApks struct{}

func (fakeApks) Chunk(sum []byte, index uint32) ([]byte, uint64, error) {
	if index > 0 {
		return nil, 0, os.ErrNotExist
	}
	return []byte("apk"), 3, nil
}

func TestApkChunk(t *testing.T) {
	f := newFx(t)
	sum := make([]byte, 32)
	if _, _, err := f.svc.ApkChunk(sum, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no apk dir: %v", err)
	}
	f.svc.Apks = fakeApks{}
	if d, n, err := f.svc.ApkChunk(sum, 0); err != nil || string(d) != "apk" || n != 3 {
		t.Fatalf("chunk: %q %d %v", d, n, err)
	}
	if _, _, err := f.svc.ApkChunk(sum, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("past end: %v", err)
	}
	if _, _, err := f.svc.ApkChunk(sum[:5], 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("short sum: %v", err)
	}
}
