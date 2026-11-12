package meshsim

import (
	"context"
	"crypto/ed25519"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

type newsKey struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newNewsKey() newsKey {
	pub, priv, _ := ed25519.GenerateKey(nil)
	return newsKey{pub, priv}
}

// reissue signs the next manifest version with the current nodes and the given news keys and loads it on every node.
func (s *sim) reissue(news ...newsKey) {
	var m pb.Manifest
	var body pb.RecordBody
	proto.Unmarshal(s.manifest.Body, &body)
	proto.Unmarshal(body.Payload, &m)
	next := &pb.Manifest{Version: m.Version + 1, IssuedMs: time.Now().UnixMilli(), NetworkPub: s.netPub, Nodes: m.Nodes}
	for _, k := range news {
		next.NewsKeys = append(next.NewsKeys, k.pub)
	}
	s.manifest = s.sign(pb.RecordType_MANIFEST, keys.ID16(s.netPub), next, s.netPriv)
	for _, n := range s.nodes {
		if _, err := n.svc.ImportRecord(context.Background(), s.manifest); err != nil {
			s.t.Fatal(err)
		}
	}
	for _, n := range s.nodes { // a copy that arrived by replication first may still be loading
		eventually(s.t, n.label+" loads the new manifest", func() bool { return n.svc.CurrentManifest().GetVersion() == next.Version })
	}
}

func (s *sim) announcement(k newsKey, text string) *pb.Record {
	return s.sign(pb.RecordType_ANNOUNCEMENT, keys.ID16(k.pub), &pb.Announcement{TextRu: text, TextEn: text}, k.priv)
}

func (s *sim) deletion(k newsKey, target *pb.Record) *pb.Record {
	return s.sign(pb.RecordType_ANNOUNCEMENT_DELETED, keys.ID16(k.pub), &pb.AnnouncementDeleted{Target: recordKey(target)}, k.priv)
}

// publishNews sends rec with news.publish on a fresh, not logged-in connection to n (as otter-admin does).
func (s *sim) publishNews(n *simNode, rec *pb.Record) (pb.Status, string) {
	c := s.dial(n)
	defer c.close()
	return c.call("news.publish", &pb.RecordRequest{Record: rec}, nil)
}

func (n *simNode) newsCount() int {
	l, err := n.svc.News(context.Background())
	if err != nil {
		return -1
	}
	return len(l)
}

func newsList(c *client) []*pb.Record {
	var b pb.RecordBatch
	c.mustCall("news.list", &pb.Empty{}, &b)
	return b.Records
}

func TestNewsReplicationDeletionRevocation(t *testing.T) {
	s := newSim(t, "a", "b", "c")
	a, b, c := s.node("a"), s.node("b"), s.node("c")
	nk := newNewsKey()
	s.reissue(nk) // v2 lists the news key
	alice := s.register(a, "alice")
	eventually(t, "alice known on b", func() bool { return b.knows(alice) })
	cb := s.login(b, alice)
	defer cb.close()

	// published to a → replicated to b and c; the client on b is told and lists it
	ann := s.announcement(nk, "Вышла новая версия")
	if st, msg := s.publishNews(a, ann); st != pb.Status_STATUS_OK {
		t.Fatalf("publish: %v %s", st, msg)
	}
	if st, _ := s.publishNews(a, ann); st != pb.Status_STATUS_OK {
		t.Fatal("publish is not idempotent")
	}
	key := recordKey(ann)
	eventually(t, "announcement on b and c", func() bool { return b.has(key) && c.has(key) })
	cb.nextEvent("news")
	if l := newsList(cb); len(l) != 1 || !proto.Equal(l[0], ann) {
		t.Fatalf("news.list on b: %d records", len(l))
	}

	// a deletion published to c removes it on a and b
	del := s.deletion(nk, ann)
	if st, msg := s.publishNews(c, del); st != pb.Status_STATUS_OK {
		t.Fatalf("publish deletion: %v %s", st, msg)
	}
	eventually(t, "announcement gone on a and b", func() bool { return !a.has(key) && !b.has(key) && !c.has(key) })
	eventually(t, "deletion on a and b", func() bool { return a.has(recordKey(del)) && b.has(recordKey(del)) })
	cb.nextEvent("news")
	if l := newsList(cb); len(l) != 1 || !proto.Equal(l[0], del) {
		t.Fatalf("news.list after the deletion: %d records", len(l))
	}

	// a key that is not in the manifest: rejected by news.publish; injected into a's store, it does not spread
	rogue := newNewsKey()
	bad := s.announcement(rogue, "не от админа")
	if st, msg := s.publishNews(a, bad); st != pb.Status_STATUS_INVALID {
		t.Fatalf("rogue publish: %v %s", st, msg)
	}
	var body pb.RecordBody
	proto.Unmarshal(bad.Body, &body)
	if _, _, err := a.st.ApplyFrom(context.Background(), bad, &body, a.id); err != nil {
		t.Fatal(err)
	}
	if !a.has(recordKey(bad)) {
		t.Fatal("injection failed")
	}
	ann2 := s.announcement(nk, "Вторая новость")
	if st, msg := s.publishNews(a, ann2); st != pb.Status_STATUS_OK {
		t.Fatalf("publish 2: %v %s", st, msg)
	}
	eventually(t, "second announcement on b and c", func() bool { return b.has(recordKey(ann2)) && c.has(recordKey(ann2)) })
	time.Sleep(300 * time.Millisecond) // a few more replication rounds
	if b.has(recordKey(bad)) || c.has(recordKey(bad)) {
		t.Fatal("an announcement by an unlisted key was replicated")
	}

	// manifest v3 without the key: every node drops what it signed (and a drops the injected one)
	s.reissue()
	for _, n := range s.nodes { // the drop runs right after the manifest is loaded
		eventually(t, n.label+" drops the revoked news", func() bool { return n.newsCount() == 0 })
	}
	cb.nextEvent("news")
	if l := newsList(cb); len(l) != 0 {
		t.Fatalf("news.list after revocation: %d records", len(l))
	}
	if st, _ := s.publishNews(b, s.announcement(nk, "после отзыва")); st != pb.Status_STATUS_INVALID {
		t.Fatalf("revoked key accepted: %v", st)
	}
}

func TestNewsPush(t *testing.T) {
	s := newSim(t, "a", "b", "c")
	s.enablePush("b") // v2
	nk := newNewsKey()
	s.reissue(nk) // v3: push_capable b, news key
	a, b, c := s.node("a"), s.node("b"), s.node("c")
	alice := s.register(a, "alice")
	bob := s.register(a, "bob")
	carol := s.register(a, "carol")
	eventually(t, "accounts known on b", func() bool { return b.knows(alice) && b.knows(bob) && b.knows(carol) })
	for _, x := range []*account{bob, carol} {
		cx := s.login(b, x)
		s.registerPush(cx, x, x.name+"-token")
		offline(t, cx, b, x)
	}
	ca := s.login(b, alice) // alice stays online on b: no push for her
	defer ca.close()
	s.registerPush(ca, alice, "alice-token")
	eventually(t, "tokens on b", func() bool {
		return token(b, alice) != "" && token(b, bob) != "" && token(b, carol) != ""
	})

	// published to a (not push-capable): b, the first capable node, wakes every offline device once
	ann := s.announcement(nk, "Новость")
	if st, msg := s.publishNews(a, ann); st != pb.Status_STATUS_OK {
		t.Fatalf("publish: %v %s", st, msg)
	}
	eventually(t, "b pushed twice", func() bool { return b.sender.count() == 2 })
	eventually(t, "announcement on c", func() bool { return c.has(recordKey(ann)) })
	time.Sleep(300 * time.Millisecond)
	b.pusher.Wait()
	b.sender.mu.Lock()
	sent := slices.Clone(b.sender.sent)
	b.sender.mu.Unlock()
	slices.Sort(sent)
	if !slices.Equal(sent, []string{"bob-token", "carol-token"}) || a.sender.count() != 0 || c.sender.count() != 0 {
		t.Fatalf("pushes: b=%v a=%d c=%d", sent, a.sender.count(), c.sender.count())
	}

	// a deletion never pushes, even after the coalescing window
	for _, n := range s.nodes {
		n.clock.advance(11 * time.Second)
	}
	del := s.deletion(nk, ann)
	if st, msg := s.publishNews(a, del); st != pb.Status_STATUS_OK {
		t.Fatalf("publish deletion: %v %s", st, msg)
	}
	eventually(t, "deletion on b and c", func() bool { return b.has(recordKey(del)) && c.has(recordKey(del)) })
	time.Sleep(300 * time.Millisecond)
	b.pusher.Wait()
	if b.sender.count() != 2 || a.sender.count() != 0 || c.sender.count() != 0 {
		t.Fatalf("deletion pushed: a=%d b=%d c=%d", a.sender.count(), b.sender.count(), c.sender.count())
	}
}
