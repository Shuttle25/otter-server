package meshsim

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/push"
)

type recSender struct {
	mu   sync.Mutex
	sent []string
	err  error
}

func (r *recSender) Send(_ context.Context, token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, token)
	return r.err
}

func (r *recSender) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.sent) }

// fakeClock lets a scenario step over the pusher's 10 s coalescing window without sleeping.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// enablePush gives every node a recording sender (an FCM key) and publishes manifest v2 with push_capable set for
// the listed labels. Call it right after newSim, before any client connects.
func (s *sim) enablePush(capable ...string) {
	var m pb.Manifest
	var body pb.RecordBody
	proto.Unmarshal(s.manifest.Body, &body)
	proto.Unmarshal(body.Payload, &m)
	var infos []*pb.NodeInfo
	for _, n := range m.Nodes {
		c := proto.Clone(n).(*pb.NodeInfo)
		c.PushCapable = slices.Contains(capable, n.Label)
		infos = append(infos, c)
	}
	s.manifest = s.signManifest(2, infos)
	for _, n := range s.nodes {
		n.sender = &recSender{}
		n.clock = &fakeClock{t: time.Now()}
		s.stop(n)
		s.start(n)
		if _, err := n.svc.ImportRecord(context.Background(), s.manifest); err != nil {
			s.t.Fatal(err)
		}
		if n.svc.CurrentManifest().GetVersion() != 2 {
			s.t.Fatalf("%s: manifest v2 not loaded", n.label)
		}
	}
}

func (s *sim) registerPush(c *client, a *account, token string) {
	c.mustCall("push.register", &pb.RecordRequest{Record: s.signAs(a, pb.RecordType_PUSH_TOKEN,
		&pb.PushToken{DeviceId: 1, Kind: pb.PushToken_FCM, Token: token})}, nil)
}

func (s *sim) sendUrgent(c *client, from, to *account, text string, urgent bool) []byte {
	r := s.signAs(from, pb.RecordType_ENVELOPE, &pb.Envelope{SenderUser: from.id, SenderDevice: 1, Kind: pb.Envelope_SIGNAL,
		Urgent: urgent, Recipients: []*pb.Recipient{{User: to.id, Device: 1, Content: []byte(text)}}})
	c.mustCall("msg.send", &pb.RecordRequest{Record: r}, nil)
	return recordKey(r)
}

// offline closes c and waits until node n no longer counts a's session as live.
func offline(t *testing.T, c *client, n *simNode, a *account) {
	t.Helper()
	c.close()
	eventually(t, a.name+" offline on "+n.label, func() bool { return !n.svc.Notify.Online(a.id, 1) })
}

func token(n *simNode, a *account) string {
	tok, _ := n.st.PushToken(context.Background(), a.id, 1)
	return tok
}

func TestPushFromFirstCapableNode(t *testing.T) {
	s := newSim(t, "a", "b", "c")
	s.enablePush("b")
	a, b, c := s.node("a"), s.node("b"), s.node("c")
	alice := s.register(a, "alice")
	bob := s.register(a, "bob")
	eventually(t, "bob known everywhere", func() bool { return b.knows(bob) && c.knows(bob) })
	cb := s.login(b, bob)
	s.registerPush(cb, bob, "bob-token")
	offline(t, cb, b, bob)
	eventually(t, "token replicated", func() bool { return token(a, bob) == "bob-token" && token(c, bob) == "bob-token" })
	ca := s.login(a, alice)
	defer ca.close()

	// (a) sender on a (not capable), recipient offline → exactly one push, from b; (b) three envelopes coalesce
	for i := 0; i < 3; i++ {
		s.sendUrgent(ca, alice, bob, fmt.Sprintf("hi %d", i), true)
	}
	eventually(t, "b pushed", func() bool { return b.sender.count() == 1 })
	eventually(t, "all three envelopes on every node", func() bool { return b.mailbox(bob) == 3 && c.mailbox(bob) == 3 })
	time.Sleep(300 * time.Millisecond)
	b.pusher.Wait()
	if b.sender.count() != 1 || a.sender.count() != 0 || c.sender.count() != 0 {
		t.Fatalf("pushes a=%d b=%d c=%d", a.sender.count(), b.sender.count(), c.sender.count())
	}

	// (d) a receipt (urgent=false) never pushes, even after the coalescing window
	for _, n := range s.nodes {
		n.clock.advance(11 * time.Second)
	}
	s.sendUrgent(ca, alice, bob, "receipt", false)
	eventually(t, "receipt on b", func() bool { return b.mailbox(bob) == 4 })
	time.Sleep(300 * time.Millisecond)
	b.pusher.Wait()
	if b.sender.count() != 1 {
		t.Fatalf("receipt pushed: %d", b.sender.count())
	}

	// (c) recipient online on b → no push from b
	cb2 := s.login(b, bob)
	defer cb2.close()
	s.sendUrgent(ca, alice, bob, "while online", true)
	eventually(t, "message on b and c", func() bool { return b.mailbox(bob) == 5 && c.mailbox(bob) == 5 })
	time.Sleep(300 * time.Millisecond)
	b.pusher.Wait()
	if b.sender.count() != 1 || a.sender.count() != 0 || c.sender.count() != 0 {
		t.Fatalf("pushed to an online recipient: a=%d b=%d c=%d", a.sender.count(), b.sender.count(), c.sender.count())
	}

	// control: once bob is offline again, the next urgent envelope pushes
	offline(t, cb2, b, bob)
	s.sendUrgent(ca, alice, bob, "after", true)
	eventually(t, "b pushed again", func() bool { return b.sender.count() == 2 })
}

func TestPushOriginCapable(t *testing.T) {
	s := newSim(t, "a", "b")
	s.enablePush("a", "b")
	a, b := s.node("a"), s.node("b")
	alice := s.register(a, "alice")
	bob := s.register(a, "bob")
	cb := s.login(a, bob)
	s.registerPush(cb, bob, "bob-token")
	offline(t, cb, a, bob)
	eventually(t, "b has token", func() bool { return token(b, bob) != "" })
	ca := s.login(a, alice)
	defer ca.close()
	s.sendUrgent(ca, alice, bob, "hi", true)
	eventually(t, "a pushed", func() bool { return a.sender.count() == 1 })
	eventually(t, "envelope on b", func() bool { return b.mailbox(bob) == 1 })
	time.Sleep(300 * time.Millisecond)
	b.pusher.Wait()
	if b.sender.count() != 0 {
		t.Fatalf("b pushed although the origin is capable")
	}
}

func TestPushUnregisteredDropsToken(t *testing.T) {
	s := newSim(t, "a")
	s.enablePush("a")
	a := s.node("a")
	a.sender.err = push.ErrUnregistered
	alice := s.register(a, "alice")
	bob := s.register(a, "bob")
	cb := s.login(a, bob)
	s.registerPush(cb, bob, "dead")
	offline(t, cb, a, bob)
	if token(a, bob) != "dead" {
		t.Fatal("token not stored")
	}
	ca := s.login(a, alice)
	defer ca.close()
	s.sendUrgent(ca, alice, bob, "hi", true)
	eventually(t, "token dropped", func() bool { return token(a, bob) == "" })
	if a.sender.count() != 1 {
		t.Fatalf("sends: %d", a.sender.count())
	}
}
