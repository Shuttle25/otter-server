package meshsim

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

// client speaks the client protocol to one node (copy of the gateway test client).
type client struct {
	t      *testing.T
	c      *websocket.Conn
	next   atomic.Uint64
	resps  chan *pb.Response
	events chan *pb.Event
	hello  *pb.Hello
}

func (s *sim) dial(n *simNode) *client {
	t := s.t
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, s.url(n), nil)
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadLimit(1 << 20)
	cl := &client{t: t, c: c, resps: make(chan *pb.Response, 16), events: make(chan *pb.Event, 256)}
	go func() {
		for {
			_, data, err := c.Read(context.Background())
			if err != nil {
				close(cl.events)
				return
			}
			var f pb.Frame
			proto.Unmarshal(data, &f)
			if r := f.GetResponse(); r != nil {
				cl.resps <- r
			}
			if e := f.GetEvent(); e != nil {
				cl.events <- e
			}
		}
	}()
	cl.hello = &pb.Hello{}
	proto.Unmarshal(cl.nextEvent("hello").Body, cl.hello)
	t.Cleanup(func() { c.CloseNow() })
	return cl
}

func (c *client) close() { c.c.CloseNow() }

func (c *client) call(method string, req, resp proto.Message) (pb.Status, string) {
	c.t.Helper()
	b, _ := proto.Marshal(req)
	id := c.next.Add(1)
	f, _ := proto.Marshal(&pb.Frame{Kind: &pb.Frame_Request{Request: &pb.Request{Id: id, Method: method, Body: b}}})
	if err := c.c.Write(context.Background(), websocket.MessageBinary, f); err != nil {
		c.t.Fatal(err)
	}
	select {
	case r := <-c.resps:
		if resp != nil && r.Status == pb.Status_STATUS_OK {
			proto.Unmarshal(r.Body, resp)
		}
		return r.Status, r.Error
	case <-time.After(5 * time.Second):
		c.t.Fatalf("%s: timeout", method)
	}
	return 0, ""
}

func (c *client) mustCall(method string, req, resp proto.Message) {
	c.t.Helper()
	if st, msg := c.call(method, req, resp); st != pb.Status_STATUS_OK {
		c.t.Fatalf("%s: %v %s", method, st, msg)
	}
}

func (c *client) nextEvent(typ string) *pb.Event {
	c.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case e, ok := <-c.events:
			if !ok {
				c.t.Fatalf("closed while waiting for %s", typ)
			}
			if e.Type == typ {
				return e
			}
		case <-deadline:
			c.t.Fatalf("timeout waiting for event %s", typ)
		}
	}
}

// noEnvelopes asserts that no envelopes event arrives within d.
func (c *client) noEnvelopes(d time.Duration) {
	c.t.Helper()
	deadline := time.After(d)
	for {
		select {
		case e, ok := <-c.events:
			if ok && e.Type == "envelopes" {
				c.t.Fatal("unexpected envelopes")
			}
		case <-deadline:
			return
		}
	}
}

// envelopes waits for an envelopes event and returns the record keys it carries.
func (c *client) envelopes() [][]byte {
	c.t.Helper()
	var b pb.RecordBatch
	proto.Unmarshal(c.nextEvent("envelopes").Body, &b)
	var out [][]byte
	for _, r := range b.Records {
		var body pb.RecordBody
		proto.Unmarshal(r.Body, &body)
		k, _ := keys.RecordKey(body.Author, body.Id)
		out = append(out, k)
	}
	return out
}

type account struct {
	id    []byte
	priv  ed25519.PrivateKey
	name  string
	proof []byte // invite_proof of the entry (D100)
}

func (s *sim) signAs(a *account, typ pb.RecordType, payload proto.Message) *pb.Record {
	return s.sign(typ, a.id, payload, a.priv)
}

// register creates an account through node n's client API with a fresh bootstrap invite; owners get 11 one-time keys each.
func (s *sim) register(n *simNode, name string, owners ...*simNode) *account {
	return s.registerWith(n, name, s.invite(n), owners...)
}

// registerWith is register with a given invite.
func (s *sim) registerWith(n *simNode, name string, tk *ticket, owners ...*simNode) *account {
	a, st, msg := s.tryRegister(n, name, tk, owners...)
	if st != pb.Status_STATUS_OK {
		s.t.Fatalf("register %s: %v %s", name, st, msg)
	}
	return a
}

// tryRegister is registerWith returning the node's answer.
func (s *sim) tryRegister(n *simNode, name string, tk *ticket, owners ...*simNode) (*account, pb.Status, string) {
	if len(owners) == 0 {
		owners = []*simNode{n}
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	a := &account{id: keys.ID16(pub), priv: priv, name: name}
	e := &pb.DirectoryEntry{UserId: a.id, Username: name, DisplayName: name, AccountPub: pub,
		IdentityPub: make([]byte, 33), IdentitySig: make([]byte, 64), Version: 1, CanInvite: true,
		RegisteredMs: time.Now().UnixMilli()}
	if err := records.Redeem(e, tk.rec, tk.secret); err != nil {
		s.t.Fatal(err)
	}
	a.proof = e.InviteProof
	pk := &pb.PreKeys{DeviceId: 1, RegistrationId: 4,
		SignedPrekey: &pb.SignedPreKey{Id: 1, PublicKey: make([]byte, 33), Signature: make([]byte, 64)},
		KyberPrekey:  &pb.SignedPreKey{Id: 1, PublicKey: make([]byte, 1569), Signature: make([]byte, 64)}}
	id := uint32(1)
	for _, o := range owners {
		for i := 0; i < 11; i++ {
			pk.OneTime = append(pk.OneTime, &pb.OneTimePreKey{Id: id, PublicKey: make([]byte, 33), OwnerNode: o.id})
			id++
		}
	}
	sum := sha256.Sum256(tk.secret)
	c := s.dial(n)
	defer c.close()
	st, msg := c.call("register", &pb.RegisterRequest{
		DirectoryEntry: s.signAs(a, pb.RecordType_DIRECTORY_ENTRY, e),
		Prekeys:        s.signAs(a, pb.RecordType_PREKEYS, pk),
		InviteUsed:     s.signAs(a, pb.RecordType_INVITE_USED, &pb.InviteUsed{InviteId: sum[:], UserId: a.id})}, nil)
	return a, st, msg
}

// login dials n and logs a in.
func (s *sim) login(n *simNode, a *account) *client {
	c := s.dial(n)
	ts := time.Now().UnixMilli()
	c.mustCall("auth.login", &pb.LoginRequest{UserId: a.id, DeviceId: 1, TsMs: ts,
		Signature: ed25519.Sign(a.priv, keys.AuthMessage(c.hello.NodeId, c.hello.Nonce, ts))}, nil)
	return c
}

// send submits an envelope from -> to through c and returns its record key.
func (s *sim) send(c *client, from, to *account, text string) []byte {
	r := s.signAs(from, pb.RecordType_ENVELOPE, &pb.Envelope{SenderUser: from.id, SenderDevice: 1, Kind: pb.Envelope_SIGNAL,
		Recipients: []*pb.Recipient{{User: to.id, Device: 1, Content: []byte(text)}}})
	c.mustCall("msg.send", &pb.RecordRequest{Record: r}, nil)
	return recordKey(r)
}

func (s *sim) ack(c *client, who *account, ks ...[]byte) {
	c.mustCall("msg.ack", &pb.RecordRequest{Record: s.signAs(who, pb.RecordType_ACK, &pb.Ack{EnvelopeIds: ks, DeviceId: 1})}, nil)
}

func recordKey(r *pb.Record) []byte {
	var b pb.RecordBody
	proto.Unmarshal(r.Body, &b)
	k, _ := keys.RecordKey(b.Author, b.Id)
	return k
}

func contains(list [][]byte, k []byte) bool {
	for _, x := range list {
		if bytes.Equal(x, k) {
			return true
		}
	}
	return false
}
