package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"context"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

func r16() []byte { b := make([]byte, 16); rand.Read(b); return b }

func sign(t *testing.T, typ pb.RecordType, author []byte, payload proto.Message, k ed25519.PrivateKey) *pb.Record {
	p, _ := proto.Marshal(payload)
	r, err := records.Sign(&pb.RecordBody{Id: r16(), Type: typ, Author: author, CreatedMs: time.Now().UnixMilli(), Payload: p}, k)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

type acct struct {
	id   []byte
	priv ed25519.PrivateKey
}

// ticket is an invite as the inviter's app hands it over: the signed INVITE and the secret from the link.
type ticket struct {
	secret []byte
	rec    *pb.Record
}

// newTicket signs a fresh invite by author (not published).
func newTicket(t *testing.T, author []byte, k ed25519.PrivateKey) *ticket {
	secret := make([]byte, 32)
	rand.Read(secret)
	inv, err := records.InvitePayload(secret, time.Now().Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	return &ticket{secret: secret, rec: sign(t, pb.RecordType_INVITE, author, inv, k)}
}

// netInvite imports a network-signed bootstrap invite on n, as the operator does.
func netInvite(t *testing.T, n *node) *ticket {
	tk := newTicket(t, keys.ID16(n.svc.NetworkPub), n.netPriv)
	if _, err := n.svc.ImportRecord(context.Background(), tk.rec); err != nil {
		t.Fatal(err)
	}
	return tk
}

func registerReq(t *testing.T, n *node, tk *ticket, name string) (*acct, *pb.RegisterRequest) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	id := keys.ID16(pub)
	entry := &pb.DirectoryEntry{UserId: id, Username: name, DisplayName: name, AccountPub: pub,
		IdentityPub: make([]byte, 33), IdentitySig: make([]byte, 64), Version: 1, CanInvite: true,
		RegisteredMs: time.Now().UnixMilli()}
	if err := records.Redeem(entry, tk.rec, tk.secret); err != nil {
		t.Fatal(err)
	}
	pk := &pb.PreKeys{DeviceId: 1, RegistrationId: 9,
		SignedPrekey: &pb.SignedPreKey{Id: 1, PublicKey: make([]byte, 33), Signature: make([]byte, 64)},
		KyberPrekey:  &pb.SignedPreKey{Id: 1, PublicKey: make([]byte, 1569), Signature: make([]byte, 64)}}
	for i := 0; i < 11; i++ {
		pk.OneTime = append(pk.OneTime, &pb.OneTimePreKey{Id: uint32(i + 1), PublicKey: make([]byte, 33), OwnerNode: n.svc.NodeID})
	}
	sum := sha256.Sum256(tk.secret)
	return &acct{id, priv}, &pb.RegisterRequest{
		DirectoryEntry: sign(t, pb.RecordType_DIRECTORY_ENTRY, id, entry, priv),
		Prekeys:        sign(t, pb.RecordType_PREKEYS, id, pk, priv),
		InviteUsed:     sign(t, pb.RecordType_INVITE_USED, id, &pb.InviteUsed{InviteId: sum[:], UserId: id}, priv)}
}

func login(t *testing.T, c *client, a *acct) { loginResp(t, c, a) }

// loginResp logs a in on c and returns the decoded answer.
func loginResp(t *testing.T, c *client, a *acct) *pb.LoginResponse {
	ts := time.Now().UnixMilli()
	var resp pb.LoginResponse
	st, msg := c.call("auth.login", &pb.LoginRequest{UserId: a.id, DeviceId: 1, TsMs: ts,
		Signature: ed25519.Sign(a.priv, keys.AuthMessage(c.hello.NodeId, c.hello.Nonce, ts))}, &resp)
	if st != pb.Status_STATUS_OK {
		t.Fatalf("login: %v %s", st, msg)
	}
	return &resp
}

func TestEndToEnd(t *testing.T) {
	n := startNode(t)
	ctx := context.Background()

	// bootstrap invite imported by the operator
	secret := netInvite(t, n)

	ca := dial(t, n)
	if st, _ := ca.call("directory.sync", &pb.Empty{}, nil); st != pb.Status_STATUS_UNAUTHORIZED {
		t.Fatalf("pre-login call: %v", st)
	}
	anna, req := registerReq(t, n, secret, "anna")
	if st, msg := ca.call("register", req, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("register: %v %s", st, msg)
	}
	login(t, ca, anna)
	if st, _ := ca.call("auth.login", &pb.LoginRequest{}, nil); st != pb.Status_STATUS_INVALID {
		t.Fatal("second login must fail")
	}

	// anna invites boris
	s2 := newTicket(t, anna.id, anna.priv)
	invRec := s2.rec
	if st, msg := ca.call("invite.create", &pb.RecordRequest{Record: invRec}, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("invite: %v %s", st, msg)
	}
	cb := dial(t, n)
	boris, req2 := registerReq(t, n, s2, "boris")
	if st, msg := cb.call("register", req2, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("register boris: %v %s", st, msg)
	}
	ca.nextEvent("directory")
	login(t, cb, boris)

	var dir pb.RecordBatch
	cb.call("directory.sync", &pb.Empty{}, &dir)
	if len(dir.Records) != 2 {
		t.Fatalf("directory: %d", len(dir.Records))
	}

	var bundle pb.PreKeyBundle
	if st, msg := cb.call("prekeys.fetch", &pb.PreKeyFetchRequest{UserId: anna.id, DeviceId: 1}, &bundle); st != pb.Status_STATUS_OK || bundle.OneTime == nil {
		t.Fatalf("prekeys: %v %s", st, msg)
	}
	// 11 uploaded: after one fetch 10 remain (not low); the second fetch leaves 9 -> prekeys_low
	cb.call("prekeys.fetch", &pb.PreKeyFetchRequest{UserId: anna.id, DeviceId: 1}, &bundle)
	ca.nextEvent("prekeys_low")

	// boris -> anna
	env := sign(t, pb.RecordType_ENVELOPE, boris.id, &pb.Envelope{SenderUser: boris.id, SenderDevice: 1, Kind: pb.Envelope_PREKEY_SIGNAL, Urgent: true,
		Recipients: []*pb.Recipient{{User: anna.id, Device: 1, Content: []byte("hello")}}}, boris.priv)
	if st, msg := cb.call("msg.send", &pb.RecordRequest{Record: env}, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("send: %v %s", st, msg)
	}
	var batch pb.RecordBatch
	proto.Unmarshal(ca.nextEvent("envelopes").Body, &batch)
	if len(batch.Records) != 1 || !proto.Equal(batch.Records[0], env) {
		t.Fatalf("delivered %v", batch.Records)
	}

	// reconnect without ack -> redelivered
	ca.c.CloseNow()
	ca2 := dial(t, n)
	login(t, ca2, anna)
	proto.Unmarshal(ca2.nextEvent("envelopes").Body, &batch)
	if len(batch.Records) != 1 {
		t.Fatal("not redelivered")
	}

	// ack -> gone
	var body pb.RecordBody
	proto.Unmarshal(env.Body, &body)
	key, _ := keys.RecordKey(body.Author, body.Id)
	ack := sign(t, pb.RecordType_ACK, anna.id, &pb.Ack{EnvelopeIds: [][]byte{key}, DeviceId: 1}, anna.priv)
	if st, msg := ca2.call("msg.ack", &pb.RecordRequest{Record: ack}, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("ack: %v %s", st, msg)
	}
	if box, _ := n.svc.Mailbox(ctx, anna.id, 1, 10); len(box) != 0 {
		t.Fatal("mailbox not empty after ack")
	}
	ca3 := dial(t, n)
	login(t, ca3, anna)
	ca3.noEvent("envelopes", 300*time.Millisecond)
}

func TestOversizedFrameClosesConnection(t *testing.T) {
	n := startNode(t)
	c := dial(t, n)
	if st, _ := c.call("nope.method", &pb.Empty{}, nil); st != pb.Status_STATUS_UNAUTHORIZED {
		t.Fatalf("unknown method before login: %v", st)
	}
	big := make([]byte, maxFrame+1)
	_ = c.c.Write(context.Background(), websocket.MessageBinary, big)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-c.events:
			if !ok {
				return // closed by the server
			}
		case <-deadline:
			t.Fatal("connection not closed after oversized frame")
		}
	}
}

func TestUnknownMethodAfterLogin(t *testing.T) {
	n := startNode(t)
	secret := netInvite(t, n)
	c := dial(t, n)
	a, req := registerReq(t, n, secret, "anna")
	if st, msg := c.call("register", req, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("register: %v %s", st, msg)
	}
	login(t, c, a)
	if st, _ := c.call("nope.method", &pb.Empty{}, nil); st != pb.Status_STATUS_INVALID {
		t.Fatalf("unknown method: %v", st)
	}
	if st, _ := c.call("msg.send", &pb.RecordRequest{}, nil); st != pb.Status_STATUS_INVALID {
		t.Fatalf("missing record: %v", st)
	}
	if st, _ := c.call("ping", &pb.Empty{}, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("ping: %v", st)
	}
}
