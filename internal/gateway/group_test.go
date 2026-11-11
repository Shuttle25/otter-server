package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

// One SENDER_KEY envelope to 4 recipients: each receives it; the record stays until the last ACK.
func TestGroupEnvelopeFanOut(t *testing.T) {
	n := startNode(t)
	ctx := context.Background()
	register := func(name string) (*acct, *client) {
		secret := make([]byte, 32)
		rand.Read(secret)
		sum := sha256.Sum256(secret)
		inv := sign(t, pb.RecordType_INVITE, keys.ID16(n.svc.NetworkPub), &pb.Invite{InviteId: sum[:], ExpiresMs: time.Now().Add(time.Hour).UnixMilli()}, n.netPriv)
		if _, err := n.svc.ImportRecord(ctx, inv); err != nil {
			t.Fatal(err)
		}
		c := dial(t, n)
		a, req := registerReq(t, n, secret, name)
		if st, msg := c.call("register", req, nil); st != pb.Status_STATUS_OK {
			t.Fatalf("register %s: %v %s", name, st, msg)
		}
		login(t, c, a)
		return a, c
	}
	sender, cs := register("sender")
	var members []*acct
	var clients []*client
	for _, name := range []string{"m_one", "m_two", "m_three", "m_four"} {
		a, c := register(name)
		members, clients = append(members, a), append(clients, c)
	}
	var rs []*pb.Recipient
	for _, m := range members {
		rs = append(rs, &pb.Recipient{User: m.id, Device: 1})
	}
	env := sign(t, pb.RecordType_ENVELOPE, sender.id, &pb.Envelope{SenderUser: sender.id, SenderDevice: 1,
		Kind: pb.Envelope_SENDER_KEY, SharedContent: []byte("group ciphertext"), Recipients: rs}, sender.priv)
	if st, msg := cs.call("msg.send", &pb.RecordRequest{Record: env}, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("send: %v %s", st, msg)
	}
	for i, c := range clients {
		var batch pb.RecordBatch
		proto.Unmarshal(c.nextEvent("envelopes").Body, &batch)
		if len(batch.Records) != 1 || !proto.Equal(batch.Records[0], env) {
			t.Fatalf("member %d got %v", i, batch.Records)
		}
	}
	var body pb.RecordBody
	proto.Unmarshal(env.Body, &body)
	key, _ := keys.RecordKey(body.Author, body.Id)
	for i, m := range members {
		ack := sign(t, pb.RecordType_ACK, m.id, &pb.Ack{EnvelopeIds: [][]byte{key}, DeviceId: 1}, m.priv)
		if st, msg := clients[i].call("msg.ack", &pb.RecordRequest{Record: ack}, nil); st != pb.Status_STATUS_OK {
			t.Fatalf("ack %d: %v %s", i, st, msg)
		}
		_, err := n.svc.Store.Get(ctx, key)
		if i < len(members)-1 && err != nil {
			t.Fatalf("record gone after %d acks: %v", i+1, err)
		}
		if i == len(members)-1 && err == nil {
			t.Fatal("record still present after all acks")
		}
	}
}
