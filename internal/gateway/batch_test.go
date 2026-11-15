package gateway

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/store"
)

// TestEnvelopeBatchesStayUnderTheByteBudget: queued big envelopes reach the phone in several events, none bigger
// than deliverBatchBytes plus one record (M9.1, D93), so a phone's 4 MiB frame limit never cuts an honest node.
func TestEnvelopeBatchesStayUnderTheByteBudget(t *testing.T) {
	n := startNode(t)
	anna, ca := newTestUser(t, n, "anna") // stays logged out while boris sends
	boris, cb := newTestUser(t, n, "boris")
	login(t, cb, boris)
	var sent [][]byte
	for i := 0; i < 8; i++ {
		env := sign(t, pb.RecordType_ENVELOPE, boris.id, &pb.Envelope{SenderUser: boris.id, SenderDevice: 1, Kind: pb.Envelope_SIGNAL,
			Recipients: []*pb.Recipient{{User: anna.id, Device: 1, Content: bytes.Repeat([]byte{byte(i)}, 250<<10)}}}, boris.priv)
		if st, msg := cb.call("msg.send", &pb.RecordRequest{Record: env}, nil); st != pb.Status_STATUS_OK {
			t.Fatalf("send %d: %v %s", i, st, msg)
		}
		sent = append(sent, env.Body)
	}
	login(t, ca, anna)
	var got [][]byte
	events := 0
	for len(got) < len(sent) {
		e := ca.nextEvent("envelopes")
		events++
		if len(e.Body) > deliverBatchBytes+(300<<10) {
			t.Fatalf("event %d is %d bytes", events, len(e.Body))
		}
		var b pb.RecordBatch
		if err := proto.Unmarshal(e.Body, &b); err != nil {
			t.Fatal(err)
		}
		for _, r := range b.Records {
			got = append(got, r.Body)
		}
	}
	if events < 3 {
		t.Fatalf("8 × 250 KiB came in %d events", events)
	}
	for i := range sent {
		if !bytes.Equal(sent[i], got[i]) {
			t.Fatalf("envelope %d out of order", i)
		}
	}
}

func mailboxEntries(t *testing.T, sizes ...int) []store.MailboxEntry {
	t.Helper()
	var es []store.MailboxEntry
	for i, n := range sizes {
		raw, err := proto.Marshal(&pb.Record{Body: bytes.Repeat([]byte{byte(i)}, n)})
		if err != nil {
			t.Fatal(err)
		}
		es = append(es, store.MailboxEntry{Key: []byte{byte(i >> 8), byte(i)}, Raw: raw})
	}
	return es
}

// TestNextBatchSendsAnOversizedRecordAlone: a record bigger than the byte budget is still delivered, in an event
// of its own; the records around it go in the events before and after.
func TestNextBatchSendsAnOversizedRecordAlone(t *testing.T) {
	es := mailboxEntries(t, 100, 5000, 100)
	sent := map[string]bool{}
	var counts []int
	for {
		b, full := nextBatch(es, sent, 1000)
		if len(b.Records) == 0 {
			break
		}
		counts = append(counts, len(b.Records))
		if !full {
			break
		}
	}
	if len(counts) != 3 || counts[0] != 1 || counts[1] != 1 || counts[2] != 1 {
		t.Fatalf("events %v, want [1 1 1]", counts)
	}
}

// TestNextBatchKeepsTheRecordCapForSmallEnvelopes: small envelopes still go 100 per event.
func TestNextBatchKeepsTheRecordCapForSmallEnvelopes(t *testing.T) {
	sizes := make([]int, 250)
	for i := range sizes {
		sizes[i] = 50
	}
	es := mailboxEntries(t, sizes...)
	sent := map[string]bool{}
	var counts []int
	for {
		b, full := nextBatch(es, sent, deliverBatchBytes)
		counts = append(counts, len(b.Records))
		if !full {
			break
		}
	}
	if len(counts) != 3 || counts[0] != deliverBatch || counts[1] != deliverBatch || counts[2] != 50 {
		t.Fatalf("events %v, want [100 100 50]", counts)
	}
	if b, _ := nextBatch(es, sent, deliverBatchBytes); len(b.Records) != 0 {
		t.Fatalf("%d records sent twice", len(b.Records))
	}
}
