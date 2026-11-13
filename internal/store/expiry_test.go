package store

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

// putEnvelope applies an ENVELOPE from sender to (rcpt, device 1) directly through the store (no Validate, so an
// already-expired record can be inserted) and returns its record key.
func putEnvelope(t *testing.T, s *Store, sender, rcpt []byte, created, expires int64) []byte {
	t.Helper()
	p, _ := proto.Marshal(&pb.Envelope{SenderUser: sender, SenderDevice: 1, Kind: pb.Envelope_SIGNAL,
		Recipients: []*pb.Recipient{{User: rcpt, Device: 1, Content: []byte{1}}}})
	b := &pb.RecordBody{Id: r16(), Type: pb.RecordType_ENVELOPE, Author: sender, CreatedMs: created, ExpiresMs: expires, Payload: p}
	raw, _ := proto.Marshal(b)
	it := Item{Record: &pb.Record{Body: raw, Signature: make([]byte, 64)}, Body: b}
	if err := apply(t, s, it); err != nil {
		t.Fatal(err)
	}
	k, err := keys.RecordKey(sender, b.Id)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestMailboxSkipsAndJanitorPurgesExpiredEnvelopes(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	now := int64(1_800_000_000_000)
	s.now = func() time.Time { return time.UnixMilli(now) } // envelopes arrive "now", well inside the 30-day retention
	alice, bob := r16(), r16()
	short := putEnvelope(t, s, alice, bob, now-60_000, now+60_000) // created 1 min ago, expires in 1 min
	gone := putEnvelope(t, s, alice, bob, now-180_000, now-60_000) // expired 1 min ago (arrived before expiry)
	keep := putEnvelope(t, s, alice, bob, now-180_000, 0)          // never expires

	got, err := s.mailboxAt(ctx, bob, 1, 10, now)
	if err != nil {
		t.Fatal(err)
	}
	if !hasKey(got, short) || !hasKey(got, keep) || hasKey(got, gone) {
		t.Fatalf("mailbox = %v; want short+keep, not expired", got)
	}
	st, err := s.Expire(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if st.Envelopes != 1 {
		t.Fatalf("expired envelope not purged exactly once: %+v", st)
	}
	if _, err := s.Get(ctx, gone); err == nil {
		t.Fatal("expired envelope record still stored")
	}
	if _, err := s.Get(ctx, keep); err != nil {
		t.Fatalf("never-expiring envelope removed: %v", err)
	}
	// even ignoring the read filter, the mailbox row is gone
	got, _ = s.mailboxAt(ctx, bob, 1, 10, 0)
	if hasKey(got, gone) || !hasKey(got, keep) || !hasKey(got, short) {
		t.Fatalf("after janitor: %v", got)
	}
}

func hasKey(es []MailboxEntry, k []byte) bool {
	for _, e := range es {
		if string(e.Key) == string(k) {
			return true
		}
	}
	return false
}
