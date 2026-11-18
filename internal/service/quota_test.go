package service

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ottermsg/server/internal/limits"
	pb "ottermsg/server/internal/proto/otterv1"
)

// A member's phone (or a thief with it) floods an offline recipient (D117).
func TestUndeliveredQuota(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	f.svc.Rejected = &limits.Counters{}
	a := f.mustRegister(f.invite(nil, time.Hour), "anna")
	b := f.mustRegister(f.invite(a, time.Hour), "boris")
	c := f.mustRegister(f.invite(a, time.Hour), "clara")
	env := func(from *user, n int) *pb.Record {
		return sign(t, pb.RecordType_ENVELOPE, from.id, &pb.Envelope{SenderUser: from.id, SenderDevice: 1,
			Kind: pb.Envelope_PREKEY_SIGNAL, Recipients: []*pb.Recipient{{User: a.id, Device: 1, Content: make([]byte, n)}}}, from.priv)
	}
	one := len(env(b, 4000).Body)
	f.svc.Limits.UserPending = int64(2*one + one/2) // room for two

	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.svc.Submit(ctx, b.id, env(b, 4000), pb.RecordType_ENVELOPE); err == nil {
				ok.Add(1)
			} else if !errors.Is(err, ErrQuota) {
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 2 {
		t.Fatalf("accepted %d, want 2", ok.Load())
	}
	if n := f.svc.Rejected.Pending.Load(); n != 6 {
		t.Fatalf("pending refusals counted %d, want 6", n)
	}
	if _, err := f.svc.Submit(ctx, c.id, env(c, 4000), pb.RecordType_ENVELOPE); err != nil {
		t.Fatalf("another author is not limited: %v", err)
	}
	// each node checks only its own submissions: boris's envelopes arriving from a peer are stored
	if applied, err := f.svc.ApplyReplicated(ctx, r16(), env(b, 4000)); err != nil || !applied {
		t.Fatalf("replicated envelope over the quota: %v %v", applied, err)
	}
	// anna's phone acks everything (acks are never refused for quota): boris has room again
	box, _ := f.svc.Mailbox(ctx, a.id, 1, 100)
	var ids [][]byte
	for _, e := range box {
		ids = append(ids, e.Key)
	}
	ack := sign(t, pb.RecordType_ACK, a.id, &pb.Ack{EnvelopeIds: ids, DeviceId: 1}, a.priv)
	if _, err := f.svc.Submit(ctx, a.id, ack, pb.RecordType_ACK); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Submit(ctx, b.id, env(b, 4000), pb.RecordType_ENVELOPE); err != nil {
		t.Fatalf("after delivery: %v", err)
	}
}

// UserPending 0 means no cap.
func TestUndeliveredQuotaOff(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	a := f.mustRegister(f.invite(nil, time.Hour), "anna")
	b := f.mustRegister(f.invite(a, time.Hour), "boris")
	f.svc.Limits.UserPending = 0
	for i := 0; i < 5; i++ {
		rec := sign(t, pb.RecordType_ENVELOPE, b.id, &pb.Envelope{SenderUser: b.id, SenderDevice: 1,
			Kind: pb.Envelope_PREKEY_SIGNAL, Recipients: []*pb.Recipient{{User: a.id, Device: 1, Content: make([]byte, 4000)}}}, b.priv)
		if _, err := f.svc.Submit(ctx, b.id, rec, pb.RecordType_ENVELOPE); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
}

// Writes refused for low disk are counted (otter_rejected_total{kind="disk"}).
func TestDiskRefusalsCounted(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	a := f.mustRegister(f.invite(nil, time.Hour), "anna")
	b := f.mustRegister(f.invite(a, time.Hour), "boris")
	f.svc.Rejected = &limits.Counters{}
	f.svc.Disk = &DiskGuard{Dir: t.TempDir(), Floor: 1 << 30,
		Free: func(string) (int64, int64, error) { return 100 << 20, 20 << 30, nil }}
	f.svc.Disk.Check()
	rec := sign(t, pb.RecordType_ENVELOPE, b.id, &pb.Envelope{SenderUser: b.id, SenderDevice: 1,
		Kind: pb.Envelope_PREKEY_SIGNAL, Recipients: []*pb.Recipient{{User: a.id, Device: 1, Content: []byte("x")}}}, b.priv)
	if _, err := f.svc.Submit(ctx, b.id, rec, pb.RecordType_ENVELOPE); !errors.Is(err, ErrRetryLater) {
		t.Fatalf("critical disk: %v", err)
	}
	if n := f.svc.Rejected.Disk.Load(); n != 1 {
		t.Fatalf("disk refusals %d, want 1", n)
	}
	f.svc.Rejected = nil // nil counters are fine
	if _, err := f.svc.Submit(ctx, b.id, rec, pb.RecordType_ENVELOPE); !errors.Is(err, ErrRetryLater) {
		t.Fatalf("critical disk, no counters: %v", err)
	}
}
