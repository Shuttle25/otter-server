package service

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	pb "ottermsg/server/internal/proto/otterv1"
)

// A hostile peer or member filling the disk: bulk writes stop first, small replicated records last (D118).
func TestDiskFloorLevels(t *testing.T) {
	f := newFx(t)
	withBlobs(t, f)
	ctx := context.Background()
	a := f.mustRegister(f.invite(nil, time.Hour), "anna")
	b := f.mustRegister(f.invite(a, time.Hour), "boris")
	keep, err := f.persistentBlob(a) // created while the disk is fine
	if err != nil {
		t.Fatal(err)
	}
	free := int64(10 << 30)
	f.svc.Disk = &DiskGuard{Dir: t.TempDir(), Floor: 1 << 30,
		Free: func(string) (int64, int64, error) { return free, 20 << 30, nil }}
	level := func(want DiskLevel) {
		t.Helper()
		if got := f.svc.Disk.Check(); got != want {
			t.Fatalf("level %v, want %v", got, want)
		}
	}
	env := func() *pb.Record {
		return sign(t, pb.RecordType_ENVELOPE, b.id, &pb.Envelope{SenderUser: b.id, SenderDevice: 1,
			Kind: pb.Envelope_PREKEY_SIGNAL, Recipients: []*pb.Recipient{{User: a.id, Device: 1, Content: []byte("x")}}}, b.priv)
	}
	low := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, ErrRetryLater) || !strings.Contains(err.Error(), "node storage low") {
			t.Fatalf("%s: %v, want retry later / node storage low", what, err)
		}
	}
	tk := f.newTicket(a, time.Hour) // signed before the disk fills; registration is tried at critical

	free = 900 << 20
	level(DiskLow)
	_, err = f.persistentBlob(a)
	low("new blob at low disk", err)
	blob, err := f.svc.Store.Blob(ctx, keep)
	if err != nil {
		t.Fatal(err)
	}
	low("chunk at low disk", f.svc.StoreChunk(ctx, blob, 0, make([]byte, 1000)))
	low("chunk upload at low disk", f.svc.PutChunk(ctx, a.id, keep, 0, make([]byte, 1000)))
	low("backup at low disk", f.svc.PublishBackup(ctx, a.id, backupMetaRec(t, a, 1, bytes.Repeat([]byte{3}, 16), []byte("s"), keep)))
	if _, err := f.svc.Submit(ctx, b.id, env(), pb.RecordType_ENVELOPE); err != nil {
		t.Fatalf("message at low disk: %v", err)
	}
	if err := f.svc.UpdateDirectoryEntry(ctx, a.id, sign(t, pb.RecordType_DIRECTORY_ENTRY, a.id, entryV(a, "anna", "Анна", 2, 1), a.priv)); err != nil {
		t.Fatalf("profile edit at low disk: %v", err)
	}

	free = 200 << 20
	level(DiskCritical)
	_, err = f.svc.Submit(ctx, b.id, env(), pb.RecordType_ENVELOPE)
	low("message at critical disk", err)
	low("profile edit at critical disk", f.svc.UpdateDirectoryEntry(ctx, a.id,
		sign(t, pb.RecordType_DIRECTORY_ENTRY, a.id, entryV(a, "anna", "Аня", 3, 1), a.priv)))
	_, req := f.registerReq(tk, "vera")
	_, err = f.svc.Register(ctx, req)
	low("registration at critical disk", err)
	if _, err := f.svc.ApplyReplicated(ctx, r16(), env()); err != nil {
		t.Fatalf("replicated record at critical disk: %v", err)
	}
	// acks free space: the delivered envelope can still be dropped
	ack := sign(t, pb.RecordType_ACK, a.id, &pb.Ack{EnvelopeIds: [][]byte{make([]byte, 32)}, DeviceId: 1}, a.priv)
	if _, err := f.svc.Submit(ctx, a.id, ack, pb.RecordType_ACK); err != nil {
		t.Fatalf("ack at critical disk: %v", err)
	}
	// a record of another type cannot ride the ack path past the floor
	if _, err := f.svc.Submit(ctx, b.id, env(), pb.RecordType_ACK); errors.Is(err, ErrRetryLater) || err == nil {
		t.Fatalf("envelope via the ack path: %v", err)
	}

	free = 32 << 20
	level(DiskFull)
	_, err = f.svc.ApplyReplicated(ctx, r16(), env())
	low("replicated record at full disk", err)

	free = 10 << 30
	level(DiskOK)
	if _, err := f.persistentBlob(a); err != nil {
		t.Fatalf("after space was freed: %v", err)
	}
	if err := f.svc.StoreChunk(ctx, blob, 0, make([]byte, 1000)); errors.Is(err, ErrRetryLater) {
		t.Fatalf("chunk after space was freed: %v", err)
	}
	if _, err := f.svc.Register(ctx, req); err != nil {
		t.Fatalf("registration after space was freed: %v", err)
	}
	if _, err := f.svc.Submit(ctx, b.id, env(), pb.RecordType_ENVELOPE); err != nil {
		t.Fatalf("message after space was freed: %v", err)
	}
}

// floor "0" switches off low and critical; the 64 MiB reserve for SQLite always stays.
func TestDiskFloorDisabled(t *testing.T) {
	free := int64(100 << 20)
	g := &DiskGuard{Free: func(string) (int64, int64, error) { return free, 1 << 30, nil }}
	if l := g.Check(); l != DiskOK {
		t.Fatalf("floor 0 at 100 MiB: %v", l)
	}
	free = DiskReserve - 1
	if l := g.Check(); l != DiskFull {
		t.Fatalf("floor 0 below the reserve: %v", l)
	}
	if f, total := g.Usage(); f != DiskReserve-1 || total != 1<<30 {
		t.Fatalf("usage %d %d", f, total)
	}
	// a failed measurement keeps the last level
	g.Free = func(string) (int64, int64, error) { return 0, 0, errors.New("io") }
	if l := g.Check(); l != DiskFull {
		t.Fatalf("after a failed measurement: %v", l)
	}
	var nilGuard *DiskGuard
	if nilGuard.Level() != DiskOK {
		t.Fatal("nil guard must allow everything")
	}
}

// The real statfs measures the data directory.
func TestDiskStatfs(t *testing.T) {
	g := &DiskGuard{Dir: t.TempDir(), Floor: 1}
	g.Check()
	if free, total := g.Usage(); total <= 0 || free < 0 || free > total {
		t.Fatalf("statfs: free %d total %d", free, total)
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// Run re-measures and logs each change of level at warn.
func TestDiskRunLogsChanges(t *testing.T) {
	var mu sync.Mutex
	free := int64(10 << 30)
	g := &DiskGuard{Floor: 1 << 30, Free: func(string) (int64, int64, error) {
		mu.Lock()
		defer mu.Unlock()
		return free, 20 << 30, nil
	}}
	var out syncBuf
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.Run(ctx, time.Millisecond, slog.New(slog.NewTextHandler(&out, nil))); close(done) }()
	defer func() { cancel(); <-done }()
	for _, total := g.Usage(); total == 0; _, total = g.Usage() { // Run's first measurement (ok)
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	free = 100 << 20
	mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), "to=critical") {
		if time.Now().After(deadline) {
			t.Fatalf("no level change logged: %q", out.String())
		}
		time.Sleep(time.Millisecond)
	}
	if s := out.String(); !strings.Contains(s, "level=WARN") || !strings.Contains(s, "disk level changed") || !strings.Contains(s, "from=ok") {
		t.Fatalf("log: %q", s)
	}
	if g.Level() != DiskCritical {
		t.Fatalf("level %v", g.Level())
	}
}
