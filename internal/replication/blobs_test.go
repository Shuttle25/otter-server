package replication

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	pb "ottermsg/server/internal/proto/otterv1"
)

// fakePeer answers PeerBlobGet frames from its session's out channel with fixed bytes (nil = missing).
func fakePeer(r *Replicator, id byte, answer []byte) *session {
	ctx, cancel := context.WithCancel(context.Background())
	s := &session{r: r, peer: []byte{id}, ctx: ctx, cancel: cancel, out: make(chan *pb.PeerFrame, 4),
		pending: map[uint64]chan *pb.PeerBlobChunk{}, serveSem: make(chan struct{}, 4)}
	go func() {
		for {
			select {
			case f := <-s.out:
				g := f.GetBlobGet()
				s.pmu.Lock()
				ch := s.pending[g.Req]
				delete(s.pending, g.Req)
				s.pmu.Unlock()
				if ch != nil {
					ch <- blobChunk(g.Req, answer).GetBlobChunk()
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return s
}

func TestFetchChunkSkipsGarbageAndMissing(t *testing.T) {
	r := &Replicator{log: slog.New(slog.DiscardHandler), reg: registry{byPeer: map[string]*session{}}}
	good := []byte("good chunk")
	for _, p := range []*session{fakePeer(r, 1, []byte("garbage")), fakePeer(r, 2, nil), fakePeer(r, 3, good)} {
		r.reg.byPeer[string(p.peer)] = p
		defer p.cancel()
	}
	ok := func(d []byte) bool { return bytes.Equal(d, good) }
	got, err := r.FetchChunk(context.Background(), make([]byte, 32), 0, ok)
	if err != nil || !bytes.Equal(got, good) {
		t.Fatalf("fetch: %q %v", got, err)
	}
	if string(r.last.get(make([]byte, 32))) != string([]byte{3}) {
		t.Fatal("the answering peer is not remembered")
	}
	delete(r.reg.byPeer, string([]byte{3}))
	if _, err := r.FetchChunk(context.Background(), make([]byte, 32), 0, ok); err != ErrNoPeerHasChunk {
		t.Fatalf("without a good peer: %v", err)
	}
}

func TestLimiter(t *testing.T) {
	now := time.Unix(0, 0)
	var slept time.Duration
	l := &limiter{rate: 1000, now: func() time.Time { return now },
		sleep: func(_ context.Context, d time.Duration) error { slept += d; now = now.Add(d); return nil }}
	for i := 0; i < 5; i++ {
		l.wait(context.Background(), 500)
	}
	if slept != 2500*time.Millisecond {
		t.Fatalf("slept %v for 2500 bytes at 1000 B/s", slept)
	}
	now = now.Add(10 * time.Second) // idle time is not saved up as a burst
	slept = 0
	l.wait(context.Background(), 1000)
	if slept != time.Second {
		t.Fatalf("after idle: %v", slept)
	}
	unl := &limiter{rate: 0, now: time.Now, sleep: func(context.Context, time.Duration) error { t.Fatal("slept"); return nil }}
	unl.wait(context.Background(), 1<<30)
}
