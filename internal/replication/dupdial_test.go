package replication

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	pb "ottermsg/server/internal/proto/otterv1"
)

// slowDialer takes `delay` before each dial (a slow or censored link, like ru-1 → eeee) and records how many dials
// to the same peer were in flight at once.
type slowDialer struct {
	inner    EndpointDialer
	delay    time.Duration
	cur, max atomic.Int32
	total    atomic.Int32
}

func (d *slowDialer) DialEndpoint(ctx context.Context, n *pb.NodeInfo, ep *pb.Endpoint) (*websocket.Conn, error) {
	c := d.cur.Add(1)
	defer d.cur.Add(-1)
	for {
		m := d.max.Load()
		if c <= m || d.max.CompareAndSwap(m, c) {
			break
		}
	}
	d.total.Add(1)
	select {
	case <-time.After(d.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return d.inner.DialEndpoint(ctx, n, ep)
}

// A dial that takes longer than dialEvery must not be joined by a second dial to the same peer: the second session
// would replace the first ("peer session down … context canceled" right before "peer session up", seen on ru-1
// 2026-11-15) and throw away whatever the first one had received.
func TestSlowDialIsNotDuplicated(t *testing.T) {
	m, _, _, aLog, rank := frozenMesh(t, time.Hour) // nothing freezes within the test
	a, b := m.nodes[0], m.nodes[1]
	sd := &slowDialer{inner: &dpiDialer{frozen: map[string]bool{}}, delay: 10 * dialEvery}
	a.repl = New(a.svc, &MultiDialer{EP: sd, Rank: rank, Log: aLog}, quiet, WithNetlog(aLog, rank))
	m.start()
	eventually(t, "session up after a slow dial", func() bool { return sessionOf(a, b.id) != nil })
	s := sessionOf(a, b.id)
	time.Sleep(20 * dialEvery)
	if got := sd.max.Load(); got != 1 {
		t.Fatalf("dials to one peer in flight at once: %d (want 1)", got)
	}
	if sessionOf(a, b.id) != s {
		t.Fatal("the first session was replaced by a duplicate dial")
	}
}
