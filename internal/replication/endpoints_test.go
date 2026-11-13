package replication

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	"ottermsg/server/internal/netlog"
	pb "ottermsg/server/internal/proto/otterv1"
)

func eps(names ...string) []*pb.Endpoint {
	var out []*pb.Endpoint
	for _, n := range names {
		out = append(out, &pb.Endpoint{Kind: pb.Endpoint_WSS, Host: n, Port: 1})
	}
	return out
}

func hosts(es []*pb.Endpoint) string {
	s := ""
	for _, e := range es {
		s += e.Host
	}
	return s
}

func TestRankerOrder(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	r := NewRanker(func() time.Time { return now })
	e := eps("a", "b", "c", "d")
	e[2].Priority = 0
	e[0].Priority, e[1].Priority, e[3].Priority = 5, 5, 5
	if got := hosts(r.Order(e)); got != "cabd" {
		t.Fatalf("priority then manifest order: %s", got)
	}
	r.Done(e[3], netlog.OK)
	r.Done(e[2], netlog.Timeout)
	if got := hosts(r.Order(e)); got != "dabc" {
		t.Fatalf("success first, recent failure last: %s", got)
	}
	for i := 0; i < 3; i++ {
		r.Done(e[3], netlog.ResetAfterKB)
	}
	if got := hosts(r.Order(e)); got != "abcd" {
		t.Fatalf("throttled endpoint demoted below failures: %s", got)
	}
	now = now.Add(25 * time.Hour)
	r.Done(e[3], netlog.OK)
	if got := hosts(r.Order(e)); got[0] != 'd' {
		t.Fatalf("demotion expires after 24h: %s", got)
	}
}

type fakeEP struct {
	mu    sync.Mutex
	fail  map[string]error
	tried []string
}

func (f *fakeEP) DialEndpoint(ctx context.Context, n *pb.NodeInfo, ep *pb.Endpoint) (*websocket.Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tried = append(f.tried, ep.Host)
	if err := f.fail[ep.Host]; err != nil {
		return nil, err
	}
	return nil, errSkip // never reached in this test
}

var errSkip = errors.New("unused")

type memLog struct {
	mu sync.Mutex
	es []netlog.Entry
}

func (m *memLog) Add(_ context.Context, e netlog.Entry) {
	m.mu.Lock()
	m.es = append(m.es, e)
	m.mu.Unlock()
}

func TestMultiDialerTriesAllAndLogs(t *testing.T) {
	f := &fakeEP{fail: map[string]error{"a": context.DeadlineExceeded, "b": context.DeadlineExceeded}}
	log := &memLog{}
	d := &MultiDialer{EP: f, Rank: NewRanker(time.Now), Log: log}
	n := &pb.NodeInfo{Label: "eeee", Endpoints: eps("a", "b")}
	if _, err := d.Dial(context.Background(), n); err == nil {
		t.Fatal("expected failure")
	}
	if len(f.tried) != 2 || len(log.es) != 2 || log.es[0].Class != netlog.Timeout || log.es[0].Peer != "eeee" ||
		log.es[0].Direction != "out" || log.es[0].Endpoint != "wss:a:1" {
		t.Fatalf("tried %v log %+v", f.tried, log.es)
	}
}

func (m *memLog) find(pred func(netlog.Entry) bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.es {
		if pred(e) {
			return true
		}
	}
	return false
}

// A dial-out-only node dials B; B logs the inbound session, and when B cuts the session soon after A received
// over 1 KB, A logs reset_after_kb for the endpoint it dialed and ranks it down.
func TestSessionLogsInboundAndThrottle(t *testing.T) {
	m := newMesh(t, 2, false)
	a, b := m.nodes[0], m.nodes[1]
	man := proto.Clone(a.svc.CurrentManifest()).(*pb.Manifest)
	man.Version = 2
	man.Nodes[0].DialOutOnly = true
	rec := m.sign(pb.RecordType_MANIFEST, keys.ID16(m.netPub), man, m.netPriv)
	for _, nd := range m.nodes {
		if _, err := nd.svc.ImportRecord(context.Background(), rec); err != nil {
			t.Fatal(err)
		}
	}
	aLog, bLog := &memLog{}, &memLog{}
	rank := NewRanker(time.Now)
	a.repl = New(a.svc, &MultiDialer{EP: NetDialer{AllowPlain: true}, Rank: rank, Log: aLog}, quiet, WithNetlog(aLog, rank))
	b.repl.nlog = bLog
	m.start()
	boris := m.register(1, "boris") // carries a 1569-byte prekey: well over 1 KB to A
	eventually(t, "boris on A", func() bool { return known(a, boris) })
	if !bLog.find(func(e netlog.Entry) bool {
		return e.Direction == "in" && e.Peer == "n0" && e.Endpoint == "wss" && e.Class == netlog.OK
	}) {
		t.Fatalf("no inbound line on B: %+v", bLog.es)
	}
	ep := man.Nodes[1].Endpoints[0]
	if !aLog.find(func(e netlog.Entry) bool {
		return e.Direction == "out" && e.Peer == "n1" && e.Endpoint == EndpointName(ep) && e.Class == netlog.OK
	}) {
		t.Fatalf("no outbound line on A: %+v", aLog.es)
	}
	b.repl.DropPeer(a.id)
	eventually(t, "reset_after_kb on A", func() bool {
		return aLog.find(func(e netlog.Entry) bool {
			return e.Direction == "out" && e.Peer == "n1" && e.Class == netlog.ResetAfterKB && e.Endpoint == EndpointName(ep)
		})
	})
	rank.mu.Lock()
	throttles := len(rank.st[EndpointName(ep)].throttles)
	rank.mu.Unlock()
	if throttles != 1 {
		t.Fatalf("ranker throttles: %d", throttles)
	}
}
