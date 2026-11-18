package gateway

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"ottermsg/server/internal/limits"
	pb "ottermsg/server/internal/proto/otterv1"
)

func tightLimits(g *Gateway) {
	g.ExemptLoopback = false // httptest clients come from 127.0.0.1
	g.IPRequests = limits.NewKeyed(0.001, 5)
	g.IPPublic = limits.NewKeyed(0.001, 2)
}

func tooMany(st pb.Status, msg string) bool {
	return st == pb.Status_STATUS_RETRY_LATER && strings.Contains(msg, "too many requests")
}

// A hostile client floods requests and public methods from one address; the session stays open.
func TestRequestRateLimits(t *testing.T) {
	n := startNode(t, tightLimits)
	c := dial(t, n)
	for i := 0; i < 2; i++ {
		if st, msg := c.call("backup.auth", &pb.BackupAuthRequest{Username: "nobody"}, nil); tooMany(st, msg) {
			t.Fatalf("public call %d refused", i)
		}
	}
	st, msg := c.call("backup.auth", &pb.BackupAuthRequest{Username: "nobody"}, nil)
	if !tooMany(st, msg) {
		t.Fatalf("3rd public call: %v %s", st, msg)
	}
	for i := 0; i < 2; i++ {
		if st, msg := c.call("ping", &pb.Empty{}, nil); tooMany(st, msg) {
			t.Fatalf("ping %d refused", i)
		}
	}
	if st, msg := c.call("ping", &pb.Empty{}, nil); !tooMany(st, msg) {
		t.Fatalf("6th request: %v %s", st, msg)
	}
	// a second connection from the same address shares the buckets
	if st, msg := dial(t, n).call("ping", &pb.Empty{}, nil); !tooMany(st, msg) {
		t.Fatalf("new connection, same address: %v %s", st, msg)
	}
	// the session is still open: refusals keep being answered
	if st, msg := c.call("ping", &pb.Empty{}, nil); !tooMany(st, msg) {
		t.Fatalf("after refusals: %v %s", st, msg)
	}
	gw := n.svc.Notify.(*Gateway)
	if gw.Rejected.ReqRate.Load() != 3 || gw.Rejected.PublicRate.Load() != 1 {
		t.Fatalf("counters %+v", gw.Rejected.Map())
	}
}

// Under the D116 defaults a stranger gets 20 public calls, then waits; ordinary traffic of a family (here 400
// requests at once from one address) passes.
func TestDefaultLimits(t *testing.T) {
	n := startNode(t, func(g *Gateway) { g.ExemptLoopback = false })
	c := dial(t, n)
	for i := 0; i < 400; i++ {
		if st, msg := c.call("ping", &pb.Empty{}, nil); tooMany(st, msg) {
			t.Fatalf("ping %d refused", i)
		}
	}
	for i := 0; i < 20; i++ {
		if st, msg := c.call("news.publish", &pb.RecordRequest{}, nil); st != pb.Status_STATUS_INVALID {
			t.Fatalf("public call %d: %v %s", i, st, msg)
		}
	}
	if st, msg := c.call("register", &pb.RegisterRequest{}, nil); !tooMany(st, msg) {
		t.Fatalf("21st public call: %v %s", st, msg)
	}
}

// Loopback (REALITY's inner listener, every phone behind it) is exempt by default.
func TestLoopbackExempt(t *testing.T) {
	n := startNode(t)
	c := dial(t, n)
	for i := 0; i < 50; i++ {
		if st, msg := c.call("news.publish", &pb.RecordRequest{}, nil); tooMany(st, msg) {
			t.Fatalf("loopback public call %d refused", i)
		}
	}
}

// Restores relayed through a no_backups node arrive as "tunnel:<relay id>" (M9.3): they are limited under that one
// key, and other sources keep their own budget.
func TestTunnelSessionsKeyedByRelay(t *testing.T) {
	var from atomic.Value
	from.Store("tunnel:00")
	relay := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r2 := r.Clone(r.Context())
			r2.RemoteAddr = from.Load().(string)
			h.ServeHTTP(w, r2)
		})
	}
	n := startNodeWrapped(t, relay, func(g *Gateway) { g.IPPublic = limits.NewKeyed(0.001, 2) })
	a, b := dial(t, n), dial(t, n)
	for _, c := range []*client{a, b} {
		if st, msg := c.call("backup.auth", &pb.BackupAuthRequest{Username: "nobody"}, nil); tooMany(st, msg) {
			t.Fatalf("relayed restore refused: %s", msg)
		}
	}
	if st, msg := a.call("backup.auth", &pb.BackupAuthRequest{Username: "nobody"}, nil); !tooMany(st, msg) {
		t.Fatalf("3rd call via the same relay: %v %s", st, msg)
	}
	from.Store("tunnel:01")
	if st, msg := dial(t, n).call("backup.auth", &pb.BackupAuthRequest{Username: "nobody"}, nil); tooMany(st, msg) {
		t.Fatalf("another relay refused: %s", msg)
	}
}

// A logged-in member floods write calls: after the burst they are refused, reads still pass (D116).
func TestUserWriteRate(t *testing.T) {
	n := startNode(t, func(g *Gateway) { g.UserWrites = limits.NewKeyed(0.001, 3) })
	anna, _ := newTestUser(t, n, "anna")
	boris, cb := newTestUser(t, n, "boris")
	login(t, cb, boris)
	send := func() (pb.Status, string) {
		env := sign(t, pb.RecordType_ENVELOPE, boris.id, &pb.Envelope{SenderUser: boris.id, SenderDevice: 1, Kind: pb.Envelope_SIGNAL,
			Recipients: []*pb.Recipient{{User: anna.id, Device: 1, Content: []byte("hi")}}}, boris.priv)
		return cb.call("msg.send", &pb.RecordRequest{Record: env}, nil)
	}
	for i := 0; i < 3; i++ {
		if st, msg := send(); st != pb.Status_STATUS_OK {
			t.Fatalf("send %d: %v %s", i, st, msg)
		}
	}
	if st, msg := send(); !tooMany(st, msg) {
		t.Fatalf("4th send: %v %s", st, msg)
	}
	if st, msg := cb.call("directory.sync", &pb.Empty{}, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("read after the write limit: %v %s", st, msg)
	}
	if gw := n.svc.Notify.(*Gateway); gw.Rejected.UserRate.Load() != 1 {
		t.Fatalf("counters %+v", gw.Rejected.Map())
	}
}

// Over the undelivered quota msg.send answers STATUS_QUOTA (D117).
func TestUndeliveredQuotaStatus(t *testing.T) {
	n := startNode(t)
	n.svc.Limits.UserPending = 1000
	anna, _ := newTestUser(t, n, "anna")
	boris, cb := newTestUser(t, n, "boris")
	login(t, cb, boris)
	env := sign(t, pb.RecordType_ENVELOPE, boris.id, &pb.Envelope{SenderUser: boris.id, SenderDevice: 1, Kind: pb.Envelope_SIGNAL,
		Recipients: []*pb.Recipient{{User: anna.id, Device: 1, Content: make([]byte, 2000)}}}, boris.priv)
	if st, msg := cb.call("msg.send", &pb.RecordRequest{Record: env}, nil); st != pb.Status_STATUS_QUOTA {
		t.Fatalf("over the quota: %v %s", st, msg)
	}
}
