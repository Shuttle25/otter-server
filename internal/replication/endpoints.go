package replication

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"ottermsg/server/internal/netlog"
	pb "ottermsg/server/internal/proto/otterv1"
)

// EndpointDialer opens a peer WebSocket over one endpoint.
type EndpointDialer interface {
	DialEndpoint(ctx context.Context, n *pb.NodeInfo, ep *pb.Endpoint) (*websocket.Conn, error)
}

// EndpointName is the log/rank key: "reality:host:443", "wss:host:27443".
func EndpointName(ep *pb.Endpoint) string {
	return fmt.Sprintf("%s:%s:%d", strings.ToLower(ep.Kind.String()), ep.Host, ep.Port)
}

const (
	recentSuccess  = 7 * 24 * time.Hour
	recentFailure  = 10 * time.Minute
	throttleWindow = 24 * time.Hour
	throttleLimit  = 3
)

type epState struct {
	lastOK, lastFail time.Time
	throttles        []time.Time
	demotedUntil     time.Time
}

// Ranker orders a peer's endpoints from what worked recently (D73). In memory: a restart starts fresh.
type Ranker struct {
	now func() time.Time
	mu  sync.Mutex
	st  map[string]*epState
}

func NewRanker(now func() time.Time) *Ranker { return &Ranker{now: now, st: map[string]*epState{}} }

func (r *Ranker) state(ep *pb.Endpoint) *epState {
	k := EndpointName(ep)
	s := r.st[k]
	if s == nil {
		s = &epState{}
		r.st[k] = s
	}
	return s
}

// Done records an outcome for ep.
func (r *Ranker) Done(ep *pb.Endpoint, c netlog.Class) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, now := r.state(ep), r.now()
	switch c {
	case netlog.OK:
		s.lastOK = now
	case netlog.ResetAfterKB:
		s.lastFail = now
		keep := s.throttles[:0]
		for _, t := range s.throttles {
			if now.Sub(t) < throttleWindow {
				keep = append(keep, t)
			}
		}
		s.throttles = append(keep, now)
		if len(s.throttles) >= throttleLimit {
			s.demotedUntil = now.Add(throttleWindow)
		}
	default:
		s.lastFail = now
	}
}

// Order returns eps best first: recent success → priority/manifest order → recent failure → demoted.
func (r *Ranker) Order(eps []*pb.Endpoint) []*pb.Endpoint {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	type row struct {
		ep    *pb.Endpoint
		i     int
		group int
		ok    time.Time
	}
	rows := make([]row, len(eps))
	for i, ep := range eps {
		s := r.state(ep)
		g := 1
		switch {
		case now.Before(s.demotedUntil):
			g = 3
		case !s.lastFail.IsZero() && now.Sub(s.lastFail) < recentFailure && s.lastFail.After(s.lastOK):
			g = 2
		case !s.lastOK.IsZero() && now.Sub(s.lastOK) < recentSuccess:
			g = 0
		}
		rows[i] = row{ep, i, g, s.lastOK}
	}
	sort.SliceStable(rows, func(a, b int) bool {
		x, y := rows[a], rows[b]
		if x.group != y.group {
			return x.group < y.group
		}
		if x.group == 0 && !x.ok.Equal(y.ok) {
			return x.ok.After(y.ok)
		}
		if x.ep.Priority != y.ep.Priority {
			return x.ep.Priority < y.ep.Priority
		}
		return x.i < y.i
	})
	out := make([]*pb.Endpoint, len(rows))
	for i, x := range rows {
		out[i] = x.ep
	}
	return out
}

// MultiDialer implements Dialer over an EndpointDialer: ranked order, every attempt logged.
type MultiDialer struct {
	EP   EndpointDialer
	Rank *Ranker
	Log  netlog.Logger
}

func (d *MultiDialer) Dial(ctx context.Context, n *pb.NodeInfo) (*websocket.Conn, error) {
	c, _, err := d.DialWith(ctx, n)
	return c, err
}

// DialWith is Dial that also reports which endpoint connected.
func (d *MultiDialer) DialWith(ctx context.Context, n *pb.NodeInfo) (*websocket.Conn, *pb.Endpoint, error) {
	var lastErr error = errors.New("no usable endpoint")
	for _, ep := range d.Rank.Order(n.Endpoints) {
		c, err := d.EP.DialEndpoint(ctx, n, ep)
		if errors.Is(err, ErrUnsupported) {
			continue
		}
		if err != nil && ctx.Err() != nil {
			return nil, nil, err // shutting down: not an observation about the endpoint
		}
		cl := netlog.Classify(err, 0)
		d.Rank.Done(ep, cl)
		d.Log.Add(ctx, netlog.Entry{Peer: n.Label, Endpoint: EndpointName(ep), Direction: "out", Result: netlog.Result(cl), Class: cl, Detail: errText(err)})
		if err == nil {
			return c, ep, nil
		}
		lastErr = err
	}
	return nil, nil, lastErr
}

// ErrUnsupported: this dialer cannot use the endpoint kind (skipped silently, not logged).
var ErrUnsupported = errors.New("endpoint kind not supported here")

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
