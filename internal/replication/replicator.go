// Package replication keeps node oplogs in sync over authenticated peer sessions (docs/03).
package replication

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"ottermsg/server/internal/netlog"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/service"
	"ottermsg/server/internal/store"
)

type Replicator struct {
	svc    *service.Service
	st     *store.Store
	dialer Dialer
	log    *slog.Logger
	ctx    context.Context
	reg    registry
	last   lastPeers
	rank   *Ranker
	nlog   netlog.Logger

	mu      sync.Mutex
	backoff map[string]time.Duration
	nextTry map[string]time.Time

	seenMu sync.Mutex
	seen   map[string]*peerSeen // per peer node id: monitoring state that outlives sessions (D130; M9.4 monitoring reads it)
}

// peerSeen is what monitoring needs to know about a peer across sessions.
type peerSeen struct {
	pingFails int64
}

func (r *Replicator) peer(id []byte) *peerSeen { // callers hold seenMu
	if r.seen == nil {
		r.seen = map[string]*peerSeen{}
	}
	p := r.seen[string(id)]
	if p == nil {
		p = &peerSeen{}
		r.seen[string(id)] = p
	}
	return p
}

func (r *Replicator) notePingFail(id []byte) {
	r.seenMu.Lock()
	r.peer(id).pingFails++
	r.seenMu.Unlock()
}

// Option configures a Replicator.
type Option func(*Replicator)

// WithNetlog sets the connectivity log and the ranker shared with a MultiDialer (D74).
func WithNetlog(l netlog.Logger, rank *Ranker) Option {
	return func(r *Replicator) { r.nlog, r.rank = l, rank }
}

func New(svc *service.Service, dialer Dialer, log *slog.Logger, opts ...Option) *Replicator {
	r := &Replicator{svc: svc, st: svc.Store, dialer: dialer, log: log, ctx: context.Background(),
		reg: registry{byPeer: map[string]*session{}}, backoff: map[string]time.Duration{}, nextTry: map[string]time.Time{},
		rank: NewRanker(time.Now), nlog: netlog.Nop{}}
	for _, o := range opts {
		o(r)
	}
	svc.OnManifest(func(m *pb.Manifest) { r.pruneSessions(m) })
	return r
}

func (r *Replicator) manifestVersion() uint64 {
	if m := r.svc.CurrentManifest(); m != nil {
		return m.Version
	}
	return 0
}

type listenerKey struct{}

// WithListener tags requests served by one listener ("wss", "reality") for the inbound log.
func WithListener(h http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), listenerKey{}, name)))
	})
}

func listenerName(req *http.Request) string {
	if s, ok := req.Context().Value(listenerKey{}).(string); ok {
		return s
	}
	return "wss"
}

// labelOf is the manifest label of node id, or its hex id.
func (r *Replicator) labelOf(id []byte) string {
	if m := r.svc.CurrentManifest(); m != nil {
		for _, n := range m.Nodes {
			if bytes.Equal(n.NodeId, id) && n.Label != "" {
				return n.Label
			}
		}
	}
	return fmt.Sprintf("%x", id)
}

// ServeHTTP accepts peer connections on <path>/peer.
func (r *Replicator) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	c, err := websocket.Accept(w, req, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	c.SetReadLimit(maxFrame)
	peer, err := r.acceptHandshake(req.Context(), c)
	if err != nil {
		r.log.Info("peer rejected", "remote", req.RemoteAddr, "err", err)
		host, _, herr := net.SplitHostPort(req.RemoteAddr)
		if herr != nil {
			host = req.RemoteAddr
		}
		r.nlog.Add(req.Context(), netlog.Entry{Peer: host, Endpoint: listenerName(req), Direction: "in", Result: "fail",
			Class: netlog.Handshake, Detail: err.Error()})
		_ = writeFrame(req.Context(), c, &pb.PeerFrame{Kind: &pb.PeerFrame_Error{Error: &pb.PeerError{Message: "handshake failed"}}})
		c.Close(websocket.StatusPolicyViolation, "handshake failed")
		return
	}
	r.nlog.Add(req.Context(), netlog.Entry{Peer: r.labelOf(peer), Endpoint: listenerName(req), Direction: "in", Result: "ok", Class: netlog.OK})
	r.runSession(c, peer, peer, nil) // the remote side dialed
}

// throttleSession: an outbound session dropped this soon after receiving ≥ 1 KB counts as throttling (D73).
const throttleSession = 2 * time.Minute

// runSession serves one authenticated session; ep is the endpoint we dialed (nil for inbound sessions).
func (r *Replicator) runSession(c *websocket.Conn, peer, dialer []byte, ep *pb.Endpoint) {
	s := newSession(r, c, peer, dialer)
	if !r.reg.add(s) {
		c.Close(websocket.StatusNormalClosure, "duplicate session")
		return
	}
	defer r.reg.remove(s)
	r.log.Info("peer session up", "peer", fmt.Sprintf("%x", peer), "dialer", fmt.Sprintf("%x", dialer))
	err := s.run()
	r.log.Info("peer session down", "peer", fmt.Sprintf("%x", peer), "err", err)
	if ep != nil && err != nil && r.baseCtx().Err() == nil {
		in, dur := s.bytesIn.Load(), time.Since(s.start)
		frozen := s.pingFailed.Load() // D130: a freeze can start at any time, even after a long transfer
		if frozen || (dur < throttleSession && in >= netlog.ThrottleBytes) {
			r.rank.Done(ep, netlog.ResetAfterKB)
			detail := fmt.Sprintf("%d bytes in %s: %v", in, dur.Round(time.Second), err)
			if frozen {
				detail = fmt.Sprintf("frozen: no pong within %s, %d bytes in %s", peerPingTimeout, in, dur.Round(time.Second))
			}
			r.nlog.Add(r.baseCtx(), netlog.Entry{Peer: r.labelOf(peer), Endpoint: EndpointName(ep), Direction: "out",
				Result: "fail", Class: netlog.ResetAfterKB, Detail: detail})
		}
	}
	r.mu.Lock()
	k := string(peer)
	if time.Since(s.start) >= stableSession {
		r.backoff[k] = 0
	}
	if errors.Is(err, service.ErrRetryLater) {
		r.nextTry[k] = time.Now().Add(retryLaterDelay)
	}
	r.mu.Unlock()
}

// Timings (package-level so tests can shorten them with SetTestTimings before starting nodes).
var (
	dialEvery       = 5 * time.Second
	minBackoff      = 5 * time.Second
	maxBackoff      = 5 * time.Minute
	retryLaterDelay = 30 * time.Second
	stableSession   = time.Minute
)

// SetTestTimings shortens dialing intervals for tests. Call before any replicator starts.
func SetTestTimings(dial, backoff time.Duration) {
	dialEvery, minBackoff, retryLaterDelay = dial, backoff, backoff
	maxBackoff = 10 * backoff
	pullRetryMin, pullRetryMax, pullIdle = backoff, 10*backoff, 10*backoff
	peerPing, peerPingTimeout = 2*dial, 5*dial
	handshakeTimeout = 5 * dial
}

func (r *Replicator) baseCtx() context.Context { r.mu.Lock(); defer r.mu.Unlock(); return r.ctx }

// Run keeps sessions to all manifest peers until ctx ends.
func (r *Replicator) Run(ctx context.Context) {
	r.mu.Lock()
	r.ctx = ctx
	r.mu.Unlock()
	t := time.NewTicker(dialEvery)
	defer t.Stop()
	for {
		r.dialMissing(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (r *Replicator) dialMissing(ctx context.Context) {
	m := r.svc.CurrentManifest()
	if m == nil {
		return
	}
	selfOut := r.selfDialOutOnly(m)
	for _, n := range m.Nodes {
		if bytes.Equal(n.NodeId, r.svc.NodeID) || r.reg.has(n.NodeId) {
			continue
		}
		if n.DialOutOnly && !selfOut {
			continue // D71: a node inside a censored network dials us, never the other way round
		}
		k := string(n.NodeId)
		r.mu.Lock()
		due := time.Now().After(r.nextTry[k])
		if due {
			b := r.backoff[k]
			b = min(max(b*2, minBackoff), maxBackoff)
			r.backoff[k] = b
			r.nextTry[k] = time.Now().Add(b)
		}
		r.mu.Unlock()
		if !due {
			continue
		}
		go func(n *pb.NodeInfo) {
			var c *websocket.Conn
			var ep *pb.Endpoint
			var err error
			if md, ok := r.dialer.(*MultiDialer); ok {
				c, ep, err = md.DialWith(ctx, n)
			} else {
				c, err = r.dialer.Dial(ctx, n)
			}
			if err != nil {
				r.log.Debug("peer dial failed", "peer", n.Label, "err", err)
				return
			}
			if err := r.dialHandshake(ctx, c, n); err != nil {
				r.log.Info("peer handshake failed", "peer", n.Label, "err", err)
				c.CloseNow()
				if ctx.Err() == nil {
					// the transport attempt was already logged as ok; the endpoint is now ranked failed (D130)
					if ep != nil {
						r.rank.Done(ep, netlog.Handshake) // D130: the transport opened but froze or failed; try the next endpoint first
					}
					err = fmt.Errorf("%w: %v", netlog.ErrHandshake, err)
					r.nlog.Add(ctx, netlog.Entry{Peer: n.Label, Endpoint: "handshake", Direction: "out", Result: "fail",
						Class: netlog.Classify(err, 0), Detail: err.Error()})
				}
				return
			}
			r.runSession(c, n.NodeId, r.svc.NodeID, ep)
		}(n)
	}
}

// selfDialOutOnly reports whether this node is itself dial-out-only; two such nodes may still dial each other.
func (r *Replicator) selfDialOutOnly(m *pb.Manifest) bool {
	for _, n := range m.Nodes {
		if bytes.Equal(n.NodeId, r.svc.NodeID) {
			return n.DialOutOnly
		}
	}
	return false
}

func (r *Replicator) pruneSessions(m *pb.Manifest) {
	keep := map[string]bool{}
	for _, n := range m.Nodes {
		keep[string(n.NodeId)] = true
	}
	r.reg.mu.Lock()
	defer r.reg.mu.Unlock()
	for k, s := range r.reg.byPeer {
		if !keep[k] {
			s.close()
		}
	}
}

type PeerStatus struct {
	Node      []byte
	Connected bool
	CaughtUp  bool
	Cursor    int64
}

func (r *Replicator) Status() []PeerStatus {
	m := r.svc.CurrentManifest()
	if m == nil {
		return nil
	}
	var out []PeerStatus
	for _, n := range m.Nodes {
		if bytes.Equal(n.NodeId, r.svc.NodeID) {
			continue
		}
		ps := PeerStatus{Node: n.NodeId}
		r.reg.mu.Lock()
		if s := r.reg.byPeer[string(n.NodeId)]; s != nil {
			s.mu.Lock()
			ps.Connected, ps.CaughtUp, ps.Cursor = true, s.caughtUp, s.cursor
			s.mu.Unlock()
		}
		r.reg.mu.Unlock()
		out = append(out, ps)
	}
	return out
}

// DropPeer closes the session with node id, if any (used to simulate a cut link; the next dial may reconnect).
func (r *Replicator) DropPeer(id []byte) {
	r.reg.mu.Lock()
	s := r.reg.byPeer[string(id)]
	r.reg.mu.Unlock()
	if s != nil {
		s.close()
	}
}
