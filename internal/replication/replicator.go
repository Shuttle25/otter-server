// Package replication keeps node oplogs in sync over authenticated peer sessions (docs/03).
package replication

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
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

	mu      sync.Mutex
	backoff map[string]time.Duration
	nextTry map[string]time.Time
}

func New(svc *service.Service, dialer Dialer, log *slog.Logger) *Replicator {
	r := &Replicator{svc: svc, st: svc.Store, dialer: dialer, log: log, ctx: context.Background(),
		reg: registry{byPeer: map[string]*session{}}, backoff: map[string]time.Duration{}, nextTry: map[string]time.Time{}}
	svc.OnManifest(func(m *pb.Manifest) { r.pruneSessions(m) })
	return r
}

func (r *Replicator) manifestVersion() uint64 {
	if m := r.svc.CurrentManifest(); m != nil {
		return m.Version
	}
	return 0
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
		_ = writeFrame(req.Context(), c, &pb.PeerFrame{Kind: &pb.PeerFrame_Error{Error: &pb.PeerError{Message: "handshake failed"}}})
		c.Close(websocket.StatusPolicyViolation, "handshake failed")
		return
	}
	r.runSession(c, peer, peer) // the remote side dialed
}

func (r *Replicator) runSession(c *websocket.Conn, peer, dialer []byte) {
	s := newSession(r, c, peer, dialer)
	if !r.reg.add(s) {
		c.Close(websocket.StatusNormalClosure, "duplicate session")
		return
	}
	defer r.reg.remove(s)
	r.log.Info("peer session up", "peer", fmt.Sprintf("%x", peer), "dialer", fmt.Sprintf("%x", dialer))
	err := s.run()
	r.log.Info("peer session down", "peer", fmt.Sprintf("%x", peer), "err", err)
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
	for _, n := range m.Nodes {
		if bytes.Equal(n.NodeId, r.svc.NodeID) || r.reg.has(n.NodeId) {
			continue
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
			c, err := r.dialer.Dial(ctx, n)
			if err != nil {
				r.log.Debug("peer dial failed", "peer", n.Label, "err", err)
				return
			}
			if err := r.dialHandshake(ctx, c, n); err != nil {
				r.log.Info("peer handshake failed", "peer", n.Label, "err", err)
				c.CloseNow()
				return
			}
			r.runSession(c, n.NodeId, r.svc.NodeID)
		}(n)
	}
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
