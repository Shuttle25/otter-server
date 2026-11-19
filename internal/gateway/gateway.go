// Package gateway serves the client protocol (docs/02 §4) over WebSocket.
package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/limits"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/service"
)

const (
	ProtocolVersion   = 1
	maxFrame          = 1 << 20
	deliverBatch      = 100
	deliverBatchBytes = 768 << 10 // one envelopes event; phones refuse frames over 4 MiB (D93)
	writeTimeout      = 10 * time.Second
	// DefaultRequestsPerIP: requests per second of one source on client sessions, burst 10× (D116)
	DefaultRequestsPerIP = 50
)

type Gateway struct {
	// PingInterval/PingTimeout: server-side keep-alive. A phone's socket can die silently (half-open TCP) and would
	// count as online, so its pushes are skipped. Pongs are read by the session's read loop, which also reads large
	// frames (blob chunks); on a slow or throttled mobile link one chunk can take tens of seconds, so the timeout is
	// generous (60 s): a dead socket is dropped within ~90 s, a slow healthy one is never cut. Call pushes do not
	// depend on this (they ignore Online).
	PingInterval time.Duration
	PingTimeout  time.Duration

	// Limits (D116). IPRequests: all requests of a source (limits.Source: IPv4, IPv6 /64, or a relayed restore's
	// "tunnel:<node>"); IPPublic: the unauthenticated methods in publicLimited; UserWrites: write methods per
	// logged-in user (Task 63). Loopback (REALITY's inner listener) is exempt unless ExemptLoopback is false (tests).
	IPRequests, IPPublic, UserWrites *limits.Keyed
	Rejected                         *limits.Counters
	ExemptLoopback                   bool

	// Version is this node's release, told to logged-in members only in LoginResponse.server_version (M9.5, D139);
	// set by otter-node. Information only: a node can lie about it.
	Version string

	svc      *service.Service
	log      *slog.Logger
	mu       sync.Mutex
	sessions map[*session]struct{}
}

func New(svc *service.Service, log *slog.Logger) *Gateway {
	g := &Gateway{PingInterval: 30 * time.Second, PingTimeout: 60 * time.Second,
		IPRequests: limits.NewKeyed(DefaultRequestsPerIP, 10*DefaultRequestsPerIP), IPPublic: limits.NewKeyed(20.0/60, 20),
		UserWrites: limits.NewKeyed(1, 300), Rejected: &limits.Counters{}, ExemptLoopback: true,
		svc: svc, log: log, sessions: map[*session]struct{}{}}
	svc.Notify = g
	return g
}

func (g *Gateway) snapshot() []*session {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]*session, 0, len(g.sessions))
	for s := range g.sessions {
		out = append(out, s)
	}
	return out
}

// Sessions counts connected client sessions and the logged-in ones among them (monitoring, D119).
func (g *Gateway) Sessions() (all, loggedIn int) {
	for _, s := range g.snapshot() {
		all++
		if s.loggedIn() {
			loggedIn++
		}
	}
	return all, loggedIn
}

func (g *Gateway) add(s *session)    { g.mu.Lock(); g.sessions[s] = struct{}{}; g.mu.Unlock() }
func (g *Gateway) remove(s *session) { g.mu.Lock(); delete(g.sessions, s); g.mu.Unlock() }

// Envelope implements service.Notifier.
func (g *Gateway) Envelope(user []byte, device uint32) {
	for _, s := range g.snapshot() {
		if s.is(user, device) {
			s.kick()
		}
	}
}

// Online implements service.Notifier: a logged-in session of this (user, device) that was not replaced (D52/D56).
func (g *Gateway) Online(user []byte, device uint32) bool {
	for _, s := range g.snapshot() {
		if s.is(user, device) && !s.replaced() {
			return true
		}
	}
	return false
}

func (g *Gateway) Directory() {
	for _, s := range g.snapshot() {
		if s.loggedIn() {
			s.event("directory", &pb.Empty{})
		}
	}
}

func (g *Gateway) PrekeysLow(user []byte, device uint32, owner []byte, remaining int) {
	for _, s := range g.snapshot() {
		if s.is(user, device) {
			s.event("prekeys_low", &pb.PrekeysLow{Remaining: uint32(remaining), OwnerNode: owner})
		}
	}
}

// News implements service.Notifier: logged-in sessions re-fetch news.list (D67).
func (g *Gateway) News() {
	for _, s := range g.snapshot() {
		if s.loggedIn() {
			s.event("news", &pb.Empty{})
		}
	}
}

// Revoked implements service.Notifier: every session of the account ends at once (C2). Returns how many.
func (g *Gateway) Revoked(user []byte) int {
	n := 0
	for _, s := range g.snapshot() {
		if u := s.userID(); u != nil && bytes.Equal(u, user) {
			s.endRevoked()
			n++
		}
	}
	return n
}

// Manifest broadcasts the new manifest to every connected session (logged in or not).
func (g *Gateway) Manifest(version uint64) {
	rec, v, err := g.svc.Manifest(context.Background())
	if err != nil || v != version {
		return
	}
	for _, s := range g.snapshot() {
		s.event("manifest", &pb.ManifestResponse{Manifest: rec})
	}
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true}) // native clients send no Origin
	if err != nil {
		return
	}
	c.SetReadLimit(maxFrame)
	ctx, cancel := context.WithCancel(r.Context())
	nonce := make([]byte, 32)
	rand.Read(nonce)
	s := &session{g: g, conn: c, out: make(chan *pb.Frame, 64), wake: make(chan struct{}, 1), nonce: nonce, ctx: ctx, cancel: cancel,
		source:  service.SourceOf(r.RemoteAddr),
		blobSem: make(chan struct{}, 4)}
	if ip := limits.ClientIP(r); !(g.ExemptLoopback && limits.IsLoopback(ip)) {
		s.ip = ip
	}
	defer func() {
		cancel()
		g.remove(s)
		c.CloseNow()
	}()
	g.add(s) // every connected session receives manifest events
	go s.writeLoop()
	go s.keepalive(g.PingInterval, g.PingTimeout)

	var mv uint64
	if _, v, err := g.svc.Manifest(ctx); err == nil {
		mv = v
	}
	s.event("hello", &pb.Hello{ProtocolVersion: ProtocolVersion, NodeId: g.svc.NodeID, Nonce: nonce,
		ManifestVersion: mv, ServerTimeMs: time.Now().UnixMilli()})

	for {
		typ, data, err := c.Read(ctx)
		if err != nil {
			if !errors.Is(err, context.Canceled) && websocket.CloseStatus(err) == -1 {
				g.log.Debug("session read ended", "err", err)
			}
			return
		}
		if typ != websocket.MessageBinary {
			continue
		}
		var f pb.Frame
		if err := proto.Unmarshal(data, &f); err != nil {
			c.Close(websocket.StatusUnsupportedData, "bad frame")
			return
		}
		if req := f.GetRequest(); req != nil {
			if req.Method == "blob.get" {
				select {
				case s.blobSem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				go func() { defer func() { <-s.blobSem }(); s.handle(ctx, req) }()
				continue
			}
			s.handle(ctx, req)
		}
	}
}
