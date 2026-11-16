package replication

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/service"
)

// Restore tunnel (D114). A node marked no_backups serves <path>/tunnel?to=<hex node id>: a WebSocket whose binary
// messages are the bytes of a phone's TLS stream to the target node. The bytes ride on the existing peer session with
// the target, whichever side dialed it (D132: a new connection from such a node abroad may freeze), and end inside
// the target's process in a TLS server with its WSS certificate. The relaying node sees only TLS records.
const (
	tunnelChunk       = 32 << 10 // max bytes per PeerTunnelData
	tunnelWindow      = 32       // unacknowledged data frames per stream and direction
	maxTunnelsPerPeer = 16
	maxTunnelsPerIP   = 4
	maxTunnels        = 32
)

var (
	tunnelIdle     = 2 * time.Minute
	tunnelLifetime = 30 * time.Minute
	tunnelOffer    = 5 * time.Second // how long a new stream waits for the TLS server to accept it
	tunnelTap      atomic.Pointer[func([]byte)]
	errTunnelBusy  = errors.New("too many tunnels")
)

// SetTunnelTap lets tests observe every byte a relaying node forwards. Never set in production.
func SetTunnelTap(f func([]byte)) {
	if f == nil {
		tunnelTap.Store(nil)
		return
	}
	tunnelTap.Store(&f)
}

type tunnel struct {
	id     uint64
	in     chan []byte // from the peer; an honest peer never has more than tunnelWindow queued
	credit atomic.Int64
	more   chan struct{}
	done   chan struct{}
	once   sync.Once
	why    atomic.Pointer[string]
}

func newTunnel(id uint64) *tunnel {
	t := &tunnel{id: id, in: make(chan []byte, tunnelWindow), more: make(chan struct{}, 1), done: make(chan struct{})}
	t.credit.Store(tunnelWindow)
	return t
}

func (t *tunnel) stop(why string) {
	t.once.Do(func() { t.why.Store(&why); close(t.done) })
}

func (t *tunnel) reason() string {
	if p := t.why.Load(); p != nil {
		return *p
	}
	return ""
}

// addCredit returns acknowledged slots; the window never grows above tunnelWindow (forged acks gain nothing).
func (t *tunnel) addCredit(n uint32) {
	for {
		c := t.credit.Load()
		v := min(c+int64(n), tunnelWindow)
		if t.credit.CompareAndSwap(c, v) {
			break
		}
	}
	select {
	case t.more <- struct{}{}:
	default:
	}
}

func tunnelClose(id uint64, why string) *pb.PeerFrame {
	return &pb.PeerFrame{Kind: &pb.PeerFrame_TunnelClose{TunnelClose: &pb.PeerTunnelClose{Stream: id, Reason: why}}}
}

func (s *session) addTunnel(id uint64) *tunnel {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	if s.tunnels[id] != nil || len(s.tunnels) >= maxTunnelsPerPeer {
		return nil
	}
	t := newTunnel(id)
	s.tunnels[id] = t
	return t
}

func (s *session) tunnelByID(id uint64) *tunnel {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	return s.tunnels[id]
}
func (s *session) dropTunnel(id uint64) { s.tmu.Lock(); delete(s.tunnels, id); s.tmu.Unlock() }

// onTunnelFrame runs on the session's read loop; it blocks at most on sending a refusal.
func (s *session) onTunnelFrame(f *pb.PeerFrame) {
	switch k := f.Kind.(type) {
	case *pb.PeerFrame_TunnelOpen:
		s.acceptTunnel(k.TunnelOpen.Stream)
	case *pb.PeerFrame_TunnelData:
		t := s.tunnelByID(k.TunnelData.Stream)
		if t == nil {
			return
		}
		if n := len(k.TunnelData.Data); n == 0 || n > tunnelChunk {
			t.stop("bad data frame")
			return
		}
		select {
		case t.in <- k.TunnelData.Data:
		default:
			t.stop("window exceeded") // the peer ignored the window
		}
	case *pb.PeerFrame_TunnelAck:
		if t := s.tunnelByID(k.TunnelAck.Stream); t != nil {
			t.addCredit(k.TunnelAck.Chunks)
		}
	case *pb.PeerFrame_TunnelClose:
		if t := s.tunnelByID(k.TunnelClose.Stream); t != nil {
			t.stop("peer closed: " + k.TunnelClose.Reason)
		}
	}
}

// openTunnel (relaying side) starts a stream to the peer's in-process TLS endpoint.
func (s *session) openTunnel() (*tunnel, error) {
	id := s.nextTunnel.Add(1)
	t := s.addTunnel(id)
	if t == nil {
		return nil, errTunnelBusy
	}
	s.send(&pb.PeerFrame{Kind: &pb.PeerFrame_TunnelOpen{TunnelOpen: &pb.PeerTunnelOpen{Stream: id}}})
	return t, nil
}

// acceptTunnel (target side): only a peer marked no_backups may open one, only when this node is not marked
// no_backups itself and serves the tunnel listener.
func (s *session) acceptTunnel(id uint64) {
	ln := s.r.tln.Load()
	why := ""
	switch {
	case ln == nil:
		why = "no tunnel endpoint"
	case !s.r.peerNoBackups(s.peer):
		why = "peer is not marked no_backups"
	case s.r.peerNoBackups(s.r.svc.NodeID):
		why = "this node is marked no_backups"
	}
	if why != "" {
		s.r.log.Info("tunnel refused", "peer", s.r.labelOf(s.peer), "stream", id, "reason", why)
		s.send(tunnelClose(id, why))
		return
	}
	t := s.addTunnel(id)
	if t == nil {
		s.r.log.Info("tunnel refused", "peer", s.r.labelOf(s.peer), "stream", id, "reason", "busy")
		s.send(tunnelClose(id, "busy"))
		return
	}
	a, b := net.Pipe()
	go func() {
		if !ln.offer(tunnelConn{Conn: a, from: "tunnel:" + hex.EncodeToString(s.peer)}) {
			a.Close()
		}
	}()
	go s.runTunnel(t, b, false)
}

// runTunnel copies c ↔ the peer stream until either side ends, it idles, or its lifetime passes; it closes c and
// tells the peer. tap: this node relays a phone's bytes (tests observe them).
func (s *session) runTunnel(t *tunnel, c net.Conn, tap bool) {
	ctx, cancel := context.WithTimeout(s.ctx, tunnelLifetime)
	start := time.Now()
	var up, down atomic.Int64 // bytes to / from the peer
	s.r.log.Info("tunnel open", "peer", s.r.labelOf(s.peer), "stream", t.id)
	defer func() {
		cancel()
		t.stop("")
		c.Close()
		s.dropTunnel(t.id)
		s.send(tunnelClose(t.id, ""))
		s.r.log.Info("tunnel closed", "peer", s.r.labelOf(s.peer), "stream", t.id, "reason", t.reason(),
			"bytes_out", up.Load(), "bytes_in", down.Load(), "dur", time.Since(start).Round(time.Second))
	}()
	observe := func(b []byte) {
		if tap {
			if f := tunnelTap.Load(); f != nil {
				(*f)(b)
			}
		}
	}
	go func() { // unblock c.Read on peer close, session end or lifetime
		select {
		case <-t.done:
		case <-ctx.Done():
			if s.ctx.Err() != nil {
				t.stop("peer session ended")
			} else {
				t.stop("lifetime")
			}
		}
		c.Close()
	}()
	go func() { // peer → c
		for {
			select {
			case b := <-t.in:
				observe(b)
				c.SetWriteDeadline(time.Now().Add(tunnelIdle))
				if _, err := c.Write(b); err != nil {
					t.stop("local write: " + err.Error())
					return
				}
				down.Add(int64(len(b)))
				s.send(&pb.PeerFrame{Kind: &pb.PeerFrame_TunnelAck{TunnelAck: &pb.PeerTunnelAck{Stream: t.id, Chunks: 1}}})
			case <-t.done:
				return
			}
		}
	}()
	buf := make([]byte, tunnelChunk)
	for { // c → peer
		for t.credit.Load() <= 0 {
			select {
			case <-t.more:
			case <-t.done:
				return
			case <-time.After(tunnelIdle):
				t.stop("peer stopped acknowledging")
				return
			}
		}
		c.SetReadDeadline(time.Now().Add(tunnelIdle))
		n, err := c.Read(buf)
		if n > 0 {
			observe(buf[:n])
			t.credit.Add(-1)
			up.Add(int64(n))
			s.send(&pb.PeerFrame{Kind: &pb.PeerFrame_TunnelData{TunnelData: &pb.PeerTunnelData{Stream: t.id, Data: bytes.Clone(buf[:n])}}})
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.stop("idle")
			} else {
				t.stop("")
			}
			return
		}
	}
}

type tunnelAddr string

func (a tunnelAddr) Network() string { return "tunnel" }
func (a tunnelAddr) String() string  { return string(a) }

// tunnelConn reports the relaying node as its remote address ("tunnel:<hex node id>"): until a PROXY header
// follow-up, every restore relayed by one node shares that node's restore-limit source (D105, owner answer).
type tunnelConn struct {
	net.Conn
	from string
}

func (c tunnelConn) RemoteAddr() net.Addr { return tunnelAddr(c.from) }

type tunnelListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *tunnelListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *tunnelListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *tunnelListener) Addr() net.Addr { return tunnelAddr("tunnel") }
func (l *tunnelListener) offer(c net.Conn) bool {
	t := time.NewTimer(tunnelOffer)
	defer t.Stop()
	select {
	case l.conns <- c:
		return true
	case <-l.done:
		return false
	case <-t.C:
		return false
	}
}

// TunnelListener yields restore streams relayed by peers marked no_backups. Serve it with tls.NewListener (the WSS
// certificate) and the client handler; until it is called, this node refuses tunnels.
func (r *Replicator) TunnelListener() net.Listener {
	l := &tunnelListener{conns: make(chan net.Conn), done: make(chan struct{})}
	if r.tln.CompareAndSwap(nil, l) {
		return l
	}
	return r.tln.Load()
}

type tunnelLimits struct {
	mu    sync.Mutex
	total int
	perIP map[string]int
}

func (l *tunnelLimits) acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.perIP == nil {
		l.perIP = map[string]int{}
	}
	if l.total >= maxTunnels || l.perIP[ip] >= maxTunnelsPerIP {
		return false
	}
	l.total++
	l.perIP[ip]++
	return true
}

func (l *tunnelLimits) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.perIP[ip]--; l.perIP[ip] <= 0 {
		delete(l.perIP, ip)
	}
}

// ServeTunnel serves <path>/tunnel?to=<hex node id> on a node marked no_backups (D114). The target must be another
// manifest node without no_backups with a live peer session; this node never dials for a tunnel.
func (r *Replicator) ServeTunnel(w http.ResponseWriter, req *http.Request) {
	m := r.svc.CurrentManifest()
	if m == nil || !service.NodeNoBackups(m, r.svc.NodeID) {
		http.NotFound(w, req)
		return
	}
	to, err := hex.DecodeString(req.URL.Query().Get("to"))
	var target *pb.NodeInfo
	if err == nil && len(to) > 0 && !bytes.Equal(to, r.svc.NodeID) {
		for _, n := range m.Nodes {
			if bytes.Equal(n.NodeId, to) {
				target = n
			}
		}
	}
	if target == nil || target.NoBackups {
		http.Error(w, "unknown node", http.StatusNotFound)
		return
	}
	s := r.reg.get(to)
	if s == nil {
		r.log.Info("tunnel refused", "peer", r.labelOf(to), "reason", "no peer session")
		http.Error(w, "node not connected", http.StatusServiceUnavailable)
		return
	}
	src := service.SourceOf(req.RemoteAddr) // IPv4 or IPv6 /64; never logged
	if !r.tlim.acquire(src) {
		r.log.Info("tunnel refused", "peer", r.labelOf(to), "reason", "too many tunnels")
		http.Error(w, "busy", http.StatusTooManyRequests)
		return
	}
	defer r.tlim.release(src)
	c, err := websocket.Accept(w, req, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	t, err := s.openTunnel()
	if err != nil {
		r.log.Info("tunnel refused", "peer", r.labelOf(to), "reason", err.Error())
		c.Close(websocket.StatusTryAgainLater, "busy")
		return
	}
	s.runTunnel(t, websocket.NetConn(s.ctx, c, websocket.MessageBinary), true)
}
