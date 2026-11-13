package turnsrv

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"

	"ottermsg/server/internal/netlog"
)

// Config of the embedded relay. All limits must be positive (config.validateTurn fills the defaults).
type Config struct {
	UDPListen, TCPListen, TLSListen string
	TLS                             *tls.Config // nil = no TLS listener
	RelayIP                         net.IP      // IPv4, written into relay addresses
	PortMin, PortMax                int         // UDP relay ports (inclusive)
	Secret                          []byte      // TURN-REST shared secret, SecretLen bytes
	Realm                           string
	MaxPerUser, MaxTotal            int // live allocations per TURN user / per node
	RelayKbps                       int // per allocation, each direction
	AllowPrivatePeers               bool
	Netlog                          netlog.Logger
	StatsFile                       string // "" = do not publish
	Log                             *slog.Logger

	// tests only
	now       func() time.Time // clock for the credential expiry check (pion keeps its own real-clock check)
	pionOut   io.Writer        // pion's log output (default stderr)
	pionLevel logging.LogLevel // default warn
}

type Server struct {
	srv   *turn.Server
	Stats *Stats
	stop  context.CancelFunc
	done  chan struct{}
	once  sync.Once
	err   error
}

// pendingTTL: a quota reservation that did not become an allocation (relay port busy, ...) lapses after this.
const pendingTTL = 5 * time.Second

// quota counts allocations per TURN user id and per node (pion has only a yes/no hook). A slot is reserved in the
// QuotaHandler and turned into a live allocation by OnAllocationCreated, so concurrent Allocate requests on
// different connections cannot overshoot the limits.
type quota struct {
	mu             sync.Mutex
	live           map[string]int
	pending        map[string][]time.Time
	total          int
	maxPer, maxAll int
	now            func() time.Time
}

func newQuota(maxPer, maxAll int, now func() time.Time) *quota {
	return &quota{live: map[string]int{}, pending: map[string][]time.Time{}, maxPer: maxPer, maxAll: maxAll, now: now}
}

// reserve takes a slot for u if both limits allow it.
func (q *quota) reserve(u string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()
	pendingAll := 0
	for k, ts := range q.pending {
		i := 0
		for i < len(ts) && now.Sub(ts[i]) > pendingTTL {
			i++
		}
		if i == len(ts) {
			delete(q.pending, k)
			continue
		}
		q.pending[k] = ts[i:]
		pendingAll += len(ts) - i
	}
	if q.live[u]+len(q.pending[u]) >= q.maxPer || q.total+pendingAll >= q.maxAll {
		return false
	}
	q.pending[u] = append(q.pending[u], now)
	return true
}

func (q *quota) created(u string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if ts := q.pending[u]; len(ts) > 1 {
		q.pending[u] = ts[1:]
	} else {
		delete(q.pending, u)
	}
	q.live[u]++
	q.total++
}

func (q *quota) deleted(u string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.live[u]--
	q.total--
	if q.live[u] <= 0 {
		delete(q.live, u)
	}
}

func (c *Config) check() error {
	switch {
	case len(c.Secret) != SecretLen:
		return errors.New("turn: secret must be 32 bytes")
	case c.RelayIP.To4() == nil:
		return errors.New("turn: relay_ip must be an IPv4 address")
	case c.PortMin < 1 || c.PortMax > 65535 || c.PortMin > c.PortMax:
		return fmt.Errorf("turn: relay ports %d-%d invalid", c.PortMin, c.PortMax)
	case c.MaxPerUser <= 0 || c.MaxTotal <= 0 || c.RelayKbps <= 0:
		return errors.New("turn: max_allocations_per_user, max_allocations and relay_kbps must be positive")
	}
	return nil
}

// ownIPs: the relay IP and every address of the node's interfaces.
func ownIPs(relay net.IP) []net.IP {
	own := []net.IP{relay}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			own = append(own, n.IP)
		}
	}
	return own
}

// Start listens on UDP, TCP and (with cfg.TLS) TLS and relays UDP for authenticated users. Nothing secret (the
// secret, passwords, keys, account ids) is logged; TURN user names carry only an expiry and a hash tag.
func Start(cfg Config) (*Server, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Netlog == nil {
		cfg.Netlog = netlog.Nop{}
	}
	if cfg.Realm == "" {
		cfg.Realm = "otter"
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	if cfg.pionLevel == logging.LogLevelDisabled {
		cfg.pionLevel = logging.LogLevelWarn
	}
	s := &Server{Stats: &Stats{}, done: make(chan struct{})}
	q := newQuota(cfg.MaxPerUser, cfg.MaxTotal, cfg.now)
	// at most 20 lines at once, then one per second: a login flood must not turn into a database write flood
	nlLimit := newBucket(1, 20, cfg.now)
	nl := func(src net.Addr, c netlog.Class, detail string) {
		if !nlLimit.take(1) {
			return
		}
		ep := "turn"
		if src != nil {
			ep += ":" + src.Network()
		}
		cfg.Netlog.Add(context.Background(), netlog.Entry{Peer: "turn", Endpoint: ep, Direction: "in",
			Result: netlog.Result(c), Class: c, Detail: detail})
	}
	gen := &relayGen{
		base: &turn.RelayAddressGeneratorPortRange{RelayAddress: cfg.RelayIP.To4(), Address: "0.0.0.0",
			MinPort: uint16(cfg.PortMin), MaxPort: uint16(cfg.PortMax)},
		own: ownIPs(cfg.RelayIP), minPort: cfg.PortMin, maxPort: cfg.PortMax,
		bytesPerSec: cfg.RelayKbps * 1000 / 8, stats: s.Stats,
	}
	perm := func(_ net.Addr, ip net.IP) bool { return peerAllowed(ip, cfg.AllowPrivatePeers) }

	var closers []io.Closer
	fail := func(err error) (*Server, error) {
		for _, c := range closers {
			_ = c.Close()
		}
		return nil, err
	}
	udp, err := net.ListenPacket("udp4", cfg.UDPListen)
	if err != nil {
		return fail(err)
	}
	closers = append(closers, udp)
	tcp, err := net.Listen("tcp4", cfg.TCPListen)
	if err != nil {
		return fail(err)
	}
	closers = append(closers, tcp)
	lns := []turn.ListenerConfig{{Listener: tcp, RelayAddressGenerator: gen, PermissionHandler: perm}}
	if cfg.TLS != nil && cfg.TLSListen != "" {
		tl, err := tls.Listen("tcp4", cfg.TLSListen, cfg.TLS)
		if err != nil {
			return fail(err)
		}
		closers = append(closers, tl)
		lns = append(lns, turn.ListenerConfig{Listener: tl, RelayAddressGenerator: gen, PermissionHandler: perm})
	}

	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = cfg.pionLevel
	if cfg.pionOut != nil {
		lf.Writer = cfg.pionOut
	}
	// pion's TURN-REST handler logs every refused user name; keep it silent (failures go to netlog).
	quiet := logging.NewDefaultLoggerFactory()
	quiet.DefaultLogLevel = logging.LogLevelDisabled
	rest := turn.LongTermTURNRESTAuthHandler(string(cfg.Secret), quiet.NewLogger("turn-auth"))
	// Runs for every authenticated request (Allocate, Refresh, CreatePermission, ChannelBind), so credentials
	// that expire during a call stop working on the next refresh.
	auth := func(ra *turn.RequestAttributes) (string, []byte, bool) {
		if expired(ra.Username, cfg.now()) {
			nl(ra.SrcAddr, netlog.Auth, "expired or malformed credentials")
			return "", nil, false
		}
		return rest(ra)
	}

	srv, err := turn.NewServer(turn.ServerConfig{
		Realm:         cfg.Realm,
		LoggerFactory: lf,
		AuthHandler:   auth,
		QuotaHandler: func(userID, _ string, src net.Addr) bool {
			if q.reserve(userID) {
				return true
			}
			nl(src, netlog.Quota, "allocation quota reached")
			return false
		},
		EventHandler: turn.EventHandler{
			// verdict false: the HMAC did not match (wrong password or another node's secret)
			OnAuth: func(src, _ net.Addr, _, username, _, _ string, verdict bool) {
				if !verdict && username != "" {
					nl(src, netlog.Auth, "bad credentials")
				}
			},
			OnAllocationCreated: func(_, _ net.Addr, _, userID, _ string, _ net.Addr, _ int) {
				q.created(userID)
				s.Stats.Allocations.Add(1)
			},
			OnAllocationDeleted: func(_, _ net.Addr, _, userID, _ string) {
				q.deleted(userID)
				s.Stats.Allocations.Add(-1)
			},
		},
		PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: udp, RelayAddressGenerator: gen, PermissionHandler: perm}},
		ListenerConfigs:   lns,
	})
	if err != nil {
		return fail(err)
	}
	s.srv = srv
	ctx, cancel := context.WithCancel(context.Background())
	s.stop = cancel
	go func() {
		defer close(s.done)
		if cfg.StatsFile == "" {
			<-ctx.Done()
			return
		}
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			if err := s.Stats.WriteFile(cfg.StatsFile, time.Now()); err != nil {
				cfg.Log.Warn("turn stats", "err", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	cfg.Log.Info("turn on", "udp", cfg.UDPListen, "tcp", cfg.TCPListen, "tls", cfg.TLSListen,
		"relay", cfg.RelayIP.String(), "ports", fmt.Sprintf("%d-%d", cfg.PortMin, cfg.PortMax))
	return s, nil
}

// Close stops the server and releases every port; pion's Close closes the listeners it was given and every relay
// socket. Safe to call more than once.
func (s *Server) Close() error {
	s.once.Do(func() {
		s.stop()
		<-s.done
		err := s.srv.Close()
		if errors.Is(err, net.ErrClosed) {
			err = nil
		}
		s.err = err
	})
	return s.err
}
