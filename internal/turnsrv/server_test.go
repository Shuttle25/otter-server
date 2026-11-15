package turnsrv

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"

	"ottermsg/server/internal/netlog"
)

type memLog struct {
	mu sync.Mutex
	e  []netlog.Entry
}

func (m *memLog) Add(_ context.Context, e netlog.Entry) {
	m.mu.Lock()
	m.e = append(m.e, e)
	m.mu.Unlock()
}

func (m *memLog) count(c netlog.Class) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, e := range m.e {
		if e.Class == c && e.Peer == "turn" && e.Direction == "in" && e.Result == "fail" {
			n++
		}
	}
	return n
}

func (m *memLog) String() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var b strings.Builder
	for _, e := range m.e {
		b.WriteString(e.Peer + " " + e.Endpoint + " " + e.Direction + " " + e.Result + " " + string(e.Class) + " " + e.Detail + "\n")
	}
	return b.String()
}

// syncBuf collects log output written from several goroutines.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func freeUDPPort(t *testing.T) int {
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func testConfig(secret []byte, maxPer, maxAll int, nl netlog.Logger) Config {
	return Config{RelayIP: net.IPv4(127, 0, 0, 1), PortMin: 32100, PortMax: 32140, Secret: secret, Realm: "otter",
		MaxPerUser: maxPer, MaxTotal: maxAll, RelayKbps: 2000, AllowPrivatePeers: true, Netlog: nl,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), pionOut: io.Discard}
}

// startCfg starts cfg on a free loopback port (UDP and TCP on the same number, as in production).
func startCfg(t *testing.T, cfg Config) (*Server, string) {
	t.Helper()
	var err error
	for range 5 {
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(freeUDPPort(t)))
		cfg.UDPListen, cfg.TCPListen = addr, addr
		var s *Server
		if s, err = Start(cfg); err == nil {
			t.Cleanup(func() { s.Close() })
			return s, addr
		}
	}
	t.Fatal(err)
	return nil, ""
}

func startTest(t *testing.T, secret []byte, maxPer int, nl netlog.Logger) (*Server, string) {
	return startCfg(t, testConfig(secret, maxPer, 41, nl))
}

func client(t *testing.T, server, user, pass string) *turn.Client {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = logging.LogLevelDisabled
	c, err := turn.NewClient(&turn.ClientConfig{STUNServerAddr: server, TURNServerAddr: server, Conn: conn,
		Username: user, Password: pass, Realm: "otter", RTO: 100 * time.Millisecond, LoggerFactory: lf})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Listen(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); conn.Close() })
	return c
}

// waitFor polls cond (netlog lines and counters are written from pion's goroutines).
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal(what)
}

func TestRelayBetweenTwoAllocations(t *testing.T) {
	secret := bytes.Repeat([]byte{3}, SecretLen)
	s, addr := startTest(t, secret, 4, netlog.Nop{})
	ua, pa := Credentials(secret, []byte("anna-00000000000"), time.Now(), time.Hour)
	ub, pb := Credentials(secret, []byte("boris-0000000000"), time.Now(), time.Hour)
	ra, err := client(t, addr, ua, pa).Allocate()
	if err != nil {
		t.Fatal(err)
	}
	rb, err := client(t, addr, ub, pb).Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if p := ra.LocalAddr().(*net.UDPAddr).Port; p < 32100 || p > 32140 {
		t.Fatalf("relay port %d outside the range", p)
	}
	rb.WriteTo([]byte("hi"), ra.LocalAddr()) // creates b's permission for a
	if _, err := ra.WriteTo([]byte("hello"), rb.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	rb.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := rb.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("relayed %q %v", buf[:n], err)
	}
	if s.Stats.Allocations.Load() != 2 || s.Stats.Relayed.Load() == 0 {
		t.Fatalf("stats %+v", s.Stats.Snapshot(time.Now()))
	}
}

func TestQuotaAndWrongSecret(t *testing.T) {
	secret := bytes.Repeat([]byte{4}, SecretLen)
	nl := &memLog{}
	s, addr := startTest(t, secret, 1, nl)
	u, p := Credentials(secret, []byte("anna-00000000000"), time.Now(), time.Hour)
	ra, err := client(t, addr, u, p).Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client(t, addr, u, p).Allocate(); err == nil {
		t.Fatal("second allocation of the same user must hit the quota")
	}
	waitFor(t, "quota netlog line", func() bool { return nl.count(netlog.Quota) == 1 })
	// another user is not affected by anna's quota
	ub, pb := Credentials(secret, []byte("boris-0000000000"), time.Now(), time.Hour)
	if _, err := client(t, addr, ub, pb).Allocate(); err != nil {
		t.Fatal(err)
	}
	wu, wp := Credentials(bytes.Repeat([]byte{5}, SecretLen), []byte("eve-000000000000"), time.Now(), time.Hour)
	if _, err := client(t, addr, wu, wp).Allocate(); err == nil {
		t.Fatal("other node's credentials accepted")
	}
	waitFor(t, "auth netlog line", func() bool { return nl.count(netlog.Auth) == 1 })
	if _, err := client(t, addr, u, "AAAA"+p[4:]).Allocate(); err == nil {
		t.Fatal("wrong password accepted")
	}
	waitFor(t, "auth netlog line", func() bool { return nl.count(netlog.Auth) == 2 })
	if s.Stats.Allocations.Load() != 2 {
		t.Fatalf("allocations %d", s.Stats.Allocations.Load())
	}
	// anna's allocation ends (Refresh with lifetime 0): her quota frees up
	ra.Close()
	waitFor(t, "allocation deleted", func() bool { return s.Stats.Allocations.Load() == 1 })
	if _, err := client(t, addr, u, p).Allocate(); err != nil {
		t.Fatalf("quota not released: %v", err)
	}
	if nl.count(netlog.Quota) != 1 || nl.count(netlog.Auth) != 2 {
		t.Fatalf("netlog:\n%s", nl)
	}
}

func TestNodeCap(t *testing.T) {
	secret := bytes.Repeat([]byte{6}, SecretLen)
	nl := &memLog{}
	_, addr := startCfg(t, testConfig(secret, 4, 2, nl))
	for i := range 3 {
		u, p := Credentials(secret, []byte{byte(i)}, time.Now(), time.Hour)
		_, err := client(t, addr, u, p).Allocate()
		if i < 2 && err != nil {
			t.Fatal(err)
		}
		if i == 2 && err == nil {
			t.Fatal("allocation above max_allocations")
		}
	}
	waitFor(t, "quota netlog line", func() bool { return nl.count(netlog.Quota) == 1 })
}

func TestExpiryCheckedOnEveryRequest(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, SecretLen)
	nl := &memLog{}
	clk := &clock{t: time.Now()}
	cfg := testConfig(secret, 4, 41, nl)
	cfg.now = clk.now
	_, addr := startCfg(t, cfg)
	u, p := Credentials(secret, []byte("anna-00000000000"), clk.now(), time.Hour)
	c := client(t, addr, u, p)
	if _, err := c.Allocate(); err != nil {
		t.Fatal(err)
	}
	if err := c.CreatePermission(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); err != nil {
		t.Fatal(err)
	}
	clk.add(2 * time.Hour) // the credentials expire while the allocation lives
	if err := c.CreatePermission(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10}); err == nil {
		t.Fatal("expired credentials accepted on an existing allocation")
	}
	waitFor(t, "auth netlog line", func() bool { return nl.count(netlog.Auth) == 1 })
	old, op := Credentials(secret, []byte("boris-0000000000"), clk.now().Add(-time.Hour), time.Minute)
	if _, err := client(t, addr, old, op).Allocate(); err == nil {
		t.Fatal("expired credentials allocated")
	}
	waitFor(t, "auth netlog line", func() bool { return nl.count(netlog.Auth) == 2 })
}

func TestPeerDenyList(t *testing.T) {
	secret := bytes.Repeat([]byte{8}, SecretLen)
	cfg := testConfig(secret, 4, 41, netlog.Nop{})
	cfg.AllowPrivatePeers = false
	_, addr := startCfg(t, cfg)
	u, p := Credentials(secret, []byte("anna-00000000000"), time.Now(), time.Hour)
	c := client(t, addr, u, p)
	if _, err := c.Allocate(); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(10, 0, 0, 1), net.IPv4(169, 254, 169, 254), net.IPv4(192, 168, 0, 1)} {
		if err := c.CreatePermission(&net.UDPAddr{IP: ip, Port: 9}); err == nil {
			t.Fatalf("permission to %s granted", ip)
		}
	}
	if err := c.CreatePermission(&net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 9}); err != nil {
		t.Fatalf("public peer refused: %v", err)
	}
}

func TestTCPAllocationRefused(t *testing.T) {
	secret := bytes.Repeat([]byte{9}, SecretLen)
	s, addr := startTest(t, secret, 4, netlog.Nop{})
	u, p := Credentials(secret, []byte("anna-00000000000"), time.Now(), time.Hour)
	// RFC 6062 runs over a TCP control connection
	tc, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = logging.LogLevelDisabled
	c, err := turn.NewClient(&turn.ClientConfig{STUNServerAddr: addr, TURNServerAddr: addr, Conn: turn.NewSTUNConn(tc),
		Username: u, Password: p, Realm: "otter", RTO: 100 * time.Millisecond, LoggerFactory: lf})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Listen(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); tc.Close() })
	if _, err := c.AllocateTCP(); err == nil {
		t.Fatal("RFC 6062 TCP allocation granted")
	}
	// the same TCP control connection gets an ordinary UDP relay (TURN over TCP for phones behind UDP blocks)
	if _, err := c.Allocate(); err != nil {
		t.Fatalf("UDP relay over a TCP control connection: %v", err)
	}
	if s.Stats.Allocations.Load() != 1 {
		t.Fatalf("allocations %d", s.Stats.Allocations.Load())
	}
}

func TestQuotaReservations(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0)}
	q := newQuota(1, 2, clk.now)
	// two Allocate requests in flight at once: only one may pass, though neither allocation exists yet
	if !q.reserve("a") || q.reserve("a") {
		t.Fatal("per-user reservation")
	}
	if !q.reserve("b") || q.reserve("c") {
		t.Fatal("per-node reservation")
	}
	q.created("a")
	if q.reserve("a") {
		t.Fatal("live allocation not counted")
	}
	clk.add(pendingTTL + time.Second) // b's allocation never came: its slot lapses
	if !q.reserve("c") {
		t.Fatal("stale reservation kept")
	}
	q.deleted("a")
	if !q.reserve("a") {
		t.Fatal("deleted allocation still counted")
	}
}

func TestNothingSecretLogged(t *testing.T) {
	secret := bytes.Repeat([]byte{0xa5}, SecretLen)
	nl := &memLog{}
	out := &syncBuf{}
	cfg := testConfig(secret, 1, 41, nl)
	cfg.Log = slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg.pionOut = out
	cfg.pionLevel = logging.LogLevelTrace
	s, addr := startCfg(t, cfg)
	u, p := Credentials(secret, []byte("anna-00000000000"), time.Now(), time.Hour)
	if _, err := client(t, addr, u, p).Allocate(); err != nil {
		t.Fatal(err)
	}
	client(t, addr, u, p).Allocate()            // quota
	client(t, addr, u, "AAAA"+p[4:]).Allocate() // bad password
	old, op := Credentials(secret, []byte("anna-00000000000"), time.Now().Add(-2*time.Hour), time.Hour)
	client(t, addr, old, op).Allocate() // expired
	waitFor(t, "netlog lines", func() bool { return nl.count(netlog.Auth) == 2 && nl.count(netlog.Quota) == 1 })
	s.Close()
	all := out.String() + nl.String()
	for _, sec := range []string{p, op, string(secret), hex.EncodeToString(secret), base64.StdEncoding.EncodeToString(secret),
		"anna-00000000000", hex.EncodeToString([]byte("anna-00000000000"))} {
		if strings.Contains(all, sec) {
			t.Fatalf("log contains a secret %q:\n%s", sec, all)
		}
	}
	if !strings.Contains(all, "turn on") {
		t.Fatalf("expected the start line in the log:\n%s", all)
	}
}

func TestCloseReleasesPorts(t *testing.T) {
	secret := bytes.Repeat([]byte{10}, SecretLen)
	cfg := testConfig(secret, 4, 41, netlog.Nop{})
	s, addr := startCfg(t, cfg)
	u, p := Credentials(secret, []byte("anna-00000000000"), time.Now(), time.Hour)
	if _, err := client(t, addr, u, p).Allocate(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.UDPListen, cfg.TCPListen = addr, addr
	s2, err := Start(cfg)
	if err != nil {
		t.Fatalf("second start on %s: %v", addr, err)
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}
	// every relay port is free again
	for port := 32100; port <= 32140; port++ {
		c, err := net.ListenPacket("udp4", "0.0.0.0:"+strconv.Itoa(port))
		if err != nil {
			t.Fatalf("relay port %d still in use: %v", port, err)
		}
		c.Close()
	}
}

func TestStartErrors(t *testing.T) {
	secret := bytes.Repeat([]byte{11}, SecretLen)
	busy, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	cfg := testConfig(secret, 4, 41, netlog.Nop{})
	cfg.UDPListen, cfg.TCPListen = busy.LocalAddr().String(), "127.0.0.1:0"
	if _, err := Start(cfg); err == nil {
		t.Fatal("start on a busy UDP port")
	}
	for name, mod := range map[string]func(*Config){
		"short secret": func(c *Config) { c.Secret = secret[:16] },
		"no relay ip":  func(c *Config) { c.RelayIP = nil },
		"ipv6 relay":   func(c *Config) { c.RelayIP = net.ParseIP("2001:db8::1") },
		"ports":        func(c *Config) { c.PortMin, c.PortMax = 32140, 32100 },
		"no rate":      func(c *Config) { c.RelayKbps = 0 },
		"no per user":  func(c *Config) { c.MaxPerUser = 0 },
		"no total":     func(c *Config) { c.MaxTotal = 0 },
	} {
		c := testConfig(secret, 4, 41, netlog.Nop{})
		c.UDPListen, c.TCPListen = "127.0.0.1:0", "127.0.0.1:0"
		mod(&c)
		if s, err := Start(c); err == nil {
			s.Close()
			t.Errorf("%s: started", name)
		}
	}
}

func TestRefusedUserCannotAllocate(t *testing.T) {
	secret := bytes.Repeat([]byte{6}, SecretLen)
	nl := &memLog{}
	cfg := testConfig(secret, 4, 41, nl)
	revoked := UserTag([]byte("boris-0000000000"))
	cfg.Refuse = func(tag string) bool { return tag == revoked }
	_, addr := startCfg(t, cfg)
	u, p := Credentials(secret, []byte("boris-0000000000"), time.Now(), time.Hour)
	if _, err := client(t, addr, u, p).Allocate(); err == nil {
		t.Fatal("revoked user allocated")
	}
	waitFor(t, "auth netlog line", func() bool { return nl.count(netlog.Auth) == 1 })
	ua, pa := Credentials(secret, []byte("anna-00000000000"), time.Now(), time.Hour)
	if _, err := client(t, addr, ua, pa).Allocate(); err != nil {
		t.Fatal(err)
	}
}
