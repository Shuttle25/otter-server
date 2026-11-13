package turnsrv

import (
	"errors"
	"math"
	"net"
	"sync"
	"time"

	"github.com/pion/turn/v5"
)

var (
	errNoTCPRelay  = errors.New("TCP relays are not offered")
	errOnlyIPv4    = errors.New("relays are IPv4 only")
	errPortOutside = errors.New("requested relay port outside the relay range")
)

// relayGen hands out UDP relay sockets from the configured port range, each wrapped with the rate cap and the
// own-port filter. TCP relays (RFC 6062) are refused: WebRTC never asks for them.
type relayGen struct {
	base        *turn.RelayAddressGeneratorPortRange
	own         []net.IP // the relay IP and every local interface address
	minPort     int
	maxPort     int
	bytesPerSec int
	stats       *Stats
	now         func() time.Time
}

func (g *relayGen) Validate() error { return g.base.Validate() }

func (g *relayGen) AllocatePacketConn(c turn.AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
	if c.Network != "udp4" {
		return nil, nil, errOnlyIPv4
	}
	// a RESERVATION-TOKEN carries a fixed port (EVEN-PORT reserves port+1): keep it inside the range
	if c.RequestedPort != 0 && (c.RequestedPort < g.minPort || c.RequestedPort > g.maxPort) {
		return nil, nil, errPortOutside
	}
	pc, addr, err := g.base.AllocatePacketConn(c)
	if err != nil {
		return nil, nil, err
	}
	return g.wrap(pc), addr, nil
}

func (g *relayGen) AllocateListener(turn.AllocateListenerConfig) (net.Listener, net.Addr, error) {
	return nil, nil, errNoTCPRelay
}

func (g *relayGen) AllocateConn(turn.AllocateConnConfig) (net.Conn, error) { return nil, errNoTCPRelay }

func (g *relayGen) wrap(pc net.PacketConn) net.PacketConn {
	return &limitedConn{PacketConn: pc, g: g, in: newBucket(g.bytesPerSec, g.bytesPerSec, g.now), out: newBucket(g.bytesPerSec, g.bytesPerSec, g.now)}
}

// blocked: anything that is not a UDP address, and the node's own addresses on a port that is not a relay port
// (its listeners, SSH, DNS, ...). Relay ports stay reachable so two phones on one node can talk.
func (g *relayGen) blocked(a net.Addr) bool {
	u, ok := a.(*net.UDPAddr)
	if !ok || u == nil {
		return true
	}
	if u.Port >= g.minPort && u.Port <= g.maxPort {
		return false
	}
	for _, ip := range g.own {
		if u.IP.Equal(ip) {
			return true
		}
	}
	return false
}

type limitedConn struct {
	net.PacketConn
	g       *relayGen
	in, out *bucket
}

func (c *limitedConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.g.blocked(addr) || !c.out.take(len(p)) {
		c.g.stats.Dropped.Add(1)
		return len(p), nil // UDP: a dropped packet is not an error
	}
	c.g.stats.Relayed.Add(int64(len(p)))
	return c.PacketConn.WriteTo(p, addr)
}

func (c *limitedConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		if c.in.take(n) {
			c.g.stats.Relayed.Add(int64(n))
			return n, addr, nil
		}
		c.g.stats.Dropped.Add(1)
	}
}

// bucket is a token bucket; the relay uses a one-second burst (burst = rate).
type bucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newBucket(perSec, burst int, now func() time.Time) *bucket {
	if now == nil {
		now = time.Now
	}
	return &bucket{rate: float64(perSec), burst: float64(burst), tokens: float64(burst), last: now(), now: now}
}

func (b *bucket) take(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.now()
	if d := t.Sub(b.last); d > 0 {
		b.tokens = math.Min(b.burst, b.tokens+d.Seconds()*b.rate)
	}
	b.last = t
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}
