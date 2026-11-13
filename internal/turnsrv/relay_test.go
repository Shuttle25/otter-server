package turnsrv

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/turn/v5"
)

type fakePC struct {
	net.PacketConn
	mu     sync.Mutex
	writes [][]byte
	reads  chan []byte
}

func (f *fakePC) WriteTo(p []byte, _ net.Addr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (f *fakePC) ReadFrom(p []byte) (int, net.Addr, error) {
	b, ok := <-f.reads
	if !ok {
		return 0, nil, net.ErrClosed
	}
	return copy(p, b), &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 9}, nil
}

func (f *fakePC) n() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.writes) }

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func testGen(st *Stats, clk *clock) *relayGen {
	return &relayGen{own: []net.IP{net.IPv4(203, 0, 113, 7), net.IPv4(198, 51, 100, 3)}, minPort: 49160, maxPort: 49200,
		bytesPerSec: 1000, stats: st, now: clk.now}
}

func TestLimitedConnWrite(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0)}
	st := &Stats{}
	g := testGen(st, clk)
	f := &fakePC{reads: make(chan []byte, 4)}
	c := g.wrap(f)
	own := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 3478}
	ownSSH := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 3), Port: 22} // another address of the node
	peer := &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 9}
	relay := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 49170}
	c.WriteTo(make([]byte, 100), own)                       // own listener port: dropped
	c.WriteTo(make([]byte, 100), ownSSH)                    // other own address, not a relay port: dropped
	c.WriteTo(make([]byte, 100), &net.TCPAddr{IP: peer.IP}) // not UDP: dropped
	c.WriteTo(make([]byte, 100), relay)                     // own relay port: allowed (two phones on one node)
	c.WriteTo(make([]byte, 900), peer)                      // 1000 B budget now used up
	c.WriteTo(make([]byte, 10), peer)                       // over the cap: dropped
	if f.n() != 2 || st.Dropped.Load() != 4 || st.Relayed.Load() != 1000 {
		t.Fatalf("writes=%d dropped=%d relayed=%d", f.n(), st.Dropped.Load(), st.Relayed.Load())
	}
	clk.add(time.Second) // refill
	c.WriteTo(make([]byte, 500), peer)
	if f.n() != 3 {
		t.Fatal("bucket did not refill")
	}
	clk.add(time.Hour) // a long pause refills only one second of burst
	if _, err := c.WriteTo(make([]byte, 1001), peer); err != nil || f.n() != 3 {
		t.Fatal("burst must be capped at one second")
	}
}

func TestLimitedConnRead(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0)}
	st := &Stats{}
	f := &fakePC{reads: make(chan []byte, 4)}
	c := testGen(st, clk).wrap(f)
	f.reads <- make([]byte, 800)
	f.reads <- make([]byte, 800) // over the cap: dropped, the read waits for the next packet
	f.reads <- make([]byte, 100)
	buf := make([]byte, 2000)
	if n, _, err := c.ReadFrom(buf); err != nil || n != 800 {
		t.Fatal(n, err)
	}
	if n, _, err := c.ReadFrom(buf); err != nil || n != 100 {
		t.Fatal(n, err)
	}
	if st.Dropped.Load() != 1 || st.Relayed.Load() != 900 {
		t.Fatalf("dropped=%d relayed=%d", st.Dropped.Load(), st.Relayed.Load())
	}
	close(f.reads)
	if _, _, err := c.ReadFrom(buf); err == nil {
		t.Fatal("read errors must pass through")
	}
}

func TestNoTCPRelays(t *testing.T) {
	g := testGen(&Stats{}, &clock{})
	if _, _, err := g.AllocateListener(turn.AllocateListenerConfig{Network: "tcp4"}); err == nil {
		t.Fatal("TCP relay must be refused")
	}
	if _, err := g.AllocateConn(turn.AllocateConnConfig{Network: "tcp4"}); err == nil {
		t.Fatal("TCP connect must be refused")
	}
}

func TestRelayPortRange(t *testing.T) {
	g := &relayGen{
		base: &turn.RelayAddressGeneratorPortRange{RelayAddress: net.IPv4(127, 0, 0, 1), Address: "127.0.0.1", MinPort: 52150, MaxPort: 52160},
		own:  []net.IP{net.IPv4(127, 0, 0, 1)}, minPort: 52150, maxPort: 52160, bytesPerSec: 1000, stats: &Stats{}, now: time.Now,
	}
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	// RESERVATION-TOKEN / EVEN-PORT can ask for a fixed port: never outside the range
	for _, p := range []int{52149, 52161, 22, 3478} {
		if _, _, err := g.AllocatePacketConn(turn.AllocateListenerConfig{Network: "udp4", RequestedPort: p}); err == nil {
			t.Fatalf("port %d outside the relay range allocated", p)
		}
	}
	if _, _, err := g.AllocatePacketConn(turn.AllocateListenerConfig{Network: "udp6"}); err == nil {
		t.Fatal("IPv6 relay allocated (relays are IPv4)")
	}
	pc, addr, err := g.AllocatePacketConn(turn.AllocateListenerConfig{Network: "udp4"})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if p := addr.(*net.UDPAddr).Port; p < 52150 || p > 52160 {
		t.Fatalf("relay port %d", p)
	}
	if _, ok := pc.(*limitedConn); !ok {
		t.Fatal("relay conn is not rate limited")
	}
}
