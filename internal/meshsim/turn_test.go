package meshsim

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"

	pb "ottermsg/server/internal/proto/otterv1"
)

func creds(t *testing.T, c *client) *pb.TurnCredentials {
	t.Helper()
	var cr pb.TurnCredentials
	if st, msg := c.call("turn.credentials", &pb.Empty{}, &cr); st != pb.Status_STATUS_OK {
		t.Fatalf("turn.credentials: %v %s", st, msg)
	}
	return &cr
}

// turnClient connects over "udp", "tcp" or "tls" to addr and returns an allocated relay conn.
func turnClient(t *testing.T, transport, addr string, cr *pb.TurnCredentials) (net.PacketConn, error) {
	t.Helper()
	var conn net.PacketConn
	switch transport {
	case "udp":
		c, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		conn = c
	case "tcp":
		c, err := net.Dial("tcp4", addr)
		if err != nil {
			t.Fatal(err)
		}
		conn = turn.NewSTUNConn(c)
	case "tls":
		c, err := tls.Dial("tcp4", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // same as phones (D77)
		if err != nil {
			t.Fatal(err)
		}
		conn = turn.NewSTUNConn(c)
	default:
		t.Fatalf("transport %q", transport)
	}
	t.Cleanup(func() { conn.Close() }) // runs last: after the client and the allocation
	lf := logging.NewDefaultLoggerFactory()
	lf.DefaultLogLevel = logging.LogLevelError
	cl, err := turn.NewClient(&turn.ClientConfig{STUNServerAddr: addr, TURNServerAddr: addr, Conn: conn,
		Username: cr.Username, Password: cr.Password, Realm: "otter", LoggerFactory: lf})
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.Listen(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cl.Close)
	relay, err := cl.Allocate()
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { relay.Close() }) // runs first: frees the allocation while the client still runs
	return relay, nil
}

// exchange relays a payload a -> b and b -> a through the two relay allocations.
func exchange(t *testing.T, a, b net.PacketConn) {
	t.Helper()
	// the first write to a peer creates the TURN permission on each side
	b.WriteTo([]byte("open"), a.LocalAddr())
	a.WriteTo([]byte("open"), b.LocalAddr())
	for _, pair := range [][2]net.PacketConn{{a, b}, {b, a}} {
		eventuallyWithin(t, 5*time.Second, "relayed payload", func() bool {
			pair[0].WriteTo([]byte("voice"), pair[1].LocalAddr())
			buf := make([]byte, 64)
			pair[1].SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, _, err := pair[1].ReadFrom(buf)
			return err == nil && string(buf[:n]) == "voice"
		})
	}
}

func TestCallRelayAcrossNodes(t *testing.T) {
	s := newSimWith(t, map[string]nodeOpts{"a": {turn: true}, "b": {turn: true}}, "a", "b")
	a, b := s.node("a"), s.node("b")
	anna, boris := s.register(a, "anna"), s.register(b, "boris")
	ca, cb := s.login(a, anna), s.login(b, boris)
	defer ca.close()
	defer cb.close()
	ra, err := turnClient(t, "udp", a.turnAddr, creds(t, ca))
	if err != nil {
		t.Fatal(err)
	}
	rb, err := turnClient(t, "tcp", b.turnAddr, creds(t, cb))
	if err != nil {
		t.Fatal(err)
	}
	exchange(t, ra, rb)
	rt, err := turnClient(t, "tls", b.turnTLSAddr, creds(t, cb))
	if err != nil {
		t.Fatal(err)
	}
	exchange(t, ra, rt)
}

func TestTurnCredentialsAreNodeLocal(t *testing.T) {
	s := newSimWith(t, map[string]nodeOpts{"a": {turn: true}, "b": {turn: true}}, "a", "b")
	a, b := s.node("a"), s.node("b")
	anna := s.register(a, "anna")
	ca := s.login(a, anna)
	defer ca.close()
	cr := creds(t, ca)
	if _, err := turnClient(t, "udp", b.turnAddr, cr); err == nil {
		t.Fatal("node b accepted credentials issued by node a")
	}
	if _, err := turnClient(t, "udp", a.turnAddr, cr); err != nil { // control: the same credentials work on a
		t.Fatalf("node a refused its own credentials: %v", err)
	}
}

func TestTurnOffNode(t *testing.T) {
	s := newSim(t, "a")
	a := s.node("a")
	ca := s.login(a, s.register(a, "anna"))
	defer ca.close()
	if st, _ := ca.call("turn.credentials", &pb.Empty{}, nil); st != pb.Status_STATUS_UNAVAILABLE {
		t.Fatalf("want UNAVAILABLE, got %v", st)
	}
}
