package meshsim

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "ottermsg/server/internal/proto/otterv1"
)

// realityWait covers the first REALITY session after a server starts (the server probes its camouflage site once,
// up to ~5 s) plus -race on a loaded machine.
const realityWait = 30 * time.Second

func netlogHas(n *simNode, dir, endpointPrefix, result string) bool {
	es, _ := n.st.Netlog(context.Background(), 200)
	for _, e := range es {
		if e.Direction == dir && strings.HasPrefix(e.Endpoint, endpointPrefix) && e.Result == result {
			return true
		}
	}
	return false
}

// noOutboundTo fails if from ever dialed the node labelled to.
func noOutboundTo(t *testing.T, from *simNode, to string) {
	t.Helper()
	es, _ := from.st.Netlog(context.Background(), 200)
	for _, e := range es {
		if e.Direction == "out" && e.Peer == to {
			t.Fatalf("%s dialed %s: %+v", from.label, to, e)
		}
	}
}

// ruFi is a dial_out_only node ru and a node fi with WS_PLAIN + REALITY; ru→fi WS_PLAIN is censored once their
// first session is up (censoring earlier could miss a session whose handshake is still in flight).
func ruFi(t *testing.T) (s *sim, ru, fi *simNode) {
	s = newSimWith(t, map[string]nodeOpts{"ru": {dialOutOnly: true}, "fi": {reality: true}}, "ru", "fi")
	ru, fi = s.node("ru"), s.node("fi")
	eventually(t, "first ru→fi session", func() bool { return ru.repl.Status()[0].Connected })
	s.part.Censor(ru, fi, pb.Endpoint_WS_PLAIN)
	return s, ru, fi
}

// users registers alice on ru and bob on fi and waits until both nodes know both.
func users(t *testing.T, s *sim, ru, fi *simNode) (alice, bob *account) {
	alice, bob = s.register(ru, "alice"), s.register(fi, "bob")
	eventuallyWithin(t, realityWait, "users on both nodes", func() bool {
		return ru.knows(alice) && ru.knows(bob) && fi.knows(alice) && fi.knows(bob)
	})
	return alice, bob
}

func TestRealityCarriesReplicationWhenWSCensored(t *testing.T) {
	s, ru, fi := ruFi(t)
	alice, bob := users(t, s, ru, fi)
	s.send(s.login(ru, alice), alice, bob, "привет")
	eventuallyWithin(t, realityWait, "bob gets the message via REALITY", func() bool { return fi.mailbox(bob) > 0 })
	if !netlogHas(ru, "out", "reality:", "ok") || !netlogHas(fi, "in", "reality", "ok") {
		t.Fatal("netlog must show the REALITY session on both sides")
	}
	if !netlogHas(ru, "out", "ws_plain:", "fail") {
		t.Fatal("netlog must show the censored WS endpoint failing")
	}
	noOutboundTo(t, fi, "ru")
}

// REALITY is the endpoint that worked last; when it gets censored, ru falls back to WS (D73 ranking).
func TestWSFallbackWhenRealityCensored(t *testing.T) {
	s, ru, fi := ruFi(t)
	alice, bob := users(t, s, ru, fi)
	eventuallyWithin(t, realityWait, "REALITY session ok", func() bool { return netlogHas(ru, "out", "reality:", "ok") })

	s.part.Uncensor(ru, fi, pb.Endpoint_WS_PLAIN)
	s.part.Censor(ru, fi, pb.Endpoint_REALITY) // cuts the REALITY session
	s.send(s.login(ru, alice), alice, bob, "fallback")
	eventuallyWithin(t, realityWait, "message via WS fallback", func() bool { return fi.mailbox(bob) > 0 })
	if !netlogHas(ru, "out", "reality:", "fail") || !netlogHas(ru, "out", "ws_plain:", "ok") {
		t.Fatal("netlog must show REALITY failing and the WS fallback")
	}
	noOutboundTo(t, fi, "ru")
}

func TestRealityProbeSeesCamouflage(t *testing.T) {
	s := newSimWith(t, map[string]nodeOpts{"fi": {reality: true}}, "fi")
	fi := s.node("fi")
	addr := net.JoinHostPort(fi.reality.ep.Host, strconv.Itoa(int(fi.reality.ep.Port)))
	c, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "camo.test", InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if string(c.ConnectionState().PeerCertificates[0].Raw) != string(fi.reality.camo.Certificate().Raw) {
		t.Fatal("probe must see the camouflage certificate")
	}
}
