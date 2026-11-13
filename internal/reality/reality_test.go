package reality

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	pb "ottermsg/server/internal/proto/otterv1"
)

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestKeys(t *testing.T) {
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{priv, pub} {
		if raw, err := b64.DecodeString(k); err != nil || len(raw) != 32 {
			t.Fatalf("key %q: %v (len %d)", k, err, len(raw))
		}
	}
	if p2, err := PublicFromPrivate(priv); err != nil || p2 != pub {
		t.Fatalf("derive: %v %s %s", err, p2, pub)
	}
	if _, err := PublicFromPrivate("short"); err == nil {
		t.Fatal("a bad private key must be refused")
	}
}

func TestKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reality.key")
	priv, _, _ := GenerateKey()
	if err := WriteKeyFile(path, priv); err != nil {
		t.Fatal(err)
	}
	if err := WriteKeyFile(path, priv); !os.IsExist(err) {
		t.Fatalf("second write must refuse to overwrite: %v", err)
	}
	if got, err := ReadKeyFile(path); err != nil || got != priv {
		t.Fatalf("read back: %v %q", err, got)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
}

type pair struct {
	ep          *pb.Endpoint
	realityAddr string
	camo        *httptest.Server
}

// startPair runs a camouflage TLS 1.3 site, an internal handler and a REALITY server in front of them.
func startPair(t *testing.T) pair {
	camo := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "camouflage") }))
	camo.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	camo.StartTLS()
	t.Cleanup(camo.Close)
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "otter:"+r.URL.Path) }))
	t.Cleanup(internal.Close)
	priv, pub, _ := GenerateKey()
	port := freePort(t)
	uuid := "d6a3f0b2-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
	srv, err := StartServer(ServerConfig{Listen: "127.0.0.1:" + strconv.Itoa(port), PrivateKey: priv,
		Dest: camo.Listener.Addr().String(), ServerNames: []string{"camo.test"}, ShortIDs: []string{"a1b2c3d4"},
		VlessUUID: uuid, Forward: internal.Listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	raw, _ := b64.DecodeString(pub)
	ep := &pb.Endpoint{Kind: pb.Endpoint_REALITY, Host: "127.0.0.1", Port: uint32(port), VlessUuid: uuid, RealityPub: raw,
		ShortIds: []string{"a1b2c3d4"}, ServerNames: []string{"camo.test"}, Fingerprint: "chrome", Path: "/x"}
	return pair{ep: ep, realityAddr: "127.0.0.1:" + strconv.Itoa(port), camo: camo}
}

func tunnelClient(cl *Client, ep *pb.Endpoint, timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return cl.DialContext(ctx, ep)
	}}}
}

func TestTunnelReachesInternalHandler(t *testing.T) {
	p := startPair(t)
	cl := NewClient()
	t.Cleanup(cl.Close)
	hc := tunnelClient(cl, p.ep, 10*time.Second)
	for i := 0; i < 2; i++ { // the second request reuses the client's Xray instance
		resp, err := hc.Get("http://anything.invalid/x/peer")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != "otter:/x/peer" {
			t.Fatalf("body %q", b)
		}
		hc.CloseIdleConnections()
	}
	if n := len(cl.inst); n != 1 {
		t.Fatalf("%d client instances, want 1", n)
	}
}

// The tunnel must outlive the context it was dialed with (the replication dialer cancels its dial timeout).
func TestTunnelOutlivesDialContext(t *testing.T) {
	p := startPair(t)
	cl := NewClient()
	t.Cleanup(cl.Close)
	ctx, cancel := context.WithCancel(context.Background())
	c, err := cl.DialContext(ctx, p.ep)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cancel()
	time.Sleep(100 * time.Millisecond)
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, "GET /x/late HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "otter:/x/late" {
		t.Fatalf("body %q", b)
	}
}

// An authenticated client asking for another destination still lands on the internal listener (freedom redirect).
func TestOnlyRedirectOutbound(t *testing.T) {
	p := startPair(t)
	forbidden := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "forbidden") }))
	t.Cleanup(forbidden.Close)
	cl := NewClient()
	t.Cleanup(cl.Close)
	in, err := cl.instance(p.ep)
	if err != nil {
		t.Fatal(err)
	}
	fa := forbidden.Listener.Addr().(*net.TCPAddr)
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return core.Dial(context.WithoutCancel(ctx), in, xnet.TCPDestination(xnet.IPAddress(fa.IP), xnet.Port(fa.Port)))
	}}}
	resp, err := hc.Get("http://" + fa.String() + "/x/peer")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "otter:/x/peer" {
		t.Fatalf("an authenticated client reached %q, not the internal listener", b)
	}
}

func TestProbeWithoutKeySeesCamouflage(t *testing.T) {
	p := startPair(t)
	c, err := tls.Dial("tcp", p.realityAddr, &tls.Config{ServerName: "camo.test", InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	got := c.ConnectionState().PeerCertificates[0].Raw
	want := p.camo.Certificate().Raw
	if string(got) != string(want) {
		t.Fatal("a probe without the key must get the camouflage site's certificate")
	}
}

func TestWrongKeyFails(t *testing.T) {
	p := startPair(t)
	_, other, _ := GenerateKey()
	p.ep.RealityPub, _ = b64.DecodeString(other)
	cl := NewClient()
	t.Cleanup(cl.Close)
	hc := tunnelClient(cl, p.ep, 5*time.Second)
	if resp, err := hc.Get("http://x/x/peer"); err == nil {
		resp.Body.Close()
		t.Fatal("tunnel with a wrong public key must fail")
	}
}

func TestIncompleteEndpointRefused(t *testing.T) {
	cl := NewClient()
	t.Cleanup(cl.Close)
	ep := &pb.Endpoint{Kind: pb.Endpoint_REALITY, Host: "127.0.0.1", Port: 443, VlessUuid: "d6a3f0b2-1c2d-4e5f-8a9b-0c1d2e3f4a5b"}
	if _, err := cl.DialContext(context.Background(), ep); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("err %v", err)
	}
}

func TestServerConfigValidation(t *testing.T) {
	priv, _, _ := GenerateKey()
	good := ServerConfig{Listen: "127.0.0.1:0", PrivateKey: priv, Dest: "example.com:443", ServerNames: []string{"example.com"},
		ShortIDs: []string{"a1b2"}, VlessUUID: "d6a3f0b2-1c2d-4e5f-8a9b-0c1d2e3f4a5b", Forward: "127.0.0.1:8080"}
	if _, err := serverConfig(good); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*ServerConfig){
		"listen":  func(c *ServerConfig) { c.Listen = "443" },
		"key":     func(c *ServerConfig) { c.PrivateKey = "x" },
		"dest":    func(c *ServerConfig) { c.Dest = "example.com" },
		"sni":     func(c *ServerConfig) { c.ServerNames = nil },
		"sid":     func(c *ServerConfig) { c.ShortIDs = []string{"xyz"} },
		"sidlen":  func(c *ServerConfig) { c.ShortIDs = []string{"0123456789abcdef01"} },
		"uuid":    func(c *ServerConfig) { c.VlessUUID = "not-a-uuid-and-longer-than-thirty-bytes" },
		"forward": func(c *ServerConfig) { c.Forward = "nope" },
	} {
		c := good
		mut(&c)
		if _, err := serverConfig(c); err == nil {
			t.Errorf("%s: bad config accepted", name)
		}
	}
}

// localH2 is a TLS site on loopback; Check is pointed at it with its own root.
func localH2(t *testing.T, tlsCfg *tls.Config) (addr string, roots *x509.CertPool) {
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	s.EnableHTTP2 = true
	s.TLS = tlsCfg
	s.StartTLS()
	t.Cleanup(s.Close)
	roots = x509.NewCertPool()
	roots.AddCert(s.Certificate())
	return s.Listener.Addr().String(), roots
}

func TestCheckLocal(t *testing.T) {
	addr, roots := localH2(t, &tls.Config{MinVersion: tls.VersionTLS13})
	r, err := check(context.Background(), addr, "example.com", roots)
	if err != nil || !r.OK() || r.Latency <= 0 {
		t.Fatalf("good site: %+v %v", r, err)
	}
	// TLS 1.2 only: not a usable camouflage target
	addr12, roots12 := localH2(t, &tls.Config{MaxVersion: tls.VersionTLS12})
	if r, err := check(context.Background(), addr12, "example.com", roots12); err != nil || r.OK() || r.TLS13 {
		t.Fatalf("tls1.2 site: %+v %v", r, err)
	}
	// a certificate not valid for the name: fails with CertOK false
	if r, err := check(context.Background(), addr, "other.test", roots); err == nil || r.CertOK {
		t.Fatalf("wrong name: %+v %v", r, err)
	}
	if _, err := Check(context.Background(), "nonexistent.invalid"); err == nil {
		t.Fatal("Check must fail for an unresolvable host")
	}
}

// A site whose handshake records exceed what REALITY can mirror (8 KB; www.microsoft.com's certificate chain was
// 8273 bytes on 2026-11-13) passes plain TLS checks but no peer could ever authenticate through it.
func TestCheckRejectsOversizedHandshake(t *testing.T) {
	big := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	big.EnableHTTP2 = true
	big.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	big.StartTLS() // generates the test certificate; reuse it with a padded chain
	cert := big.TLS.Certificates[0]
	big.Close()
	for len(cert.Certificate) < 12 { // extra copies of the leaf: ignored by verification, sent on the wire
		cert.Certificate = append(cert.Certificate, cert.Certificate[0])
	}
	addr, roots := localH2(t, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}})
	r, err := check(context.Background(), addr, "example.com", roots)
	if err == nil && r.OK() {
		t.Fatalf("oversized handshake accepted: %+v", r)
	}
	if !r.TLS13 || !r.H2 || !r.CertOK || r.Handshake {
		t.Fatalf("want tls/h2/cert ok and handshake failed: %+v %v", r, err)
	}
}
