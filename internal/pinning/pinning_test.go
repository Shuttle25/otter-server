package pinning

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func server(t *testing.T, validity time.Duration) (*httptest.Server, []byte) {
	t.Helper()
	certPEM, keyPEM, pin, err := GenerateCert([]string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, validity)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, pin
}

func get(srv *httptest.Server, host string, pins [][]byte) error {
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: ClientConfig(host, pins)}, Timeout: 5 * time.Second}
	resp, err := cl.Get(srv.URL)
	if err == nil {
		resp.Body.Close()
	}
	return err
}

func TestGenerateCertAndPin(t *testing.T) {
	certPEM, _, pin, err := GenerateCert([]string{"chat.example.org"}, []net.IP{net.ParseIP("203.0.113.10")}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(certPEM)
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pin, SPKIPin(c)) || len(pin) != 32 {
		t.Fatal("pin")
	}
	if c.VerifyHostname("chat.example.org") != nil || c.VerifyHostname("203.0.113.10") != nil {
		t.Fatal("SAN")
	}
}

func TestPinnedDial(t *testing.T) {
	srv, pin := server(t, time.Hour)
	if err := get(srv, "127.0.0.1", [][]byte{pin}); err != nil {
		t.Fatalf("matching pin: %v", err)
	}
	other := bytes.Repeat([]byte{1}, 32)
	if err := get(srv, "127.0.0.1", [][]byte{other, pin}); err != nil {
		t.Fatalf("pin among several (rotation): %v", err)
	}
	if err := get(srv, "127.0.0.1", [][]byte{other}); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("wrong pin: %v", err)
	}
	if err := get(srv, "example.org", [][]byte{pin}); err == nil {
		t.Fatal("wrong hostname accepted")
	}
	if err := get(srv, "127.0.0.1", nil); err == nil {
		t.Fatal("self-signed cert accepted without pins (system verification)")
	}
}

func TestExpiredCertRejected(t *testing.T) {
	srv, pin := server(t, -time.Minute)
	err := get(srv, "127.0.0.1", [][]byte{pin})
	if err == nil || !strings.Contains(err.Error(), "not valid now") {
		t.Fatalf("expired: %v", err)
	}
	if errors.Is(err, ErrPinMismatch) {
		t.Fatal("wrong reason")
	}
}
