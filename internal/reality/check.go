package reality

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"
)

type CheckResult struct {
	TLS13, H2, CertOK bool
	Latency           time.Duration
}

func (r CheckResult) OK() bool { return r.TLS13 && r.H2 && r.CertOK }

// Check tests a camouflage candidate from this machine: TLS 1.3, ALPN h2, a certificate valid for host (D72).
func Check(ctx context.Context, host string) (CheckResult, error) {
	return check(ctx, net.JoinHostPort(host, "443"), host, nil)
}

// check dials addr with SNI serverName; roots nil = the system roots.
func check(ctx context.Context, addr, serverName string, roots *x509.CertPool) (CheckResult, error) {
	var r CheckResult
	t0 := time.Now()
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config: &tls.Config{ServerName: serverName, RootCAs: roots, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12}}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		var cv *tls.CertificateVerificationError
		if errors.As(err, &cv) {
			return r, fmt.Errorf("%s: certificate: %w", serverName, err)
		}
		return r, fmt.Errorf("%s: %w", serverName, err) // CertOK stays false
	}
	defer c.Close()
	st := c.(*tls.Conn).ConnectionState()
	r.Latency = time.Since(t0)
	r.TLS13 = st.Version == tls.VersionTLS13
	r.H2 = st.NegotiatedProtocol == "h2"
	r.CertOK = true
	return r, nil
}
