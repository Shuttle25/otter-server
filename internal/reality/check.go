package reality

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/xtls/xray-core/common/uuid"
	pb "ottermsg/server/internal/proto/otterv1"
)

type CheckResult struct {
	TLS13, H2, CertOK bool
	Handshake         bool // a loopback REALITY handshake through the site worked
	Latency           time.Duration
}

func (r CheckResult) OK() bool { return r.TLS13 && r.H2 && r.CertOK && r.Handshake }

// Check tests a camouflage candidate from this machine: TLS 1.3, ALPN h2, a certificate valid for host (D72), and
// a REALITY handshake through it on loopback: REALITY mirrors the site's handshake records and gives up on sites
// whose records are too large (over 8 KB, e.g. a long certificate chain), which the TLS checks alone don't see.
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
	if !r.TLS13 || !r.H2 {
		return r, nil
	}
	if err := handshakeThrough(ctx, addr, serverName); err != nil {
		return r, fmt.Errorf("%s: REALITY handshake through it failed (handshake records over 8 KB?): %w", serverName, err)
	}
	r.Handshake = true
	return r, nil
}

const checkGreeting = "otter-reality-check"

// handshakeThrough starts a REALITY server on loopback with dest addr and dials it the way a peer does; an
// authenticated stream reaches a tiny internal listener that answers checkGreeting.
func handshakeThrough(ctx context.Context, addr, serverName string) error {
	internal, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer internal.Close()
	go func() {
		for {
			c, err := internal.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, checkGreeting)
			_ = c.Close()
		}
	}()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	listen := l.Addr().String()
	_ = l.Close()
	priv, pub, err := GenerateKey()
	if err != nil {
		return err
	}
	id := uuid.New()
	srv, err := StartServer(ServerConfig{Listen: listen, PrivateKey: priv, Dest: addr, ServerNames: []string{serverName},
		ShortIDs: []string{"0c"}, VlessUUID: id.String(), Forward: internal.Addr().String()})
	if err != nil {
		return err
	}
	defer srv.Close()
	host, port, err := hostPort(listen)
	if err != nil {
		return err
	}
	raw, _ := b64.DecodeString(pub)
	cl := NewClient()
	defer cl.Close()
	conn, err := cl.DialContext(ctx, &pb.Endpoint{Kind: pb.Endpoint_REALITY, Host: host, Port: port, VlessUuid: id.String(),
		RealityPub: raw, ShortIds: []string{"0c"}, ServerNames: []string{serverName}, Fingerprint: "chrome"})
	if err != nil {
		return err
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() {
		b := make([]byte, len(checkGreeting))
		_, err := io.ReadFull(conn, b)
		if err == nil && string(b) != checkGreeting {
			err = fmt.Errorf("unexpected reply %q", b)
		}
		done <- err
	}()
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	select {
	case err := <-done:
		return err
	case <-t.C:
		return errors.New("timeout")
	case <-ctx.Done():
		return ctx.Err()
	}
}
