package probe

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"ottermsg/server/internal/gateway"
	"ottermsg/server/internal/pinning"
	"ottermsg/server/internal/service"
	"ottermsg/server/internal/store"
)

func tlsNode(t *testing.T) (addr string, pin []byte, nodeID []byte) {
	st, err := store.Open(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	_, nodeKey, _ := ed25519.GenerateKey(nil)
	svc := service.New(st, nodeKey, pub)
	certPEM, keyPEM, pin, err := pinning.GenerateCert([]string{"chat.test"}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pair, _ := tls.X509KeyPair(certPEM, keyPEM)
	srv := httptest.NewUnstartedServer(gateway.New(svc, slog.New(slog.DiscardHandler)))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	t.Cleanup(func() { srv.Close(); st.Close() })
	return srv.Listener.Addr().String(), pin, svc.NodeID
}

func TestProbe(t *testing.T) {
	addr, pin, id := tlsNode(t)
	_, port, _ := net.SplitHostPort(addr)
	url := "wss://chat.test:" + port + "/"
	ctx := context.Background()
	ok := Options{URL: url, Pins: [][]byte{pin}, Addr: addr, ExpectNode: id, Timeout: 5 * time.Second}
	r, err := Run(ctx, ok)
	if err != nil || !bytes.Equal(r.NodeID, id) || r.Protocol != 1 {
		t.Fatalf("probe: %v %+v", err, r)
	}
	bad := ok
	bad.Pins = [][]byte{make([]byte, 32)}
	if _, err := Run(ctx, bad); err == nil {
		t.Fatal("wrong pin accepted")
	}
	other := ok
	other.ExpectNode = make([]byte, 16)
	if _, err := Run(ctx, other); err == nil {
		t.Fatal("wrong node id accepted")
	}
	none := ok
	none.Pins = nil
	if _, err := Run(ctx, none); err == nil {
		t.Fatal("wss without pins or --insecure accepted")
	}
	insecure := none
	insecure.Insecure = true
	if _, err := Run(ctx, insecure); err != nil {
		t.Fatalf("--insecure: %v", err)
	}
}
