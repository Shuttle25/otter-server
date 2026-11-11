package client

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"ottermsg/server/internal/gateway"
	"ottermsg/server/internal/pinning"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/service"
	"ottermsg/server/internal/store"
)

func startTLSNode(t *testing.T) (*pb.Endpoint, []byte) {
	st, err := store.Open(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	_, nodeKey, _ := ed25519.GenerateKey(nil)
	svc := service.New(st, nodeKey, pub)
	gw := gateway.New(svc, slog.New(slog.DiscardHandler))
	certPEM, keyPEM, pin, err := pinning.GenerateCert([]string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pair, _ := tls.X509KeyPair(certPEM, keyPEM)
	srv := httptest.NewUnstartedServer(gw)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	t.Cleanup(func() { srv.Close(); st.Close() })
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	return &pb.Endpoint{Kind: pb.Endpoint_WSS, Host: "127.0.0.1", Port: uint32(port), Path: "/", TlsSpkiPins: [][]byte{pin}}, svc.NodeID
}

func TestPinnedDialAndCall(t *testing.T) {
	ep, nodeID := startTLSNode(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, ep, false)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if string(c.Hello().NodeId) != string(nodeID) {
		t.Fatal("hello node id")
	}
	if err := c.Call(ctx, "ping", &pb.Empty{}, &pb.Empty{}); err != nil {
		t.Fatal(err)
	}
	var se *StatusError
	if err := c.Call(ctx, "directory.sync", &pb.Empty{}, nil); !errors.As(err, &se) || se.Status != pb.Status_STATUS_UNAUTHORIZED {
		t.Fatalf("want unauthorized, got %v", err)
	}
}

func TestWrongPinRefused(t *testing.T) {
	ep, _ := startTLSNode(t)
	ep.TlsSpkiPins = [][]byte{make([]byte, 32)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Dial(ctx, ep, false); err == nil {
		t.Fatal("wrong pin accepted")
	}
}

func TestPlainNeedsOptIn(t *testing.T) {
	ep := &pb.Endpoint{Kind: pb.Endpoint_WS_PLAIN, Host: "127.0.0.1", Port: 1, Path: "/x"}
	if _, err := URL(ep, false); err == nil {
		t.Fatal("plain endpoint used without opt-in")
	}
	if u, err := URL(ep, true); err != nil || u != "ws://127.0.0.1:1/x" {
		t.Fatalf("%s %v", u, err)
	}
}
