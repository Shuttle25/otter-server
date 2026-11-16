package meshsim

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"ottermsg/server/internal/pinning"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/replication"
)

// dialTunnel is what the phone does (D114): a WebSocket to via's /tunnel, pinned TLS to target inside it, then the
// client protocol.
func (s *sim) dialTunnel(via, target *simNode, pin []byte) (*client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	outer, _, err := websocket.Dial(ctx, s.url(via)+"/tunnel?to="+hex.EncodeToString(target.id), nil)
	if err != nil {
		return nil, err
	}
	raw := websocket.NetConn(context.Background(), outer, websocket.MessageBinary)
	tc := tls.Client(raw, &tls.Config{ServerName: target.label + ".test", InsecureSkipVerify: true,
		VerifyPeerCertificate: func(certs [][]byte, _ [][]*x509.Certificate) error {
			c, err := x509.ParseCertificate(certs[0])
			if err != nil {
				return err
			}
			if !bytes.Equal(pinning.SPKIPin(c), pin) {
				return errors.New("certificate does not match the pin")
			}
			return nil
		}})
	hc := &http.Client{Transport: &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return tc, nil }}}
	c, _, err := websocket.Dial(ctx, "wss://"+target.label+".test"+path, &websocket.DialOptions{HTTPClient: hc})
	if err != nil {
		raw.Close()
		return nil, err
	}
	s.t.Cleanup(func() { c.CloseNow() })
	return s.wrap(c), nil
}

// D114 (limit 1, restore half): a phone that reaches only the node marked no_backups restores from f1 through a
// tunnel inside the peer session f1 dialed (D132: ru never dials abroad). ru relays only TLS records.
func TestRestoreThroughTunnel(t *testing.T) {
	s := newSimWith(t, map[string]nodeOpts{"ru": {noBackups: true}, "f1": {tunnel: true}, "f2": {tunnel: true}}, "ru", "f1", "f2")
	ru, f1, f2 := s.node("ru"), s.node("f1"), s.node("f2")
	s.part.Censor(ru, f1, pb.Endpoint_WS_PLAIN) // the session with f1 is always f1's dial
	anna := s.register(f1, "anna")
	c := s.login(f1, anna)
	data := randomBytes(3 << 20)
	blob, _ := s.publishBackup(c, anna, 1, data)
	c.close()

	var mu sync.Mutex
	var relayed []byte
	replication.SetTunnelTap(func(b []byte) { mu.Lock(); relayed = append(relayed, b...); mu.Unlock() })
	t.Cleanup(func() { replication.SetTunnelTap(nil) })

	eventually(t, "ru has a session to f1", func() bool {
		for _, p := range ru.repl.Status() {
			if bytes.Equal(p.Node, f1.id) && p.Connected {
				return true
			}
		}
		return false
	})
	tc, err := s.dialTunnel(ru, f1, f1.tunnelPin)
	if err != nil {
		t.Fatal(err)
	}
	var auth pb.BackupAuthResponse
	tc.mustCall("backup.auth", &pb.BackupAuthRequest{Username: "anna"}, &auth)
	var res pb.BackupFetchResponse
	tc.mustCall("backup.fetch", &pb.BackupFetchRequest{Username: "anna", AuthSecret: bytes.Repeat([]byte{5}, 32)}, &res)
	got, st := s.getBlob(tc, blob, 12)
	if st != pb.Status_STATUS_OK || !bytes.Equal(got, data) {
		t.Fatalf("restore through the tunnel: %v", st)
	}
	tc.close()
	mu.Lock()
	leak := len(auth.Salt) == 0 || bytes.Contains(relayed, auth.Salt) || bytes.Contains(relayed, []byte("backup.fetch")) ||
		bytes.Contains(relayed, []byte("anna"))
	n := len(relayed)
	mu.Unlock()
	if n < len(data) || leak {
		t.Fatalf("relayed %d bytes, plaintext visible to ru: %v", n, leak)
	}

	// pinning: ru (or anyone in the path) cannot pose as f1
	if _, err := s.dialTunnel(ru, f1, f2.tunnelPin); err == nil {
		t.Fatal("wrong pin accepted")
	}
	// only a node marked no_backups relays, never to itself or to a node outside the manifest
	for _, tc := range []struct {
		name string
		via  *simNode
		to   []byte
	}{
		{"node without no_backups serves /tunnel", f2, f1.id},
		{"tunnel to itself", ru, ru.id},
		{"tunnel to a node outside the manifest", ru, bytes.Repeat([]byte{9}, 16)},
	} {
		if _, resp, err := websocket.Dial(context.Background(), s.url(tc.via)+"/tunnel?to="+hex.EncodeToString(tc.to), nil); err == nil || resp == nil || resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}
	// no peer session to the target: unavailable, and ru does not dial for it
	s.part.Block(ru, f2)
	if _, resp, err := websocket.Dial(context.Background(), s.url(ru)+"/tunnel?to="+hex.EncodeToString(f2.id), nil); err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("tunnel without a peer session: %v", err)
	}
}
