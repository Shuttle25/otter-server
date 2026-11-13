package replication

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

const (
	ProtocolVersion  = 1
	maxSkew          = 5 * time.Minute
	handshakeTimeout = 10 * time.Second
)

// readFrame reads one peer frame; n is the payload length received.
func readFrame(ctx context.Context, c *websocket.Conn) (f *pb.PeerFrame, n int, err error) {
	typ, data, err := c.Read(ctx)
	if err != nil {
		return nil, len(data), err
	}
	if typ != websocket.MessageBinary {
		return nil, len(data), errors.New("peer: text frame")
	}
	f = &pb.PeerFrame{}
	return f, len(data), proto.Unmarshal(data, f)
}

func writeFrame(ctx context.Context, c *websocket.Conn, f *pb.PeerFrame) error {
	b, err := proto.Marshal(f)
	if err != nil {
		return err
	}
	return c.Write(ctx, websocket.MessageBinary, b)
}

func nonce() []byte { b := make([]byte, 32); rand.Read(b); return b }

func skewOK(now time.Time, ts int64) bool {
	d := now.Sub(time.UnixMilli(ts))
	return d <= maxSkew && d >= -maxSkew
}

// acceptHandshake runs on the acceptor; returns the authenticated peer node id.
func (r *Replicator) acceptHandshake(ctx context.Context, c *websocket.Conn) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	n := nonce()
	if err := writeFrame(ctx, c, &pb.PeerFrame{Kind: &pb.PeerFrame_Hello{Hello: &pb.PeerHello{
		ProtocolVersion: ProtocolVersion, NodeId: r.svc.NodeID, Nonce: n, ManifestVersion: r.manifestVersion()}}}); err != nil {
		return nil, err
	}
	f, _, err := readFrame(ctx, c)
	if err != nil {
		return nil, err
	}
	a := f.GetAuth()
	if a == nil {
		return nil, errors.New("peer: expected auth")
	}
	pub, ok := r.svc.NodeKey(a.NodeId)
	switch {
	case !ok:
		return nil, fmt.Errorf("peer: node %x not in manifest", a.NodeId)
	case bytes.Equal(a.NodeId, r.svc.NodeID):
		return nil, errors.New("peer: connection to self")
	case !skewOK(r.svc.Now(), a.TsMs):
		return nil, errors.New("peer: clock skew")
	case len(a.Nonce) != 32 || !ed25519.Verify(pub, keys.PeerAuthMessage(r.svc.NodeID, n, a.TsMs), a.Signature):
		return nil, errors.New("peer: bad signature")
	}
	ts := r.svc.Now().UnixMilli()
	sig := ed25519.Sign(r.svc.NodeKeyPriv, keys.PeerAuthMessage(a.NodeId, a.Nonce, ts))
	return a.NodeId, writeFrame(ctx, c, &pb.PeerFrame{Kind: &pb.PeerFrame_AuthOk{AuthOk: &pb.PeerAuthOk{TsMs: ts, Signature: sig}}})
}

// dialHandshake runs on the dialer against expected node n.
func (r *Replicator) dialHandshake(ctx context.Context, c *websocket.Conn, n *pb.NodeInfo) error {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	f, _, err := readFrame(ctx, c)
	if err != nil {
		return err
	}
	h := f.GetHello()
	if h == nil || !bytes.Equal(h.NodeId, n.NodeId) || len(h.Nonce) != 32 {
		return errors.New("peer: unexpected hello")
	}
	my := nonce()
	ts := r.svc.Now().UnixMilli()
	if err := writeFrame(ctx, c, &pb.PeerFrame{Kind: &pb.PeerFrame_Auth{Auth: &pb.PeerAuth{NodeId: r.svc.NodeID, TsMs: ts, Nonce: my,
		ManifestVersion: r.manifestVersion(),
		Signature:       ed25519.Sign(r.svc.NodeKeyPriv, keys.PeerAuthMessage(n.NodeId, h.Nonce, ts))}}}); err != nil {
		return err
	}
	f, _, err = readFrame(ctx, c)
	if err != nil {
		return err
	}
	if e := f.GetError(); e != nil {
		return fmt.Errorf("peer refused: %s", e.Message)
	}
	ok := f.GetAuthOk()
	if ok == nil || !skewOK(r.svc.Now(), ok.TsMs) ||
		!ed25519.Verify(n.NodePub, keys.PeerAuthMessage(r.svc.NodeID, my, ok.TsMs), ok.Signature) {
		return errors.New("peer: bad auth_ok")
	}
	return nil
}
