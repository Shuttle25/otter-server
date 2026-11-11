package meshsim

import (
	"bytes"
	"context"
	"errors"
	"sync"

	"github.com/coder/websocket"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/replication"
)

// partition decides which node pairs may dial each other and cuts live sessions on Block.
type partition struct {
	mu      sync.Mutex
	blocked map[string]bool
	repls   map[string]*replication.Replicator
}

func newPartition() *partition {
	return &partition{blocked: map[string]bool{}, repls: map[string]*replication.Replicator{}}
}

func key(a, b []byte) string {
	if bytes.Compare(a, b) > 0 {
		a, b = b, a
	}
	return string(a) + string(b)
}

func (p *partition) register(id []byte, r *replication.Replicator) {
	p.mu.Lock()
	p.repls[string(id)] = r
	p.mu.Unlock()
}

func (p *partition) Block(a, b *simNode) {
	p.mu.Lock()
	p.blocked[key(a.id, b.id)] = true
	ra, rb := p.repls[string(a.id)], p.repls[string(b.id)]
	p.mu.Unlock()
	ra.DropPeer(b.id)
	rb.DropPeer(a.id)
}

func (p *partition) Heal(a, b *simNode) {
	p.mu.Lock()
	delete(p.blocked, key(a.id, b.id))
	p.mu.Unlock()
}

type gatedDialer struct {
	p    *partition
	self []byte
}

func (p *partition) dialer(self []byte) replication.Dialer { return gatedDialer{p, self} }

func (d gatedDialer) Dial(ctx context.Context, n *pb.NodeInfo) (*websocket.Conn, error) {
	d.p.mu.Lock()
	blocked := d.p.blocked[key(d.self, n.NodeId)]
	d.p.mu.Unlock()
	if blocked {
		return nil, errors.New("partitioned")
	}
	c, err := replication.NetDialer{AllowPlain: true}.Dial(ctx, n)
	if err != nil {
		return nil, err
	}
	d.p.mu.Lock()
	blocked = d.p.blocked[key(d.self, n.NodeId)]
	d.p.mu.Unlock()
	if blocked { // Block() happened while this dial was in flight
		c.CloseNow()
		return nil, errors.New("partitioned")
	}
	return c, nil
}
