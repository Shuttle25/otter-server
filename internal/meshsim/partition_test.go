package meshsim

import (
	"bytes"
	"context"
	"errors"
	"sync"

	"github.com/coder/websocket"
	"ottermsg/server/internal/netlog"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/reality"
	"ottermsg/server/internal/replication"
)

// partition decides which node pairs may dial each other and cuts live sessions on Block.
type partition struct {
	mu       sync.Mutex
	blocked  map[string]bool
	censored map[string]bool // one direction, one endpoint kind (censorKey)
	repls    map[string]*replication.Replicator
	reality  map[string]replication.RealityDialer // per dialing node; none = REALITY unsupported
}

func newPartition() *partition {
	return &partition{blocked: map[string]bool{}, censored: map[string]bool{}, repls: map[string]*replication.Replicator{},
		reality: map[string]replication.RealityDialer{}}
}

func censorKey(from, to []byte, k pb.Endpoint_Kind) string {
	return string(from) + "→" + string(to) + k.String()
}

// Censor blocks endpoints of kind k from `from` to `to` and cuts their live session.
func (p *partition) Censor(from, to *simNode, k pb.Endpoint_Kind) {
	p.mu.Lock()
	p.censored[censorKey(from.id, to.id, k)] = true
	r := p.repls[string(from.id)]
	p.mu.Unlock()
	r.DropPeer(to.id)
}

func (p *partition) Uncensor(from, to *simNode, k pb.Endpoint_Kind) {
	p.mu.Lock()
	delete(p.censored, censorKey(from.id, to.id, k))
	p.mu.Unlock()
}

func (p *partition) net(self []byte) replication.NetDialer {
	p.mu.Lock()
	defer p.mu.Unlock()
	return replication.NetDialer{AllowPlain: true, Reality: p.reality[string(self)]}
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

// ensureReality gives node id a REALITY client (one for the sim's lifetime, closed in newSimWith's cleanup).
func (p *partition) ensureReality(id []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.reality[string(id)] == nil {
		p.reality[string(id)] = reality.NewClient()
	}
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

func (p *partition) dialer(self []byte, rank *replication.Ranker, l netlog.Logger) replication.Dialer {
	return &replication.MultiDialer{EP: gatedDialer{p, self}, Rank: rank, Log: l}
}

func (d gatedDialer) cut(n *pb.NodeInfo, ep *pb.Endpoint) bool {
	d.p.mu.Lock()
	defer d.p.mu.Unlock()
	return d.p.blocked[key(d.self, n.NodeId)] || d.p.censored[censorKey(d.self, n.NodeId, ep.Kind)]
}

func (d gatedDialer) DialEndpoint(ctx context.Context, n *pb.NodeInfo, ep *pb.Endpoint) (*websocket.Conn, error) {
	if d.cut(n, ep) {
		return nil, errors.New("partitioned")
	}
	c, err := d.p.net(d.self).DialEndpoint(ctx, n, ep)
	if err != nil {
		return nil, err
	}
	if d.cut(n, ep) { // Block() or Censor() happened while this dial was in flight
		c.CloseNow()
		return nil, errors.New("partitioned")
	}
	return c, nil
}
