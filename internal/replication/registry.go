package replication

import (
	"bytes"
	"sync"
)

type registry struct {
	mu     sync.Mutex
	byPeer map[string]*session
}

// add registers s; returns false if s lost the tie-break (caller closes it).
func (g *registry) add(s *session) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	k := string(s.peer)
	old := g.byPeer[k]
	if old == nil || bytes.Compare(s.dialer, old.dialer) <= 0 {
		if old != nil {
			old.close()
		}
		g.byPeer[k] = s
		return true
	}
	return false
}

func (g *registry) remove(s *session) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.byPeer[string(s.peer)] == s {
		delete(g.byPeer, string(s.peer))
	}
}

func (g *registry) has(peer []byte) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.byPeer[string(peer)] != nil
}

// get returns the live session with peer, whichever side dialed it, or nil.
func (g *registry) get(peer []byte) *session {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.byPeer[string(peer)]
}

// all returns the live sessions.
func (g *registry) all() []*session {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]*session, 0, len(g.byPeer))
	for _, s := range g.byPeer {
		out = append(out, s)
	}
	return out
}
