package replication

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"ottermsg/server/internal/service"
)

// ErrNoPeerHasChunk: no connected peer answered with a valid copy of the chunk.
var ErrNoPeerHasChunk = errors.New("no peer has the chunk")

var (
	peerChunkTimeout = 10 * time.Second // per peer; an older build ignores the frame and times out
	pullRetryMin     = time.Second       // a blob nobody had: retry after this, doubling…
	pullRetryMax     = 30 * time.Second  // …up to this
	pullIdle         = 30 * time.Second  // rescan at least this often
)

type lastPeers struct {
	mu sync.Mutex
	m  map[string][]byte // blob key → peer that last answered
}

func (l *lastPeers) get(key []byte) []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.m[string(key)]
}

func (l *lastPeers) set(key, peer []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string][]byte{}
	}
	l.m[string(key)] = peer
}

func (l *lastPeers) drop(key []byte) { l.mu.Lock(); delete(l.m, string(key)); l.mu.Unlock() }

// FetchChunk asks live peer sessions one by one (the peer that last answered for this blob first) and returns the
// first answer that passes ok (service.ChunkFetcher).
func (r *Replicator) FetchChunk(ctx context.Context, key []byte, idx uint32, ok func([]byte) bool) ([]byte, error) {
	sessions := r.reg.all()
	if last := r.last.get(key); last != nil {
		for i, s := range sessions {
			if string(s.peer) == string(last) {
				sessions[0], sessions[i] = sessions[i], sessions[0]
				break
			}
		}
	}
	for _, s := range sessions {
		pctx, cancel := context.WithTimeout(ctx, peerChunkTimeout)
		data, err := s.getChunk(pctx, key, idx)
		cancel()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil || data == nil {
			continue
		}
		if !ok(data) {
			r.log.Warn("peer sent a chunk that doesn't match the blob meta", "peer", hex.EncodeToString(s.peer),
				"blob", hex.EncodeToString(key), "idx", idx)
			continue
		}
		r.last.set(key, s.peer)
		return data, nil
	}
	return nil, ErrNoPeerHasChunk
}

// limiter keeps the average transfer rate at or below rate bytes/s; 0 = unlimited.
type limiter struct {
	rate  float64
	next  time.Time
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

func newLimiter(bytesPerSec int64) *limiter {
	return &limiter{rate: float64(bytesPerSec), now: time.Now, sleep: sleepCtx}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *limiter) wait(ctx context.Context, n int) error {
	if l.rate <= 0 {
		return nil
	}
	now := l.now()
	if l.next.Before(now) {
		l.next = now
	}
	l.next = l.next.Add(time.Duration(float64(n) / l.rate * float64(time.Second)))
	if d := l.next.Sub(now); d > 0 {
		return l.sleep(ctx, d)
	}
	return nil
}

// RunPuller copies missing chunks of every live blob from peers in the background (D45) until ctx ends.
func (r *Replicator) RunPuller(ctx context.Context, bytesPerSec int64) {
	lim := newLimiter(bytesPerSec)
	type retry struct {
		at    time.Time
		delay time.Duration
	}
	skip := map[string]retry{}
	for ctx.Err() == nil {
		changed := r.st.Changed()
		gaps, err := r.st.IncompleteBlobs(ctx, 16)
		if err != nil && ctx.Err() == nil {
			r.log.Warn("blob puller", "err", err)
		}
		progressed := false
		live := map[string]bool{}
		for _, g := range gaps {
			k := string(g.Key)
			live[k] = true
			if s, ok := skip[k]; ok && time.Now().Before(s.at) {
				continue
			}
			b, err := r.st.Blob(ctx, g.Key)
			if err != nil {
				continue
			}
			failed := false
			for _, idx := range g.Missing {
				if r.svc.Disk.Level() >= service.DiskLow { // D118: StoreChunk would refuse; don't fetch for nothing
					failed = true
					break
				}
				data, err := r.FetchChunk(ctx, g.Key, idx, func(d []byte) bool { return service.ChunkOK(b, idx, d) })
				if err == nil {
					err = r.svc.StoreChunk(ctx, b, idx, data)
				}
				if err != nil {
					failed = true
					break
				}
				progressed = true
				if lim.wait(ctx, len(data)) != nil {
					return
				}
			}
			if failed {
				d := pullRetryMin
				if s, ok := skip[k]; ok {
					d = min(s.delay*2, pullRetryMax)
				}
				skip[k] = retry{time.Now().Add(d), d}
			} else {
				delete(skip, k)
				r.last.drop(g.Key)
			}
		}
		for k := range skip {
			if !live[k] {
				delete(skip, k)
			}
		}
		if progressed {
			continue
		}
		wait := pullIdle
		for _, s := range skip {
			if d := time.Until(s.at); d < wait {
				wait = max(d, 0)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-changed:
		case <-time.After(wait):
		}
	}
}
