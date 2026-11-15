package service

import (
	"sync"
	"time"
)

// windowCounter counts events per key in a sliding window (in memory; a restart forgets it).
type windowCounter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

// allow records one event for key and reports true when fewer than limit events happened within window before now;
// a refused event is not recorded.
func (w *windowCounter) allow(now time.Time, window time.Duration, key string, limit int) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.hits == nil {
		w.hits = map[string][]time.Time{}
	}
	for k, ts := range w.hits { // drop old events everywhere so the map stays small
		i := 0
		for i < len(ts) && now.Sub(ts[i]) >= window {
			i++
		}
		if i == len(ts) {
			delete(w.hits, k)
		} else {
			w.hits[k] = ts[i:]
		}
	}
	if len(w.hits[key]) >= limit {
		return false
	}
	w.hits[key] = append(w.hits[key], now)
	return true
}
