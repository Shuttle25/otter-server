package turnsrv

import (
	"encoding/json"
	"os"
	"sync/atomic"
	"time"
)

// Stats are live counters of this process; WriteFile publishes them for `otter-node stats` (a separate process).
type Stats struct {
	Allocations atomic.Int64
	Relayed     atomic.Int64 // bytes, both directions
	Dropped     atomic.Int64 // packets (rate cap, own ports)
}

type Snapshot struct {
	Allocations int64 `json:"allocations"`
	Relayed     int64 `json:"relayed_bytes"`
	Dropped     int64 `json:"dropped_packets"`
	AtMs        int64 `json:"at_ms"`
}

func (s *Stats) Snapshot(now time.Time) Snapshot {
	return Snapshot{s.Allocations.Load(), s.Relayed.Load(), s.Dropped.Load(), now.UnixMilli()}
}

// WriteFile replaces path atomically with the current snapshot.
func (s *Stats) WriteFile(path string, now time.Time) error {
	b, _ := json.Marshal(s.Snapshot(now))
	tmp := path + ".new"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadSnapshot returns the snapshot if it is younger than maxAge.
func ReadSnapshot(path string, now time.Time, maxAge time.Duration) (Snapshot, bool) {
	var s Snapshot
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &s) != nil || now.Sub(time.UnixMilli(s.AtMs)) > maxAge {
		return Snapshot{}, false
	}
	return s, true
}
