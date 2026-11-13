package turnsrv

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStatsFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "turn.stats")
	s := &Stats{}
	s.Allocations.Add(2)
	s.Relayed.Add(1234)
	s.Dropped.Add(5)
	now := time.Unix(1_800_000_000, 0)
	if err := s.WriteFile(p, now); err != nil {
		t.Fatal(err)
	}
	got, ok := ReadSnapshot(p, now.Add(5*time.Second), time.Minute)
	if !ok || got != (Snapshot{2, 1234, 5, now.UnixMilli()}) {
		t.Fatalf("%+v %v", got, ok)
	}
	if _, ok := ReadSnapshot(p, now.Add(2*time.Minute), time.Minute); ok {
		t.Fatal("stale snapshot returned")
	}
	if _, ok := ReadSnapshot(p+".missing", now, time.Minute); ok {
		t.Fatal("missing file returned a snapshot")
	}
}
