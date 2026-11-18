package metrics

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func snap(now time.Time) Snapshot {
	ms := now.UnixMilli()
	return Snapshot{Version: "0.10.1", AtMs: ms, StartedMs: ms - 3_600_000, Sessions: 3, OplogSeq: 120,
		Peers: []Peer{
			{Label: "fi-1", Connected: true, CaughtUp: true, Backlog: 0, LastUpMs: ms},
			{Label: "ru-1", Connected: true, Backlog: 40, LagS: 900, LastUpMs: ms},   // connected but not confirming
			{Label: "de-1", Connected: false, Backlog: -1, LastUpMs: ms - 20*60_000}, // gone for 20 min
		},
		DiskFree: 800 << 20, DiskTotal: 20 << 30, DiskLevel: "low", DiskFloor: 1 << 30,
		PushFailed: 4, TurnOn: true, TurnAllocs: 2, Rejected: map[string]int64{"req_rate": 5}}
}

func TestProblems(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	p := strings.Join(snap(now).Problems(now), "\n")
	for _, want := range []string{"peer ru-1 lag 15m (40 records)", "peer de-1 down for 20m", "disk low: 800MiB free (floor 1GiB)",
		"push failing: 4 failures, none sent since start"} {
		if !strings.Contains(p, want) {
			t.Fatalf("missing %q in:\n%s", want, p)
		}
	}
	if strings.Contains(p, "fi-1") {
		t.Fatalf("healthy peer reported:\n%s", p)
	}
	stale := snap(now).Problems(now.Add(3 * time.Minute))
	if !strings.Contains(strings.Join(stale, "\n"), "status is 3m old") {
		t.Fatalf("stale: %v", stale)
	}
	// a peer never up, 10 min after start
	s := snap(now)
	s.Peers = []Peer{{Label: "nl-1", Backlog: -1}}
	s.DiskLevel, s.PushFailed = "ok", 0
	if got := s.Problems(now); len(got) != 1 || got[0] != "peer nl-1 not connected since start (1h ago)" {
		t.Fatalf("never up: %v", got)
	}
	s.StartedMs = s.AtMs - 5*60_000 // just started: not yet a problem
	if got := s.Problems(now); len(got) != 0 {
		t.Fatalf("fresh start: %v", got)
	}
}

// A hostile peer controls only what it acks, i.e. its own backlog and lag. Absurd numbers there must not panic,
// overflow the summary or push the other problems out of the report.
func TestHostilePeerNumbersOnlyChangeItsOwnLine(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := snap(now)
	s.Peers = append(s.Peers, Peer{Label: "evil", Connected: true, Backlog: math.MaxInt64, LagS: math.MaxInt64, LastUpMs: s.AtMs},
		Peer{Label: "evil2", Connected: true, Backlog: math.MinInt64, LagS: math.MinInt64, LastUpMs: s.AtMs})
	p := strings.Join(s.Problems(now), "\n")
	for _, want := range []string{"peer ru-1 lag 15m (40 records)", "peer de-1 down for 20m", "disk low", "push failing", "peer evil lag "} {
		if !strings.Contains(p, want) {
			t.Fatalf("missing %q in:\n%s", want, p)
		}
	}
	if strings.Contains(p, "evil2") || strings.Contains(p, "lag -") {
		t.Fatalf("negative claims reported:\n%s", p)
	}
	line := s.Line()
	if !strings.Contains(line, "peers=4/5 ") || !strings.Contains(line, " disk=low ") || strings.Contains(line, "backlog=-") {
		t.Fatalf("line: %s", line)
	}
	var b bytes.Buffer
	s.Prometheus(&b)
	if !strings.Contains(b.String(), `otter_peer_backlog_records{peer="ru-1"} 40`) {
		t.Fatalf("honest peer lost:\n%s", b.String())
	}
}

func TestLineAndPrometheus(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := snap(now)
	if got := s.Line(); got != "peers=2/3 lag=15m backlog=40 disk=low free=800MiB sessions=3 push=0/4 turn=2 rejected=5" {
		t.Fatalf("line: %s", got)
	}
	var b bytes.Buffer
	s.Prometheus(&b)
	for _, want := range []string{`otter_peer_backlog_records{peer="ru-1"} 40`, `otter_peer_lag_seconds{peer="ru-1"} 900`,
		`otter_peer_connected{peer="de-1"} 0`, "otter_disk_free_bytes 838860800", "otter_disk_low 1",
		"otter_push_failed_total 4", "otter_turn_allocations 2", `otter_rejected_total{kind="req_rate"} 5`,
		"# TYPE otter_push_failed_total counter", `otter_build_info{version="0.10.1"} 1`} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("missing %q in:\n%s", want, b.String())
		}
	}
	if strings.Count(b.String(), "# TYPE otter_peer_connected ") != 1 {
		t.Fatalf("TYPE repeated:\n%s", b.String())
	}
	var e bytes.Buffer
	(Snapshot{Peers: []Peer{{Label: "a\"b\\c\nd"}}}).Prometheus(&e)
	if !strings.Contains(e.String(), `otter_peer_connected{peer="a\"b\\c\nd"} 0`) {
		t.Fatalf("label escaping:\n%s", e.String())
	}
}

func TestDurAndSize(t *testing.T) {
	for ms, want := range map[int64]string{-5: "0s", 0: "0s", 45_000: "45s", 14 * 60_000: "14m", 3 * 3_600_000: "3h",
		72 * 3_600_000: "3d", math.MaxInt64: "106751991167d"} {
		if got := Dur(ms); got != want {
			t.Errorf("Dur(%d) = %s, want %s", ms, got, want)
		}
	}
	for b, want := range map[int64]string{12 << 10: "12KiB", 800 << 20: "800MiB", 1 << 30: "1GiB", 3 << 29: "1.5GiB", 20 << 30: "20GiB"} {
		if got := Size(b); got != want {
			t.Errorf("Size(%d) = %s, want %s", b, got, want)
		}
	}
}

func TestFileRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "status.json")
	s := snap(time.Now())
	if err := s.WriteFile(p); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v %v", fi, err)
	}
	got, err := ReadFile(p)
	if err != nil || got.Line() != s.Line() {
		t.Fatalf("%v %s", err, got.Line())
	}
	if _, err := ReadFile(filepath.Join(t.TempDir(), "none.json")); err == nil {
		t.Fatal("missing file accepted")
	}
}
