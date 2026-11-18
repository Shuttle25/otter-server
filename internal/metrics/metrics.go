// Package metrics: the node's health snapshot (status.json, otter-node status) and its Prometheus text form (D119).
package metrics

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
	"time"
)

// Thresholds for Problems (D119).
const (
	StaleAfterMs  = 60_000
	PeerDownAfter = 10 * 60_000
	LagLimitS     = 10 * 60
	PushFailAlarm = 3
)

type Peer struct {
	Label        string `json:"label"`
	Connected    bool   `json:"connected"`  // a session is up, whichever side dialed (D132)
	CaughtUp     bool   `json:"caught_up"`  // we received the peer's whole oplog
	Backlog      int64  `json:"backlog"`    // our records the peer has not confirmed; -1 = not known yet
	LagS         int64  `json:"lag_s"`      // age of the oldest of them
	LastUpMs     int64  `json:"last_up_ms"` // last time a session was up (= at_ms while connected); 0 = never since start
	PingFailures int64  `json:"ping_failures"`
}

type Snapshot struct {
	Version          string           `json:"version"`
	AtMs             int64            `json:"at_ms"`
	StartedMs        int64            `json:"started_ms"`
	Sessions         int              `json:"client_sessions"`
	Users            int64            `json:"users"`
	Records          int64            `json:"records"`
	OplogSeq         int64            `json:"oplog_seq"`
	BlobBytes        int64            `json:"blob_bytes"`
	Peers            []Peer           `json:"peers"`
	DiskFree         int64            `json:"disk_free"`
	DiskTotal        int64            `json:"disk_total"`
	DiskLevel        string           `json:"disk_level"`
	DiskFloor        int64            `json:"disk_floor"`
	PushSent         int64            `json:"push_sent"`
	PushFailed       int64            `json:"push_failed"`
	PushUnregistered int64            `json:"push_unregistered"`
	TurnOn           bool             `json:"turn_on"`
	TurnAllocs       int64            `json:"turn_allocations"`
	TurnRelayed      int64            `json:"turn_relayed_bytes"`
	Rejected         map[string]int64 `json:"rejected"`
}

// WriteFile replaces path atomically (0600: it names peers and counts users).
func (s Snapshot) WriteFile(path string) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := path + ".new"
	_ = os.Remove(tmp) // a leftover keeps its mode on rewrite
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func ReadFile(path string) (Snapshot, error) {
	var s Snapshot
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}

// Dur prints milliseconds as 45s, 14m, 3h, 2d (negative as 0s).
func Dur(ms int64) string { return durS(max(ms, 0) / 1000) }

func durS(s int64) string {
	s = max(s, 0)
	switch {
	case s < 60:
		return fmt.Sprintf("%ds", s)
	case s < 3600:
		return fmt.Sprintf("%dm", s/60)
	case s < 48*3600:
		return fmt.Sprintf("%dh", s/3600)
	default:
		return fmt.Sprintf("%dd", s/86400)
	}
}

// Size prints bytes as 800MiB, 1GiB, 1.5GiB, 12KiB.
func Size(b int64) string {
	switch {
	case b >= 1<<30 && b%(1<<30) == 0 || b >= 10<<30:
		return fmt.Sprintf("%dGiB", b>>30)
	case b >= 1<<30:
		return fmt.Sprintf("%.1fGiB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%dMiB", b>>20)
	default:
		return fmt.Sprintf("%dKiB", max(b, 0)>>10)
	}
}

// add saturates instead of wrapping (a peer's claims are only clamped by the collector).
func add(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// Problems lists what needs the admin's attention at time now (D119). Each peer adds only its own lines.
func (s Snapshot) Problems(now time.Time) []string {
	var p []string
	if age := now.UnixMilli() - s.AtMs; age > StaleAfterMs {
		p = append(p, fmt.Sprintf("status is %s old: is otter-node running?", Dur(age)))
	}
	for _, x := range s.Peers {
		switch {
		case !x.Connected && x.LastUpMs > 0 && s.AtMs-x.LastUpMs > PeerDownAfter:
			p = append(p, fmt.Sprintf("peer %s down for %s", x.Label, Dur(s.AtMs-x.LastUpMs)))
		case !x.Connected && x.LastUpMs <= 0 && s.AtMs-s.StartedMs > PeerDownAfter:
			p = append(p, fmt.Sprintf("peer %s not connected since start (%s ago)", x.Label, Dur(s.AtMs-s.StartedMs)))
		}
		if x.LagS > LagLimitS {
			p = append(p, fmt.Sprintf("peer %s lag %s (%d records)", x.Label, durS(x.LagS), max(x.Backlog, 0)))
		}
	}
	if s.DiskLevel != "" && s.DiskLevel != "ok" {
		p = append(p, fmt.Sprintf("disk %s: %s free (floor %s)", s.DiskLevel, Size(s.DiskFree), Size(s.DiskFloor)))
	}
	if s.PushFailed >= PushFailAlarm && s.PushSent == 0 {
		p = append(p, fmt.Sprintf("push failing: %d failures, none sent since start", s.PushFailed))
	}
	return p
}

// Line is the one-line summary for deploy/status.sh.
func (s Snapshot) Line() string {
	up, backlog, lag := 0, int64(0), int64(0)
	for _, x := range s.Peers {
		if x.Connected {
			up++
		}
		backlog = add(backlog, max(x.Backlog, 0))
		lag = max(lag, x.LagS)
	}
	var rej int64
	for _, v := range s.Rejected {
		rej = add(rej, max(v, 0))
	}
	level := s.DiskLevel
	if level == "" {
		level = "unknown"
	}
	return fmt.Sprintf("peers=%d/%d lag=%s backlog=%d disk=%s free=%s sessions=%d push=%d/%d turn=%d rejected=%d",
		up, len(s.Peers), durS(lag), backlog, level, Size(s.DiskFree), s.Sessions, s.PushSent, s.PushFailed,
		s.TurnAllocs, rej)
}

type promWriter struct {
	w    io.Writer
	seen map[string]bool
}

// labelValue escapes per the text exposition format: backslash, double quote and newline.
var labelValue = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func (p *promWriter) m(name, typ, help string, v int64, labels ...string) {
	if !p.seen[name] {
		fmt.Fprintf(p.w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
		p.seen[name] = true
	}
	l := ""
	if len(labels) > 0 {
		var parts []string
		for i := 0; i+1 < len(labels); i += 2 {
			parts = append(parts, labels[i]+`="`+labelValue.Replace(labels[i+1])+`"`)
		}
		l = "{" + strings.Join(parts, ",") + "}"
	}
	fmt.Fprintf(p.w, "%s%s %d\n", name, l, v)
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// Prometheus writes the text exposition format (version 0.0.4); samples of one metric stay together.
func (s Snapshot) Prometheus(w io.Writer) {
	p := &promWriter{w: w, seen: map[string]bool{}}
	p.m("otter_up", "gauge", "The node process is running.", 1)
	p.m("otter_build_info", "gauge", "Version of otter-node.", 1, "version", s.Version)
	p.m("otter_start_time_seconds", "gauge", "Process start time.", s.StartedMs/1000)
	p.m("otter_client_sessions", "gauge", "Logged-in client sessions.", int64(s.Sessions))
	p.m("otter_users", "gauge", "Known accounts.", s.Users)
	p.m("otter_records", "gauge", "Stored records.", s.Records)
	p.m("otter_oplog_seq", "gauge", "Highest oplog sequence number.", s.OplogSeq)
	p.m("otter_blob_bytes", "gauge", "Bytes of live blobs.", s.BlobBytes)
	peer := func(name, typ, help string, v func(Peer) int64) {
		for _, x := range s.Peers {
			p.m(name, typ, help, v(x), "peer", x.Label)
		}
	}
	peer("otter_peer_connected", "gauge", "A replication session with the peer is up (either side dialed).",
		func(x Peer) int64 { return b2i(x.Connected) })
	peer("otter_peer_caught_up", "gauge", "We received the peer's whole oplog.", func(x Peer) int64 { return b2i(x.CaughtUp) })
	peer("otter_peer_backlog_records", "gauge", "Our records the peer has not confirmed (-1 unknown).",
		func(x Peer) int64 { return x.Backlog })
	peer("otter_peer_lag_seconds", "gauge", "Age of the oldest record the peer has not confirmed.", func(x Peer) int64 { return x.LagS })
	peer("otter_peer_ping_failures_total", "counter", "Sessions ended by a missing pong.", func(x Peer) int64 { return x.PingFailures })
	p.m("otter_disk_free_bytes", "gauge", "Free bytes under data_dir.", s.DiskFree)
	p.m("otter_disk_total_bytes", "gauge", "Size of the data_dir file system.", s.DiskTotal)
	p.m("otter_disk_floor_bytes", "gauge", "Configured free-space floor.", s.DiskFloor)
	p.m("otter_disk_low", "gauge", "Free space is below the floor (writes refused).", b2i(s.DiskLevel != "" && s.DiskLevel != "ok"))
	p.m("otter_push_sent_total", "counter", "Push wake-ups sent.", s.PushSent)
	p.m("otter_push_failed_total", "counter", "Push wake-ups that failed.", s.PushFailed)
	p.m("otter_push_unregistered_total", "counter", "Push tokens dropped as unregistered.", s.PushUnregistered)
	p.m("otter_turn_enabled", "gauge", "The TURN relay runs.", b2i(s.TurnOn))
	p.m("otter_turn_allocations", "gauge", "Live TURN allocations.", s.TurnAllocs)
	p.m("otter_turn_relayed_bytes_total", "counter", "Bytes relayed by TURN.", s.TurnRelayed)
	kinds := make([]string, 0, len(s.Rejected))
	for k := range s.Rejected {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		p.m("otter_rejected_total", "counter", "Requests refused by a limit.", s.Rejected[k], "kind", k)
	}
}
