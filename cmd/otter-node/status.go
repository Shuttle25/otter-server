package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"ottermsg/server/internal/config"
	"ottermsg/server/internal/gateway"
	"ottermsg/server/internal/metrics"
	"ottermsg/server/internal/push"
	"ottermsg/server/internal/replication"
	"ottermsg/server/internal/turnsrv"
)

// statusEvery: how often the running node rewrites status.json (D119).
const statusEvery = 15 * time.Second

// statusPath sits next to the database (the unit may write only there).
func statusPath(c *config.Config) string { return filepath.Join(c.DataDir, "status.json") }

// exitCode is an error that only sets the process exit code (its output is already printed).
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

// live holds what the running node reports on (D119).
type live struct {
	a       *app
	repl    *replication.Replicator
	gw      *gateway.Gateway
	pusher  *push.Pusher    // nil: push off
	turn    *turnsrv.Server // nil: TURN off
	started time.Time
	mu      sync.Mutex // one collection at a time (status writer, scrapes)
}

func (l *live) collect(ctx context.Context, now time.Time) metrics.Snapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := metrics.Snapshot{Version: version, AtMs: now.UnixMilli(), StartedMs: l.started.UnixMilli(), Rejected: l.gw.Rejected.Map()}
	_, s.Sessions = l.gw.Sessions()
	if st, err := l.a.st.Stats(ctx); err == nil {
		s.Users, s.Records, s.OplogSeq, s.BlobBytes = st.Users, st.Records, st.OplogSeq, st.BlobBytes
	}
	for _, p := range l.repl.Status() {
		mp := metrics.Peer{Label: p.Label, Connected: p.Connected, CaughtUp: p.CaughtUp, Backlog: -1,
			LastUpMs: p.LastUpMs, PingFailures: p.PingFailures}
		if p.Connected {
			mp.LastUpMs = s.AtMs
		}
		if n, lag, err := l.repl.Backlog(ctx, p, now); err == nil {
			mp.Backlog, mp.LagS = n, lag
		}
		s.Peers = append(s.Peers, mp)
	}
	s.DiskFree, s.DiskTotal = l.a.svc.Disk.Usage()
	s.DiskLevel, s.DiskFloor = l.a.svc.Disk.Level().String(), l.a.cfg.DiskFloorBytes
	if l.pusher != nil {
		s.PushSent, s.PushFailed, s.PushUnregistered = l.pusher.Sent.Load(), l.pusher.Failed.Load(), l.pusher.Unregistered.Load()
	}
	if l.turn != nil {
		ts := l.turn.Stats.Snapshot(now)
		s.TurnOn, s.TurnAllocs, s.TurnRelayed = true, ts.Allocations, ts.Relayed
	}
	return s
}

// listenMetrics opens the /metrics listener; the address was checked to be loopback by config (D119), and is
// checked again here so no code path can open it on a public interface.
func (l *live) listenMetrics() (*http.Server, net.Listener, error) {
	addr := l.a.cfg.Metrics.Listen
	host, _, err := net.SplitHostPort(addr)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
		return nil, nil, fmt.Errorf("metrics.listen %q is not a loopback address", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		l.collect(r.Context(), time.Now()).Prometheus(w)
	})
	return &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}, ln, nil
}

// run writes status.json every 15 s and serves /metrics on the loopback listener until ctx ends.
func (l *live) run(ctx context.Context) {
	write := func() {
		if err := l.collect(ctx, time.Now()).WriteFile(statusPath(l.a.cfg)); err != nil && ctx.Err() == nil {
			l.a.log.Warn("status file", "err", err)
		}
	}
	write()
	if l.a.cfg.Metrics.Listen != "off" {
		if srv, ln, err := l.listenMetrics(); err != nil {
			l.a.log.Warn("metrics listener off", "listen", l.a.cfg.Metrics.Listen, "err", err)
		} else {
			go func() {
				if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
					l.a.log.Warn("metrics listener stopped", "err", err)
				}
			}()
			defer srv.Close()
		}
	}
	t := time.NewTicker(statusEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			write()
		}
	}
}

// printStatus reads status.json only (no database): safe next to the running node, as root or otter.
// Exit: nil = healthy; exitCode(2) = problems ("! " lines printed); other errors = no usable status (exit 1).
func printStatus(cfgPath string, line, asJSON bool, out io.Writer) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	s, err := metrics.ReadFile(statusPath(cfg))
	if err != nil {
		return fmt.Errorf("no status from the running node (%v); is otter-node 0.10.1+ running?", err)
	}
	problems := s.Problems(time.Now())
	switch {
	case asJSON:
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if problems == nil {
			problems = []string{}
		}
		if err := enc.Encode(struct {
			metrics.Snapshot
			Problems []string `json:"problems"`
		}{s, problems}); err != nil {
			return err
		}
	case line:
		fmt.Fprintln(out, s.Line())
	default:
		fmt.Fprintf(out, "otter-node %s, up %s, %d client sessions, %d users, %d records, oplog %d\n", s.Version,
			metrics.Dur(s.AtMs-s.StartedMs), s.Sessions, s.Users, s.Records, s.OplogSeq)
		for _, p := range s.Peers {
			state := "down"
			if p.Connected {
				state = "up"
			}
			backlog := "?"
			if p.Backlog >= 0 {
				backlog = fmt.Sprint(p.Backlog)
			}
			fmt.Fprintf(out, "peer %-12s %-4s backlog=%s lag=%s ping_failures=%d\n", p.Label, state, backlog,
				metrics.Dur(p.LagS*1000), p.PingFailures)
		}
		fmt.Fprintf(out, "disk %s: %s free of %s (floor %s)\n", s.DiskLevel, metrics.Size(s.DiskFree),
			metrics.Size(s.DiskTotal), metrics.Size(s.DiskFloor))
		fmt.Fprintf(out, "push sent=%d failed=%d unregistered=%d; turn on=%v allocations=%d\n", s.PushSent,
			s.PushFailed, s.PushUnregistered, s.TurnOn, s.TurnAllocs)
	}
	if asJSON {
		if len(problems) > 0 {
			return exitCode(2)
		}
		return nil
	}
	for _, p := range problems {
		fmt.Fprintln(out, "! "+p)
	}
	if len(problems) > 0 {
		return exitCode(2)
	}
	return nil
}
