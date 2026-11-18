package service

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"syscall"
	"time"
)

// DiskLevel says which writes the node still accepts (D118).
type DiskLevel int32

const (
	DiskOK       DiskLevel = iota
	DiskLow                // < floor: no blobs, chunks or backups
	DiskCritical           // < floor/4: no client submissions either
	DiskFull               // < DiskReserve: no replicated records either
)

// DiskReserve is kept free for SQLite (WAL, checkpoints) whatever the floor.
const DiskReserve = 64 << 20

func (l DiskLevel) String() string {
	switch l {
	case DiskOK:
		return "ok"
	case DiskLow:
		return "low"
	case DiskCritical:
		return "critical"
	case DiskFull:
		return "full"
	}
	return fmt.Sprintf("DiskLevel(%d)", int32(l))
}

// DiskGuard measures free space under Dir. A nil guard allows everything.
type DiskGuard struct {
	Dir   string
	Floor int64                                           // 0 = only the DiskReserve level
	Free  func(dir string) (free, total int64, err error) // nil = statfs
	level atomic.Int32
	free  atomic.Int64
	total atomic.Int64
}

// statfs reports the space available to unprivileged users and the file system size.
func statfs(dir string) (int64, int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), int64(st.Blocks) * int64(st.Bsize), nil
}

// Check measures once and returns the new level (a failed measurement keeps the old level).
func (g *DiskGuard) Check() DiskLevel {
	if g == nil {
		return DiskOK
	}
	f := g.Free
	if f == nil {
		f = statfs
	}
	free, total, err := f(g.Dir)
	if err != nil {
		return g.Level()
	}
	g.free.Store(free)
	g.total.Store(total)
	l := DiskOK
	switch {
	case free < DiskReserve:
		l = DiskFull
	case g.Floor > 0 && free < g.Floor/4:
		l = DiskCritical
	case g.Floor > 0 && free < g.Floor:
		l = DiskLow
	}
	g.level.Store(int32(l))
	return l
}

// Level is the level of the last measurement.
func (g *DiskGuard) Level() DiskLevel {
	if g == nil {
		return DiskOK
	}
	return DiskLevel(g.level.Load())
}

// Usage is the last measurement (bytes).
func (g *DiskGuard) Usage() (free, total int64) {
	if g == nil {
		return 0, 0
	}
	return g.free.Load(), g.total.Load()
}

// Run re-measures every `every` and logs level changes at warn until ctx ends.
func (g *DiskGuard) Run(ctx context.Context, every time.Duration, log *slog.Logger) {
	if g == nil {
		return
	}
	prev := g.Check()
	if prev != DiskOK {
		free, _ := g.Usage()
		log.Warn("disk level", "level", prev.String(), "free_bytes", free, "floor_bytes", g.Floor)
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if l := g.Check(); l != prev {
			free, _ := g.Usage()
			log.Warn("disk level changed", "from", prev.String(), "to", l.String(), "free_bytes", free, "floor_bytes", g.Floor)
			prev = l
		}
	}
}

// errDiskLow is what a refused write answers (STATUS_RETRY_LATER at the gateway).
var errDiskLow = fmt.Errorf("%w: node storage low", ErrRetryLater)

// diskRefuses returns ErrRetryLater when free space has fallen to level `at` or below it (D118).
func (s *Service) diskRefuses(at DiskLevel) error {
	if s.Disk.Level() >= at {
		if s.Rejected != nil {
			s.Rejected.Disk.Add(1)
		}
		return errDiskLow
	}
	return nil
}
