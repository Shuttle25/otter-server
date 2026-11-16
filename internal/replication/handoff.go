package replication

import (
	"context"
	"encoding/hex"
	"time"

	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/service"
)

var (
	handoffEvery  = time.Minute
	handoffMinAge = time.Hour // an unreferenced backup blob waits this long: backup.publish follows the upload
)

func holdsFrame(req uint64, held bool) *pb.PeerFrame {
	return &pb.PeerFrame{Kind: &pb.PeerFrame_Holds{Holds: &pb.PeerHolds{Req: req, Held: held}}}
}

// holds asks this peer whether it holds key (D113); an older peer never answers and ctx ends.
func (s *session) holds(ctx context.Context, key []byte) (bool, error) {
	id := s.reqID.Add(1)
	ch := make(chan bool, 1)
	s.pmu.Lock()
	s.hpending[id] = ch
	s.pmu.Unlock()
	defer func() { s.pmu.Lock(); delete(s.hpending, id); s.pmu.Unlock() }()
	s.send(&pb.PeerFrame{Kind: &pb.PeerFrame_HoldsQuery{HoldsQuery: &pb.PeerHoldsQuery{Req: id, RecordKey: key}}})
	select {
	case h := <-ch:
		return h, nil
	case <-ctx.Done():
		return false, ctx.Err()
	case <-s.ctx.Done():
		return false, s.ctx.Err()
	}
}

// confirmationsNeeded: distinct nodes without no_backups that must hold a backup before a node with no_backups
// drops its copy: min(2, their number) (D113, owner Q3).
func confirmationsNeeded(m *pb.Manifest) int {
	n := 0
	for _, x := range m.GetNodes() {
		if !x.NoBackups {
			n++
		}
	}
	return min(2, n)
}

// RunBackupHandoff: on a node marked no_backups, deletes the backups phones uploaded here once enough other nodes
// hold them (D113). The queries ride on the existing peer sessions, whichever side dialed (D132).
func (r *Replicator) RunBackupHandoff(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(handoffEvery):
		}
		r.handoffOnce(ctx)
	}
}

func (r *Replicator) handoffOnce(ctx context.Context) {
	m := r.svc.CurrentManifest()
	if m == nil || !service.NodeNoBackups(m, r.svc.NodeID) {
		return
	}
	need := confirmationsNeeded(m)
	if need == 0 {
		return // no node may keep backups: keep ours rather than lose them
	}
	keys, err := r.st.LocalBackupItems(ctx, time.Now().Add(-handoffMinAge).UnixMilli())
	if err != nil {
		r.log.Warn("backup handoff", "err", err)
		return
	}
	for _, k := range keys {
		got := 0
		for _, s := range r.reg.all() {
			if service.NodeNoBackups(m, s.peer) {
				continue
			}
			qctx, cancel := context.WithTimeout(ctx, peerChunkTimeout)
			held, err := s.holds(qctx, k)
			cancel()
			if err == nil && held {
				got++
			}
			if got >= need {
				break
			}
		}
		if ctx.Err() != nil {
			return
		}
		if got < need {
			continue
		}
		if err := r.svc.DropBackupCopy(ctx, k); err != nil {
			r.log.Warn("backup handoff drop", "key", hex.EncodeToString(k), "err", err)
		} else {
			r.log.Info("backup handed off", "key", hex.EncodeToString(k), "confirmations", got)
		}
	}
}
