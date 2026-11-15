package service

import (
	"context"
	"time"
)

// RunJanitor expires data past retention every `every` until ctx ends.
func (s *Service) RunJanitor(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	go s.runSweeper(ctx)
	for {
		st, err := s.Store.Expire(ctx, s.Now().UnixMilli())
		if err != nil {
			s.Log.Warn("janitor", "err", err)
		} else if st.Envelopes+st.Acks+st.Tombstones+st.Oplog+st.Blobs+st.Compacted > 0 {
			s.Log.Info("janitor", "envelopes", st.Envelopes, "acks", st.Acks, "tombstones", st.Tombstones, "oplog", st.Oplog, "blobs", st.Blobs, "compacted", st.Compacted)
		}
		s.kickSweep()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
