package service

import (
	"context"
	"time"
)

// RunJanitor expires data past retention every `every` until ctx ends.
func (s *Service) RunJanitor(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		st, err := s.Store.Expire(ctx, s.Now().UnixMilli())
		if err != nil {
			s.Log.Warn("janitor", "err", err)
		} else if st.Envelopes+st.Acks+st.Tombstones+st.Oplog > 0 {
			s.Log.Info("janitor", "envelopes", st.Envelopes, "acks", st.Acks, "tombstones", st.Tombstones, "oplog", st.Oplog)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
