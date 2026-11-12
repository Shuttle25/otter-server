package store

import "context"

// Stats is a cheap read-only summary of the node database (otter-node stats, deploy/status.sh).
type Stats struct {
	Users, Records, OplogSeq, Blobs, BlobBytes, Peers int64
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	for _, q := range []struct {
		sql string
		dst *int64
	}{
		{"SELECT COUNT(*) FROM users", &st.Users},
		{"SELECT COUNT(*) FROM records", &st.Records},
		{"SELECT COALESCE(MAX(seq), 0) FROM oplog", &st.OplogSeq},
		{"SELECT COUNT(*) FROM blobs", &st.Blobs},
		{"SELECT COALESCE(SUM(size), 0) FROM blobs", &st.BlobBytes},
		{"SELECT COUNT(*) FROM peers", &st.Peers},
	} {
		if err := s.r.QueryRowContext(ctx, q.sql).Scan(q.dst); err != nil {
			return st, err
		}
	}
	return st, nil
}
