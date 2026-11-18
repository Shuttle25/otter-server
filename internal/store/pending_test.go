package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// PendingEnvelopeBytes counts the author's stored, unexpired envelopes and nothing else (D117).
func TestPendingEnvelopeBytes(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	now := int64(1_800_000_000_000)
	s.now = func() time.Time { return time.UnixMilli(now) }
	alice, bob, carol := r16(), r16(), r16()
	putEnvelope(t, s, alice, bob, now-1000, 0)
	putEnvelope(t, s, alice, bob, now-1000, now+60_000)
	putEnvelope(t, s, alice, bob, now-180_000, now-60_000) // expired, not purged yet: delivered to nobody any more
	putEnvelope(t, s, carol, bob, now-1000, 0)
	var want int64
	if err := s.r.QueryRowContext(ctx, `SELECT SUM(length(raw)) FROM records WHERE author=? AND expires_ms <> ?`,
		alice, now-60_000).Scan(&want); err != nil || want == 0 {
		t.Fatal(want, err)
	}
	if got, err := s.PendingEnvelopeBytes(ctx, alice); err != nil || got != want {
		t.Fatalf("alice: %d %v, want %d", got, err, want)
	}
	if got, err := s.PendingEnvelopeBytes(ctx, bob); err != nil || got != 0 {
		t.Fatalf("bob: %d %v", got, err)
	}
	// the lookup is indexed by (type, author) — records_type_author, M9.2 — not a table scan
	rows, err := s.r.QueryContext(ctx, `EXPLAIN QUERY PLAN `+pendingQuery, alice, 7, now)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if p := strings.Join(plan, "; "); !strings.Contains(p, "INDEX records_type_author") {
		t.Fatalf("query plan: %s", p)
	}
}
