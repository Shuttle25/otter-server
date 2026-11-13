package netlog

import (
	"context"

	"ottermsg/server/internal/store"
)

// StoreLogger writes observations to the node database (best effort).
type StoreLogger struct{ S *store.Store }

func (l StoreLogger) Add(ctx context.Context, e Entry) {
	_ = l.S.NetlogAdd(context.WithoutCancel(ctx), store.NetlogEntry{Peer: e.Peer, Endpoint: e.Endpoint,
		Direction: e.Direction, Result: e.Result, Class: string(e.Class), Detail: truncate(e.Detail, 200)})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
