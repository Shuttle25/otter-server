package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestNetlogMergeAndCap(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	e := NetlogEntry{Peer: "eeee", Endpoint: "reality:443", Direction: "out", Result: "ok", Class: "ok"}
	for i := 0; i < 3; i++ {
		if err := s.NetlogAdd(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	fail := e
	fail.Result, fail.Class, fail.Detail = "fail", "timeout", "dial tcp: i/o timeout"
	if err := s.NetlogAdd(ctx, fail); err != nil {
		t.Fatal(err)
	}
	if err := s.NetlogAdd(ctx, e); err != nil {
		t.Fatal(err)
	}
	got, err := s.Netlog(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Count != 1 || got[0].Class != "ok" || got[1].Class != "timeout" || got[2].Count != 3 {
		t.Fatalf("lines: %+v", got)
	}
	other := e
	for i := 0; i < 250; i++ {
		other.Endpoint = fmt.Sprintf("wss:%d", i) // distinct keys: no merging
		if err := s.NetlogAdd(ctx, other); err != nil {
			t.Fatal(err)
		}
	}
	all, _ := s.Netlog(ctx, 1000)
	if len(all) != NetlogMax {
		t.Fatalf("cap: %d lines", len(all))
	}
	if all[0].Endpoint != "wss:249" {
		t.Fatalf("newest first: %s", all[0].Endpoint)
	}
}

func TestJanitorPurgesOldNetlogLines(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	const day = int64(24 * 60 * 60 * 1000)
	now := int64(1_800_000_000_000)
	at := now - 8*day
	s.now = func() time.Time { return time.UnixMilli(at) }
	rejected := NetlogEntry{Peer: "198.51.100.7", Endpoint: "wss", Direction: "in", Result: "fail", Class: "handshake",
		Detail: "peer: node 01 not in manifest"}
	if err := s.NetlogAdd(ctx, rejected); err != nil {
		t.Fatal(err)
	}
	at = now - 6*day
	recent := rejected
	recent.Peer = "198.51.100.8"
	if err := s.NetlogAdd(ctx, recent); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Expire(ctx, now); err != nil {
		t.Fatal(err)
	}
	got, err := s.Netlog(ctx, 10)
	if err != nil || len(got) != 1 || got[0].Peer != "198.51.100.8" {
		t.Fatalf("after expire: %+v %v", got, err)
	}
}
