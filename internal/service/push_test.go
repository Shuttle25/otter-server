package service

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	pb "ottermsg/server/internal/proto/otterv1"
)

func TestPushDuty(t *testing.T) {
	a, b, c := []byte("aaaaaaaaaaaaaaaa"), []byte("bbbbbbbbbbbbbbbb"), []byte("cccccccccccccccc")
	m := &pb.Manifest{Version: 2, Nodes: []*pb.NodeInfo{{NodeId: a}, {NodeId: b, PushCapable: true}, {NodeId: c, PushCapable: true}}}
	svc := func(self []byte, waker bool) *Service {
		s := &Service{NodeID: self, manifest: m}
		if waker {
			s.Waker = nopWaker{}
		}
		return s
	}
	cases := []struct {
		name string
		s    *Service
		from []byte
		want bool
	}{
		{"local, capable", svc(b, true), nil, true},
		{"local, not in manifest as capable", svc(a, true), nil, false},
		{"local, capable but no key", svc(b, false), nil, false},
		{"replicated from non-capable a: first capable (b) pushes", svc(b, true), a, true},
		{"replicated from non-capable a: c is not first", svc(c, true), a, false},
		{"replicated from capable b: origin pushed", svc(c, true), b, false},
	}
	for _, tc := range cases {
		if got := tc.s.pushDuty(tc.from); got != tc.want {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
}

type nopWaker struct{}

func (nopWaker) Wake(_ context.Context, _ []byte, _ uint32)     {}
func (nopWaker) WakeCall(_ context.Context, _ []byte, _ uint32) {}

type wakeRec struct{ woke, calls []string }

func (w *wakeRec) Wake(_ context.Context, user []byte, _ uint32) {
	w.woke = append(w.woke, string(user))
}
func (w *wakeRec) WakeCall(_ context.Context, user []byte, _ uint32) {
	w.calls = append(w.calls, string(user))
}

type onlineNotifier struct {
	nopNotifier
	online string
}

func (o onlineNotifier) Online(user []byte, _ uint32) bool { return string(user) == o.online }

func TestMaybePush(t *testing.T) {
	self := []byte("bbbbbbbbbbbbbbbb")
	now := time.UnixMilli(1_800_000_000_000)
	w := &wakeRec{}
	s := &Service{NodeID: self, Waker: w, Now: func() time.Time { return now }, Notify: onlineNotifier{online: "bob"},
		manifest: &pb.Manifest{Nodes: []*pb.NodeInfo{{NodeId: self, PushCapable: true}}}}
	env := func(urgent bool) *pb.Envelope {
		return &pb.Envelope{Urgent: urgent, Recipients: []*pb.Recipient{{User: []byte("bob"), Device: 1}, {User: []byte("eve"), Device: 1}}}
	}
	fresh := &pb.RecordBody{CreatedMs: now.Add(-time.Minute).UnixMilli()}
	s.maybePush(context.Background(), fresh, env(false), nil)
	s.maybePush(context.Background(), &pb.RecordBody{CreatedMs: now.Add(-11 * time.Minute).UnixMilli()}, env(true), nil)
	if len(w.woke) != 0 {
		t.Fatalf("non-urgent or stale envelope pushed: %q", w.woke)
	}
	s.maybePush(context.Background(), fresh, env(true), nil)
	if len(w.woke) != 1 || w.woke[0] != "eve" || len(w.calls) != 0 {
		t.Fatalf("woke %q calls %q, want only the offline recipient eve via Wake", w.woke, w.calls)
	}
}

func TestMaybePushCall(t *testing.T) {
	self := []byte("bbbbbbbbbbbbbbbb")
	now := time.UnixMilli(1_800_000_000_000)
	var logs bytes.Buffer
	w := &wakeRec{}
	s := &Service{NodeID: self, Waker: w, Now: func() time.Time { return now }, Notify: onlineNotifier{online: "bob"},
		Log:      slog.New(slog.NewTextHandler(&logs, nil)),
		manifest: &pb.Manifest{Nodes: []*pb.NodeInfo{{NodeId: self, PushCapable: true}}}}
	env := &pb.Envelope{Urgent: true, Recipients: []*pb.Recipient{{User: []byte("bob"), Device: 1}, {User: []byte("eve"), Device: 1}}}
	created := now.Add(-time.Second).UnixMilli()
	body := func(ttl time.Duration) *pb.RecordBody {
		b := &pb.RecordBody{CreatedMs: created}
		if ttl != 0 {
			b.ExpiresMs = created + ttl.Milliseconds()
		}
		return b
	}

	// A call message (D78: expires 120 s after creation) wakes every recipient, online or not, via WakeCall.
	s.maybePush(context.Background(), body(120*time.Second), env, nil)
	if len(w.woke) != 0 || len(w.calls) != 2 || w.calls[0] != "bob" || w.calls[1] != "eve" {
		t.Fatalf("call: woke %q calls %q, want WakeCall for bob and eve", w.woke, w.calls)
	}

	// A non-urgent envelope with a call-like TTL is no call message.
	w.calls = nil
	s.maybePush(context.Background(), body(120*time.Second), &pb.Envelope{Recipients: env.Recipients}, nil)
	if len(w.calls)+len(w.woke) != 0 {
		t.Fatalf("non-urgent call-like envelope pushed: woke %q calls %q", w.woke, w.calls)
	}

	// Ordinary urgent messages (expires 0, ~30 days, or just over the 150 s bound) skip the online recipient.
	for _, ttl := range []time.Duration{0, 30 * 24 * time.Hour, 151 * time.Second} {
		w.woke, w.calls = nil, nil
		s.maybePush(context.Background(), body(ttl), env, nil)
		if len(w.calls) != 0 || len(w.woke) != 1 || w.woke[0] != "eve" {
			t.Fatalf("ttl %v: woke %q calls %q, want Wake for eve only", ttl, w.woke, w.calls)
		}
	}
	if !strings.Contains(logs.String(), `msg="push skipped"`) || !strings.Contains(logs.String(), "reason=online") {
		t.Fatalf("online skip not logged: %s", logs.String())
	}
}
