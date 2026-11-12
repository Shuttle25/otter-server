package service

import (
	"context"
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

func (nopWaker) Wake(_ context.Context, _ []byte, _ uint32) {}

type wakeRec struct{ woke []string }

func (w *wakeRec) Wake(_ context.Context, user []byte, _ uint32) { w.woke = append(w.woke, string(user)) }

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
	if len(w.woke) != 1 || w.woke[0] != "eve" {
		t.Fatalf("woke %q, want only the offline recipient eve", w.woke)
	}
}
