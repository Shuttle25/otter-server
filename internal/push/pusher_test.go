package push

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeSender struct {
	mu   sync.Mutex
	sent []string
	err  error
}

func (f *fakeSender) Send(_ context.Context, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, token)
	return f.err
}

type memTokens struct {
	mu   sync.Mutex
	toks map[string]string
}

func (m *memTokens) PushToken(_ context.Context, user []byte, device uint32) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.toks[string(user)], nil
}

func (m *memTokens) DropPushToken(_ context.Context, user []byte, device uint32, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.toks[string(user)] == token {
		delete(m.toks, string(user))
	}
	return nil
}

func TestPusherCoalescesAndDrops(t *testing.T) {
	s := &fakeSender{}
	toks := &memTokens{toks: map[string]string{"alice": "tok-a"}}
	now := time.Unix(1000, 0)
	p := New(s, toks, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.Now = func() time.Time { return now }
	ctx := context.Background()
	p.Wake(ctx, []byte("alice"), 1)
	p.Wake(ctx, []byte("alice"), 1)  // within 10 s: coalesced
	p.Wake(ctx, []byte("nobody"), 1) // no token: nothing sent
	p.Wait()
	if len(s.sent) != 1 || s.sent[0] != "tok-a" {
		t.Fatalf("sent %v", s.sent)
	}
	now = now.Add(11 * time.Second)
	s.err = ErrUnregistered
	p.Wake(ctx, []byte("alice"), 1)
	p.Wait()
	if len(s.sent) != 2 {
		t.Fatalf("second push after the window: %v", s.sent)
	}
	if tok, _ := toks.PushToken(ctx, []byte("alice"), 1); tok != "" {
		t.Fatalf("unregistered token kept: %q", tok)
	}
	s.err = errors.New("boom") // other errors keep the token
	toks.toks["alice"] = "tok-b"
	now = now.Add(11 * time.Second)
	p.Wake(ctx, []byte("alice"), 1)
	p.Wait()
	if tok, _ := toks.PushToken(ctx, []byte("alice"), 1); tok != "tok-b" {
		t.Fatalf("token dropped on a transient error")
	}
}

func TestPusherWakeCallBypassesCoalescing(t *testing.T) {
	s := &fakeSender{}
	user := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	toks := &memTokens{toks: map[string]string{string(user): "tok-a"}}
	now := time.Unix(1000, 0)
	var logs syncBuf
	p := New(s, toks, slog.New(slog.NewTextHandler(&logs, nil)))
	p.Now = func() time.Time { return now }
	ctx := context.Background()

	p.Wake(ctx, user, 1)     // message push
	p.WakeCall(ctx, user, 1) // a call 1 s later: never coalesced
	p.WakeCall(ctx, user, 1) // a redial: still sent
	p.Wait()
	if len(s.sent) != 3 {
		t.Fatalf("sent %v, want 3 (calls bypass coalescing)", s.sent)
	}
	p.Wake(ctx, user, 1) // a message right after a call: coalesced (WakeCall records the time)
	p.Wait()
	if len(s.sent) != 3 {
		t.Fatalf("sent %v, want the message push coalesced", s.sent)
	}

	out := logs.String()
	for _, want := range []string{
		`level=INFO msg="push sent" user=deadbeef device=1 kind=message`,
		`level=INFO msg="push sent" user=deadbeef device=1 kind=call`,
		`level=INFO msg="push skipped" user=deadbeef device=1 kind=message reason=coalesced`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "deadbeef01") || strings.Contains(out, "tok-a") {
		t.Errorf("log leaks the full user id or the token:\n%s", out)
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
