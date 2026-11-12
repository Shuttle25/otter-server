package push

import (
	"context"
	"errors"
	"io"
	"log/slog"
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
