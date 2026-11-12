package push

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Sender delivers one wake-up to an FCM token.
type Sender interface {
	Send(ctx context.Context, token string) error
}

// Tokens is the store side (internal/store implements it).
type Tokens interface {
	PushToken(ctx context.Context, user []byte, device uint32) (string, error)
	DropPushToken(ctx context.Context, user []byte, device uint32, token string) error
}

// Pusher wakes devices: ≤ 1 push per (user, device) per Every (D58). Sends run in the background.
type Pusher struct {
	Every time.Duration
	Now   func() time.Time

	sender Sender
	tokens Tokens
	log    *slog.Logger
	mu     sync.Mutex
	last   map[string]time.Time
	wg     sync.WaitGroup
}

// New returns a Pusher with the D58 coalescing window (10 s).
func New(sender Sender, tokens Tokens, log *slog.Logger) *Pusher {
	return &Pusher{Every: 10 * time.Second, Now: time.Now, sender: sender, tokens: tokens, log: log, last: map[string]time.Time{}}
}

// Wake implements service.Waker.
func (p *Pusher) Wake(ctx context.Context, user []byte, device uint32) {
	k := fmt.Sprintf("%x/%d", user, device)
	now := p.Now()
	p.mu.Lock()
	if t, ok := p.last[k]; ok && now.Sub(t) < p.Every {
		p.mu.Unlock()
		return
	}
	p.last[k] = now
	for key, t := range p.last { // keep the map small
		if now.Sub(t) > time.Minute {
			delete(p.last, key)
		}
	}
	p.mu.Unlock()
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
		defer cancel()
		tok, err := p.tokens.PushToken(ctx, user, device)
		if err != nil || tok == "" {
			return
		}
		switch err := p.sender.Send(ctx, tok); {
		case err == nil:
			p.log.Debug("push sent", "user", fmt.Sprintf("%x", user))
		case errors.Is(err, ErrUnregistered):
			p.log.Info("push token unregistered: dropped", "user", fmt.Sprintf("%x", user))
			_ = p.tokens.DropPushToken(ctx, user, device, tok)
		default:
			p.log.Warn("push failed", "err", err)
		}
	}()
}

// Wait blocks until in-flight sends finish (tests, shutdown).
func (p *Pusher) Wait() { p.wg.Wait() }
