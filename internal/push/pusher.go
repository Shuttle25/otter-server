package push

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Sender delivers one wake-up to an FCM token.
type Sender interface {
	Send(ctx context.Context, token string) error
}

// Tokens is the store side (internal/store implements it).
type Tokens interface {
	// PushTarget: the device's token ("" = none or withdrawn) and whether it wants call pushes only (D94).
	PushTarget(ctx context.Context, user []byte, device uint32) (token string, messagesOff bool, err error)
	DropPushToken(ctx context.Context, user []byte, device uint32, token string) error
}

// Pusher wakes devices: ≤ 1 push per (user, device) per Every (D58). Sends run in the background.
type Pusher struct {
	Every time.Duration
	Now   func() time.Time

	// outcomes since start, for monitoring (D119)
	Sent, Failed, Unregistered atomic.Int64

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

// Wake implements service.Waker: a message wake-up, coalesced to ≤ 1 per (user, device) per Every.
func (p *Pusher) Wake(ctx context.Context, user []byte, device uint32) {
	p.wake(ctx, user, device, false)
}

// WakeCall implements service.Waker: a call wake-up, never coalesced (a redial right after a call must
// ring). It still records the time, so message pushes right after it are coalesced.
func (p *Pusher) WakeCall(ctx context.Context, user []byte, device uint32) {
	p.wake(ctx, user, device, true)
}

func (p *Pusher) wake(ctx context.Context, user []byte, device uint32, call bool) {
	kind := "message"
	if call {
		kind = "call"
	}
	tag := userTag(user)
	k := fmt.Sprintf("%x/%d", user, device)
	now := p.Now()
	p.mu.Lock()
	if t, ok := p.last[k]; ok && now.Sub(t) < p.Every && !call {
		p.mu.Unlock()
		p.log.Info("push skipped", "user", tag, "device", device, "kind", kind, "reason", "coalesced")
		return
	}
	p.last[k] = now
	for key, t := range p.last { // keep the map small
		if now.Sub(t) > time.Minute {
			delete(p.last, key)
		}
	}
	p.mu.Unlock()
	user = bytes.Clone(user) // the send runs after the caller returns
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
		defer cancel()
		tok, off, err := p.tokens.PushTarget(ctx, user, device)
		if err != nil || tok == "" {
			return
		}
		if off && !call { // notifications off on the phone: calls still ring (D94)
			p.log.Info("push skipped", "user", tag, "device", device, "kind", kind, "reason", "messages_off")
			return
		}
		switch err := p.sender.Send(ctx, tok); {
		case err == nil:
			p.Sent.Add(1)
			p.log.Info("push sent", "user", tag, "device", device, "kind", kind)
		case errors.Is(err, ErrUnregistered):
			p.Unregistered.Add(1)
			p.log.Info("push token unregistered: dropped", "user", tag, "device", device)
			_ = p.tokens.DropPushToken(ctx, user, device, tok)
		default:
			p.Failed.Add(1)
			p.log.Warn("push failed", "user", tag, "device", device, "kind", kind, "err", err)
		}
	}()
}

// userTag: the first 4 bytes of a user id in hex, enough to follow one user through the logs.
func userTag(user []byte) string {
	return fmt.Sprintf("%x", user[:min(len(user), 4)])
}

// Wait blocks until in-flight sends finish (tests, shutdown).
func (p *Pusher) Wait() { p.wg.Wait() }
