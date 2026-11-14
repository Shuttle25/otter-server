package service

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"time"

	pb "ottermsg/server/internal/proto/otterv1"
)

// pushMaxAge: an envelope older than this (a late replication) never triggers a push.
const pushMaxAge = 10 * time.Minute

// Capable reports whether the manifest marks node id as push-capable.
func Capable(m *pb.Manifest, id []byte) bool {
	if m == nil {
		return false
	}
	for _, n := range m.Nodes {
		if bytes.Equal(n.NodeId, id) {
			return n.PushCapable
		}
	}
	return false
}

// pushDuty implements D58: from == nil for a record accepted here (client submit), else the peer it came from.
func (s *Service) pushDuty(from []byte) bool {
	m := s.CurrentManifest()
	if s.Waker == nil || !Capable(m, s.NodeID) {
		return false
	}
	if from == nil {
		return true
	}
	if Capable(m, from) {
		return false // the origin (approximated by the sending peer) pushes itself
	}
	for _, n := range m.Nodes {
		if n.PushCapable {
			return bytes.Equal(n.NodeId, s.NodeID)
		}
	}
	return false
}

// callMaxTTL: an urgent envelope that expires at most this long after creation is call signaling.
// Clients send call messages with expires_ms = created_ms + 120 s (D78); ordinary messages use 0 or ~30 days.
const callMaxTTL = 150 * time.Second

// isCall recognises call signaling without seeing the (end-to-end encrypted) content.
func isCall(body *pb.RecordBody, e *pb.Envelope) bool {
	ttl := body.ExpiresMs - body.CreatedMs
	return e.Urgent && body.ExpiresMs > 0 && ttl > 0 && ttl <= callMaxTTL.Milliseconds()
}

// maybePush wakes recipients of a fresh urgent envelope this node is responsible for (D58).
// Ordinary messages wake only recipients without a live session here; call messages wake every recipient
// (a phone's socket may be half-open and still count as online) and bypass coalescing.
func (s *Service) maybePush(ctx context.Context, body *pb.RecordBody, e *pb.Envelope, from []byte) {
	if !e.Urgent || body.CreatedMs < s.Now().Add(-pushMaxAge).UnixMilli() || !s.pushDuty(from) {
		return
	}
	call := isCall(body, e)
	for _, r := range e.Recipients {
		switch {
		case call:
			s.Waker.WakeCall(ctx, r.User, r.Device)
		case s.Notify.Online(r.User, r.Device):
			s.logger().Info("push skipped", "user", userTag(r.User), "device", r.Device, "kind", "message", "reason", "online")
		default:
			s.Waker.Wake(ctx, r.User, r.Device)
		}
	}
}

func (s *Service) logger() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// userTag: the first 4 bytes of a user id in hex, enough to follow one user through the logs.
func userTag(user []byte) string {
	return fmt.Sprintf("%x", user[:min(len(user), 4)])
}
