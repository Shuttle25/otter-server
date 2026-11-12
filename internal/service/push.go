package service

import (
	"bytes"
	"context"
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

// maybePush wakes offline recipients of a fresh urgent envelope this node is responsible for (D58).
func (s *Service) maybePush(ctx context.Context, body *pb.RecordBody, e *pb.Envelope, from []byte) {
	if !e.Urgent || body.CreatedMs < s.Now().Add(-pushMaxAge).UnixMilli() || !s.pushDuty(from) {
		return
	}
	for _, r := range e.Recipients {
		if !s.Notify.Online(r.User, r.Device) {
			s.Waker.Wake(ctx, r.User, r.Device)
		}
	}
}
