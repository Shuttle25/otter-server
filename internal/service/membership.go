package service

import (
	"context"
	"fmt"

	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/turnsrv"
)

// PublishNetworkRecord accepts an admin-signed REVOCATION or INVITE_RIGHTS (otter-admin user …), the only records
// network.publish takes (D99). Idempotent: a record already stored is OK.
func (s *Service) PublishNetworkRecord(ctx context.Context, rec *pb.Record) error {
	body, err := s.validator(nil).Validate(rec)
	if err != nil {
		return invalid(err)
	}
	if body.Type != pb.RecordType_REVOCATION && body.Type != pb.RecordType_INVITE_RIGHTS {
		return fmt.Errorf("%w: %v is not published here", ErrInvalid, body.Type)
	}
	_, applied, err := s.Store.ApplyFrom(ctx, rec, body, s.NodeID)
	if err != nil {
		return err
	}
	if applied {
		s.afterApply(ctx, body, nil)
	}
	return nil
}

// RefreshRevoked reloads the revoked accounts (TURN tags) and closes the sessions of newly revoked ones.
// Called at start and after every record that can revoke or disable an account.
func (s *Service) RefreshRevoked(ctx context.Context) {
	ids, err := s.Store.RevokedUsers(ctx)
	if err != nil {
		s.Log.Warn("revoked users not loaded", "err", err)
		return
	}
	tags := make(map[string]bool, len(ids))
	var fresh [][]byte
	s.mu.Lock()
	for _, id := range ids {
		t := turnsrv.UserTag(id)
		tags[t] = true
		if !s.revokedTags[t] {
			fresh = append(fresh, id)
		}
	}
	s.revokedTags = tags
	s.mu.Unlock()
	for _, id := range fresh {
		s.Notify.Revoked(id)
	}
}

// TurnTagRevoked implements turnsrv.Config.Refuse.
func (s *Service) TurnTagRevoked(tag string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revokedTags[tag]
}
