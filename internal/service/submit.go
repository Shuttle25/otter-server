package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/store"
)

// submitRates: records per author per hour accepted from clients (C8, D107); replication is bounded by the budgets.
var submitRates = map[pb.RecordType]int{pb.RecordType_PREKEYS: 20, pb.RecordType_PUSH_TOKEN: 30}

// freesSpace: acks let the node drop delivered envelopes and fetched blobs, so they pass even at a critical disk level.
func freesSpace(allowed []pb.RecordType) bool {
	for _, t := range allowed {
		if t != pb.RecordType_ACK && t != pb.RecordType_BLOB_FETCHED {
			return false
		}
	}
	return len(allowed) > 0
}

// Submit validates and applies a client-authored record of one of the allowed types.
func (s *Service) Submit(ctx context.Context, user []byte, rec *pb.Record, allowed ...pb.RecordType) (*pb.RecordBody, error) {
	if !freesSpace(allowed) {
		if err := s.diskRefuses(DiskCritical); err != nil { // D118
			return nil, err
		}
	}
	body, err := s.validator(nil).Validate(rec)
	if err != nil {
		return nil, invalid(err)
	}
	if !bytes.Equal(body.Author, user) {
		return nil, fmt.Errorf("%w: author is not the logged-in user", ErrUnauthorized)
	}
	if !slices.Contains(allowed, body.Type) {
		return nil, fmt.Errorf("%w: record type %v not allowed here", ErrInvalid, body.Type)
	}
	now := s.Now()
	if body.CreatedMs > now.Add(MaxClockSkew).UnixMilli() { // C8: a future date would outrank every later record
		return nil, fmt.Errorf("%w: created_ms is in the future", ErrInvalid)
	}
	if lim, ok := submitRates[body.Type]; ok && !s.submits.allow(now, time.Hour, fmt.Sprintf("%d/%x", body.Type, user), lim) {
		return nil, fmt.Errorf("%w: more than %d %v records this hour", ErrQuota, lim, body.Type)
	}
	var env *pb.Envelope
	switch body.Type {
	case pb.RecordType_ENVELOPE:
		env = &pb.Envelope{}
		if err := proto.Unmarshal(body.Payload, env); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		for _, r := range env.Recipients {
			u, err := s.Store.UserByID(ctx, r.User)
			if err != nil {
				return nil, err
			}
			if u == nil {
				return nil, fmt.Errorf("%w: recipient %x not known here yet", ErrRetryLater, r.User)
			}
			if u.Revoked {
				return nil, fmt.Errorf("%w: recipient %x", ErrNotFound, r.User)
			}
		}
	case pb.RecordType_INVITE:
		var inv pb.Invite
		if err := proto.Unmarshal(body.Payload, &inv); err != nil || len(inv.RedeemPub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: invite without a redeem key (update the app)", ErrInvalid)
		}
		if err := s.inviterAllowed(ctx, user); err != nil {
			return nil, err
		}
	}
	_, applied, err := s.Store.ApplyFrom(ctx, rec, body, s.NodeID)
	if errors.Is(err, store.ErrOverLimit) {
		return nil, fmt.Errorf("%w: %v", ErrQuota, err)
	}
	if err != nil {
		return nil, err
	}
	if applied {
		s.afterApply(ctx, body, nil)
	}
	return body, nil
}
