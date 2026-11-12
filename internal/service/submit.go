package service

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
)

// Submit validates and applies a client-authored record of one of the allowed types.
func (s *Service) Submit(ctx context.Context, user []byte, rec *pb.Record, allowed ...pb.RecordType) (*pb.RecordBody, error) {
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
		if err := s.inviterAllowed(ctx, user); err != nil {
			return nil, err
		}
	}
	_, applied, err := s.Store.ApplyFrom(ctx, rec, body, s.NodeID)
	if err != nil {
		return nil, err
	}
	if applied {
		s.afterApply(ctx, body, nil)
	}
	return body, nil
}
