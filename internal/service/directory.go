package service

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
)

// UpdateDirectoryEntry applies a newer version of the caller's own directory entry (profile edit, D39/D40).
func (s *Service) UpdateDirectoryEntry(ctx context.Context, user []byte, rec *pb.Record) error {
	body, err := s.validator(nil).Validate(rec)
	if err != nil {
		return invalid(err)
	}
	if body.Type != pb.RecordType_DIRECTORY_ENTRY {
		return fmt.Errorf("%w: not a directory entry", ErrInvalid)
	}
	if !bytes.Equal(body.Author, user) {
		return fmt.Errorf("%w: entry of another user", ErrUnauthorized)
	}
	var e pb.DirectoryEntry
	if err := proto.Unmarshal(body.Payload, &e); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	cur, err := s.Store.UserByID(ctx, user)
	if err != nil {
		return err
	}
	if cur == nil {
		return fmt.Errorf("%w: user", ErrRetryLater)
	}
	original := cur.Username
	if cur.UsernameConflict { // lost a replicated clash: stored as "<name>#<hex>", the entry keeps "<name>"
		original = strings.SplitN(cur.Username, "#", 2)[0]
	}
	if e.Username != original {
		return fmt.Errorf("%w: username changes are not supported", ErrInvalid)
	}
	if e.Version <= cur.Version {
		return fmt.Errorf("%w: version %d is not newer than %d", ErrConflict, e.Version, cur.Version)
	}
	_, applied, err := s.Store.ApplyFrom(ctx, rec, body, s.NodeID)
	if err != nil {
		return err
	}
	if applied {
		s.afterApply(ctx, body)
	}
	return nil
}
