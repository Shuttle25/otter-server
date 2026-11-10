package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
	"ottermsg/server/internal/store"
)

// Register creates an account from an invite. Returns the new user_id.
func (s *Service) Register(ctx context.Context, req *pb.RegisterRequest) ([]byte, error) {
	if len(req.InviteSecret) != 32 || req.DirectoryEntry == nil || req.Prekeys == nil || req.InviteUsed == nil {
		return nil, fmt.Errorf("%w: incomplete registration", ErrInvalid)
	}
	sum := sha256.Sum256(req.InviteSecret)
	inviteID := sum[:]
	inv, err := s.Store.Invite(ctx, inviteID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("%w: unknown invite", ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	if inv.UsedBy != nil {
		return nil, fmt.Errorf("%w: invite already used", ErrConflict)
	}
	if inv.ExpiresMs < s.Now().UnixMilli() {
		return nil, fmt.Errorf("%w: invite expired", ErrConflict)
	}
	if err := s.inviterAllowed(ctx, inv.Inviter); err != nil {
		return nil, err
	}

	dirBody, err := s.validator(nil).Validate(req.DirectoryEntry)
	if err != nil {
		return nil, invalid(err)
	}
	if dirBody.Type != pb.RecordType_DIRECTORY_ENTRY {
		return nil, fmt.Errorf("%w: directory_entry has type %v", ErrInvalid, dirBody.Type)
	}
	var e pb.DirectoryEntry
	if err := proto.Unmarshal(dirBody.Payload, &e); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if u, err := s.Store.UserByID(ctx, e.UserId); err != nil {
		return nil, err
	} else if u != nil {
		return nil, fmt.Errorf("%w: already registered", ErrConflict)
	}
	if owner, err := s.Store.UsernameOwner(ctx, e.Username); err != nil {
		return nil, err
	} else if owner != nil {
		return nil, fmt.Errorf("%w: username taken", ErrConflict)
	}

	ov := s.validator(overlay{base: s.Store, id: e.UserId, key: records.UserKey{Pub: e.AccountPub}})
	pkBody, err := ov.Validate(req.Prekeys)
	if err != nil {
		return nil, invalid(err)
	}
	var pk pb.PreKeys
	_ = proto.Unmarshal(pkBody.Payload, &pk)
	if pkBody.Type != pb.RecordType_PREKEYS || !bytes.Equal(pkBody.Author, e.UserId) || pk.SignedPrekey == nil || pk.KyberPrekey == nil {
		return nil, fmt.Errorf("%w: prekeys", ErrInvalid)
	}
	usedBody, err := ov.Validate(req.InviteUsed)
	if err != nil {
		return nil, invalid(err)
	}
	var used pb.InviteUsed
	_ = proto.Unmarshal(usedBody.Payload, &used)
	if usedBody.Type != pb.RecordType_INVITE_USED || !bytes.Equal(used.InviteId, inviteID) {
		return nil, fmt.Errorf("%w: invite_used", ErrInvalid)
	}

	_, err = s.Store.ApplyAll(ctx, s.NodeID, []store.Item{
		{Record: req.DirectoryEntry, Body: dirBody},
		{Record: req.Prekeys, Body: pkBody},
		{Record: req.InviteUsed, Body: usedBody},
	})
	switch {
	case errors.Is(err, store.ErrUsernameTaken):
		return nil, fmt.Errorf("%w: username taken", ErrConflict)
	case errors.Is(err, store.ErrInviteUnavailable):
		return nil, fmt.Errorf("%w: invite already used", ErrConflict)
	case err != nil:
		return nil, err
	}
	s.Notify.Directory()
	return e.UserId, nil
}
