package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/store"
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

// VerifyAdmin checks an admin.users request: the network key over this session's nonce, within the clock skew.
func (s *Service) VerifyAdmin(nonce []byte, r *pb.AdminRequest) error {
	skew := s.Now().Sub(time.UnixMilli(r.TsMs))
	if skew > MaxClockSkew || skew < -MaxClockSkew || len(r.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(s.NetworkPub, keys.AdminAuthMessage(s.NodeID, nonce, r.TsMs), r.Signature) {
		return fmt.Errorf("%w: admin signature", ErrUnauthorized)
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

// founding reports whether the current manifest lists the user as admitted without an invite chain (D100).
func (s *Service) founding(user []byte) bool {
	m := s.CurrentManifest()
	if m == nil {
		return false
	}
	for _, f := range m.FoundingMembers {
		if bytes.Equal(f, user) {
			return true
		}
	}
	return false
}

// admitIfNew returns the admission of a DIRECTORY_ENTRY whose user this node does not know, nil for a known user.
func (s *Service) admitIfNew(ctx context.Context, body *pb.RecordBody) (*store.Admission, error) {
	var e pb.DirectoryEntry
	if err := proto.Unmarshal(body.Payload, &e); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if _, known := s.Store.UserKey(e.UserId); known {
		return nil, nil
	}
	if s.founding(e.UserId) {
		rank := body.CreatedMs
		if e.RegisteredMs > 0 {
			rank = e.RegisteredMs
		}
		return &store.Admission{RankMs: rank}, nil
	}
	return s.admitChain(ctx, &e, false)
}

// parseInvite unpacks DirectoryEntry.invite_record: the inviter's signed INVITE (structure only, no signature check).
func parseInvite(raw []byte) (*pb.Record, *pb.RecordBody, *pb.Invite, error) {
	var rec pb.Record
	var body pb.RecordBody
	var inv pb.Invite
	if len(raw) == 0 || proto.Unmarshal(raw, &rec) != nil || len(rec.Signature) != ed25519.SignatureSize ||
		proto.Unmarshal(rec.Body, &body) != nil || body.Type != pb.RecordType_INVITE || len(body.Author) != 16 ||
		proto.Unmarshal(body.Payload, &inv) != nil || len(inv.InviteId) != 32 || len(inv.RedeemPub) != ed25519.PublicKeySize {
		return nil, nil, nil, fmt.Errorf("%w: malformed invite record", ErrInvalid)
	}
	return &rec, &body, &inv, nil
}

// admitChain verifies the invite chain of a new account (D100). Everything it checks is in signed records, so every
// node reaches the same answer. strict = registration on this node: the invite must also be valid now and its inviter
// allowed now. Invite rights are not part of the admission: every member may invite unless the admin withdrew it
// (D101 as changed by the owner). An inviter disabled as a duplicate (D102) never admits anyone: registration refuses
// its invite (inviterAllowed: revoked), and a replicated account it invited is stored disabled by the store
// (disableDuplicates), so its own invitees do not wait forever for an inviter that is never stored.
func (s *Service) admitChain(ctx context.Context, e *pb.DirectoryEntry, strict bool) (*store.Admission, error) {
	if len(e.InviteRecord) == 0 || len(e.InviteProof) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: no invite chain (update the app)", ErrInvalid)
	}
	rec, ib, inv, err := parseInvite(e.InviteRecord)
	if err != nil {
		return nil, err
	}
	fromNetwork := bytes.Equal(ib.Author, s.networkID())
	signer := s.NetworkPub
	if !fromNetwork {
		k, ok := s.Store.UserKey(ib.Author) // a revoked inviter still verifies; when it was revoked is checked below
		if !ok {
			return nil, fmt.Errorf("%w: inviter %x not known here yet", ErrRetryLater, ib.Author)
		}
		signer = k.Pub
	}
	if !ed25519.Verify(signer, rec.Body, rec.Signature) {
		return nil, fmt.Errorf("%w: invite signature", ErrInvalid)
	}
	if !ed25519.Verify(inv.RedeemPub, keys.RedeemMessage(inv.InviteId, e.UserId, e.AccountPub), e.InviteProof) {
		return nil, fmt.Errorf("%w: invite proof", ErrInvalid)
	}
	if strict && inv.ExpiresMs < s.Now().UnixMilli() {
		return nil, fmt.Errorf("%w: invite expired", ErrConflict)
	}
	if e.RegisteredMs < ib.CreatedMs || e.RegisteredMs > inv.ExpiresMs {
		return nil, fmt.Errorf("%w: registration outside the invite's lifetime", ErrInvalid)
	}
	if !fromNetwork {
		at, revoked, err := s.Store.RevokedAt(ctx, ib.Author)
		if err != nil {
			return nil, err
		}
		if revoked && at <= ib.CreatedMs {
			return nil, fmt.Errorf("%w: inviter was revoked before the invite", ErrInvalid)
		}
		ok, err := s.Store.CanInviteAt(ctx, ib.Author, ib.CreatedMs)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%w: inviter had no invite rights", ErrInvalid)
		}
		if strict {
			if err := s.inviterAllowed(ctx, ib.Author); err != nil {
				return nil, err
			}
		}
	}
	h := sha256.Sum256(e.InviteProof)
	return &store.Admission{InviteID: inv.InviteId, Rank: h[:], RankMs: ib.CreatedMs, Inviter: ib.Author}, nil
}
