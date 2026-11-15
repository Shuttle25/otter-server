package service

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
	"ottermsg/server/internal/store"
)

// ApplyReplicated validates and applies a record received from peer `from`.
// Returns ErrRetryLater if the author is not known yet (its directory entry hasn't arrived);
// a PREKEY_CONSUMED from a node outside our manifest is skipped instead.
func (s *Service) ApplyReplicated(ctx context.Context, from []byte, rec *pb.Record) (bool, error) {
	body, err := s.validator(nil).Validate(rec)
	switch {
	case errors.Is(err, records.ErrUnknownAuthor) && isPrekeyConsumed(rec):
		// Consumption only feeds refill counts. A node missing from our manifest must not stall the
		// peer session; the next manifest brings the node and its owner never re-issues those keys.
		s.Log.Debug("skipping PREKEY_CONSUMED from unknown node", "err", err)
		return false, nil
	case errors.Is(err, records.ErrUnknownNewsKey):
		// D66: the key may be revoked; retrying would stall the peer session. The admin publishes to every node.
		s.Log.Debug("skipping news from a key not in our manifest")
		return false, nil
	case errors.Is(err, records.ErrUnknownAuthor):
		return false, fmt.Errorf("%w: %v", ErrRetryLater, err)
	case errors.Is(err, records.ErrExpired):
		return false, nil
	case errors.Is(err, records.ErrRevoked):
		// the author was revoked after writing it; refusing with a retry would stall this peer forever (D99)
		s.Log.Debug("skipping record of a revoked author")
		return false, nil
	case err != nil:
		return false, invalid(err)
	}
	var adm *store.Admission
	if body.Type == pb.RecordType_DIRECTORY_ENTRY {
		if adm, err = s.admitIfNew(ctx, body); err != nil {
			return false, err // INVALID: skipped by the peer session; RETRY_LATER: the inviter's entry comes first
		}
	}
	_, applied, err := s.Store.ApplyReplicatedItem(ctx, store.Item{Record: rec, Body: body, Admission: adm}, from)
	if err != nil || !applied {
		return applied, err
	}
	s.afterApply(ctx, body, from)
	return true, nil
}

func isPrekeyConsumed(rec *pb.Record) bool {
	var b pb.RecordBody
	return proto.Unmarshal(rec.GetBody(), &b) == nil && b.Type == pb.RecordType_PREKEY_CONSUMED
}

// afterApply runs the side effects of a newly applied record. from is the peer a replicated record came from,
// nil for one accepted locally (client submit, local import).
func (s *Service) afterApply(ctx context.Context, body *pb.RecordBody, from []byte) {
	switch body.Type {
	case pb.RecordType_ENVELOPE:
		var e pb.Envelope
		if proto.Unmarshal(body.Payload, &e) == nil {
			for _, r := range e.Recipients {
				s.Notify.Envelope(r.User, r.Device)
			}
			s.maybePush(ctx, body, &e, from)
		}
	case pb.RecordType_DIRECTORY_ENTRY:
		s.RefreshRevoked(ctx) // an entry may arrive after its revocation, or a double redemption may disable one (D102)
		s.Notify.Directory()
	case pb.RecordType_REVOCATION, pb.RecordType_INVITE_RIGHTS:
		s.RefreshRevoked(ctx)
		s.Notify.Directory() // phones re-sync and verify the record themselves (D104)
	case pb.RecordType_BLOB_FETCHED:
		s.kickSweep() // the blob may be gone now: remove its files soon
	case pb.RecordType_MANIFEST:
		if changed, err := s.LoadManifest(ctx); err == nil && changed {
			s.Notify.Manifest(s.CurrentManifest().Version)
		}
	case pb.RecordType_ANNOUNCEMENT:
		// a deletion that arrived first removes it on apply (D66): nothing to show or push then
		if s.newsStored(ctx, body) {
			s.Notify.News()
			s.pushNews(ctx, body, from)
		}
	case pb.RecordType_ANNOUNCEMENT_DELETED:
		s.Notify.News()
	}
}

// PublishManifest accepts a network-signed manifest newer than the current one.
func (s *Service) PublishManifest(ctx context.Context, rec *pb.Record) error {
	body, err := s.validator(nil).Validate(rec)
	if err != nil {
		return invalid(err)
	}
	if body.Type != pb.RecordType_MANIFEST {
		return fmt.Errorf("%w: not a manifest", ErrInvalid)
	}
	var m pb.Manifest
	_ = proto.Unmarshal(body.Payload, &m)
	if cur := s.CurrentManifest(); cur != nil && m.Version <= cur.Version {
		return fmt.Errorf("%w: manifest version %d is not newer than %d", ErrConflict, m.Version, cur.Version)
	}
	if _, _, err := s.Store.ApplyFrom(ctx, rec, body, s.NodeID); err != nil {
		return err
	}
	s.afterApply(ctx, body, nil)
	return nil
}
