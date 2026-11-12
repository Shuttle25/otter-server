package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
	"ottermsg/server/internal/store"
)

// NewsKey implements records.NewsResolver from the current manifest (D65).
func (s *Service) NewsKey(id []byte) (ed25519.PublicKey, bool) {
	m := s.CurrentManifest()
	if m == nil {
		return nil, false
	}
	for _, k := range m.NewsKeys {
		if len(k) == ed25519.PublicKeySize && bytes.Equal(keys.ID16(k), id) {
			return ed25519.PublicKey(k), true
		}
	}
	return nil, false
}

func isNews(t pb.RecordType) bool {
	return t == pb.RecordType_ANNOUNCEMENT || t == pb.RecordType_ANNOUNCEMENT_DELETED
}

// PublishNews accepts an announcement or a deletion sent by the admin (news.publish, D67). Idempotent.
func (s *Service) PublishNews(ctx context.Context, rec *pb.Record) error {
	body, err := s.validator(nil).Validate(rec)
	if errors.Is(err, records.ErrUnknownNewsKey) {
		return fmt.Errorf("%w: news key not in the manifest — run manifest sign and manifest publish", ErrInvalid)
	}
	if err != nil {
		return invalid(err)
	}
	if !isNews(body.Type) {
		return fmt.Errorf("%w: not an announcement", ErrInvalid)
	}
	_, applied, err := s.Store.ApplyFrom(ctx, rec, body, s.NodeID)
	if err == nil && applied {
		s.afterApply(ctx, body, nil)
	}
	return err
}

// News returns every stored announcement and deletion, oldest first (news.list).
func (s *Service) News(ctx context.Context) ([]*pb.Record, error) {
	raws, err := s.Store.News(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*pb.Record, 0, len(raws))
	for _, raw := range raws {
		r := &pb.Record{}
		if err := proto.Unmarshal(raw, r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// newsStored reports whether a just-applied announcement is still stored: one whose deletion arrived first is
// removed on apply (D66).
func (s *Service) newsStored(ctx context.Context, body *pb.RecordBody) bool {
	key := append(append([]byte{}, body.Author...), body.Id...)
	_, err := s.Store.Get(ctx, key)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.Log.Warn("checking a new announcement", "err", err)
	}
	return err == nil
}

// dropRevokedNews deletes news authored by keys no longer in the manifest (D65).
func (s *Service) dropRevokedNews(ctx context.Context) {
	m := s.CurrentManifest()
	if m == nil {
		return
	}
	var keep [][]byte
	for _, k := range m.NewsKeys {
		keep = append(keep, keys.ID16(k))
	}
	n, err := s.Store.DropNewsExcept(ctx, keep)
	if err != nil {
		s.Log.Warn("dropping revoked news failed", "err", err)
		return
	}
	if n > 0 {
		s.Log.Info("revoked news dropped", "records", n)
		s.Notify.News()
	}
}

// pushNews wakes every registered device that is offline here, for a fresh announcement this node is responsible
// for (D67, D58 duty rule).
func (s *Service) pushNews(ctx context.Context, body *pb.RecordBody, from []byte) {
	if body.CreatedMs < s.Now().Add(-pushMaxAge).UnixMilli() || !s.pushDuty(from) {
		return
	}
	targets, err := s.Store.PushTargets(ctx)
	if err != nil {
		s.Log.Warn("push targets", "err", err)
		return
	}
	for _, t := range targets {
		if !s.Notify.Online(t.User, t.Device) {
			s.Waker.Wake(ctx, t.User, t.Device)
		}
	}
}

// ApkChunk serves apk.get (D68): chunk index of the APK with this SHA-256 and the file size.
func (s *Service) ApkChunk(sum []byte, index uint32) ([]byte, uint64, error) {
	if s.Apks == nil || len(sum) != 32 {
		return nil, 0, fmt.Errorf("%w: apk", ErrNotFound)
	}
	data, total, err := s.Apks.Chunk(sum, index)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, fmt.Errorf("%w: apk", ErrNotFound)
	}
	return data, total, err
}
