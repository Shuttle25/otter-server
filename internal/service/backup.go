package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/store"
)

// Restore authentication (D51).
const (
	DefaultKdfMKib     = 65536
	DefaultKdfT        = 3
	DefaultKdfP        = 1
	MaxFailuresPerName = 5  // per username per hour, per node
	MaxFailuresPerNode = 20 // per day, per node
	MaxPersistentBlobs = 3  // live backup blobs per user (D50)
)

// fakeSalt is a stable per-node answer for usernames without a backup, so backup.auth does not reveal which exist.
func (s *Service) fakeSalt(username string) []byte {
	k := sha256.Sum256(append([]byte("otter/fake-salt/v1"), s.NodeKeyPriv...))
	m := hmac.New(sha256.New, k[:])
	m.Write([]byte(username))
	return m.Sum(nil)[:16]
}

func (s *Service) currentBackup(ctx context.Context, username string) (*store.Backup, *pb.BackupMeta, error) {
	b, err := s.Store.BackupFor(ctx, username)
	if err != nil {
		return nil, nil, err
	}
	var rec pb.Record
	var body pb.RecordBody
	var m pb.BackupMeta
	if err := proto.Unmarshal(b.Raw, &rec); err != nil {
		return nil, nil, err
	}
	if err := proto.Unmarshal(rec.Body, &body); err != nil {
		return nil, nil, err
	}
	if err := proto.Unmarshal(body.Payload, &m); err != nil {
		return nil, nil, err
	}
	return b, &m, nil
}

// BackupAuth returns the KDF salt and parameters for a username; a stable fake salt when there is no backup.
func (s *Service) BackupAuth(ctx context.Context, username string) (*pb.BackupAuthResponse, error) {
	_, m, err := s.currentBackup(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		return &pb.BackupAuthResponse{Salt: s.fakeSalt(username), KdfMKib: DefaultKdfMKib, KdfT: DefaultKdfT, KdfP: DefaultKdfP}, nil
	}
	if err != nil {
		return nil, err
	}
	return &pb.BackupAuthResponse{Salt: m.Salt, KdfMKib: m.KdfMKib, KdfT: m.KdfT, KdfP: m.KdfP}, nil
}

// BackupFetch checks auth_secret against the verifier; on success returns both meta records and the blob key.
// Failures are rate limited per username and per node (D51).
func (s *Service) BackupFetch(ctx context.Context, username string, secret []byte) (*pb.BackupFetchResponse, []byte, error) {
	now := s.Now()
	perName, err := s.Store.AuthFailures(ctx, username, now.Add(-time.Hour).UnixMilli())
	if err != nil {
		return nil, nil, err
	}
	total, err := s.Store.AuthFailuresTotal(ctx, now.Add(-24*time.Hour).UnixMilli())
	if err != nil {
		return nil, nil, err
	}
	if perName >= MaxFailuresPerName || total >= MaxFailuresPerNode {
		return nil, nil, fmt.Errorf("%w: too many attempts", ErrRetryLater)
	}
	fail := func() error {
		if err := s.Store.AddAuthFailure(ctx, username, now.UnixMilli()); err != nil {
			return err
		}
		return fmt.Errorf("%w: wrong username or password", ErrUnauthorized)
	}
	b, m, err := s.currentBackup(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, fail()
	}
	if err != nil {
		return nil, nil, err
	}
	v := sha256.Sum256(secret)
	if len(secret) != 32 || subtle.ConstantTimeCompare(v[:], m.AuthVerifier) != 1 {
		return nil, nil, fail()
	}
	blobRaw, err := s.Store.Get(ctx, m.BlobKey)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, fmt.Errorf("%w: backup not replicated here yet", ErrRetryLater)
	}
	if err != nil {
		return nil, nil, err
	}
	var meta, blob pb.Record
	if err := proto.Unmarshal(b.Raw, &meta); err != nil {
		return nil, nil, err
	}
	if err := proto.Unmarshal(blobRaw, &blob); err != nil {
		return nil, nil, err
	}
	return &pb.BackupFetchResponse{BackupMeta: &meta, BlobMeta: &blob}, bytes.Clone(m.BlobKey), nil
}

// PublishBackup stores a BACKUP_META whose blob is one of the author's persistent blobs.
func (s *Service) PublishBackup(ctx context.Context, user []byte, rec *pb.Record) error {
	body, err := s.validator(nil).Validate(rec)
	if err != nil {
		return invalid(err)
	}
	if body.Type != pb.RecordType_BACKUP_META || !bytes.Equal(body.Author, user) {
		return fmt.Errorf("%w: not the author's backup meta", ErrInvalid)
	}
	var m pb.BackupMeta
	if err := proto.Unmarshal(body.Payload, &m); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	blob, err := s.Store.Blob(ctx, m.BlobKey)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("%w: backup blob unknown here", ErrInvalid)
	} else if err != nil {
		return err
	}
	if !bytes.Equal(blob.Owner, user) || len(blob.Readers) != 0 || blob.ExpiresMs != 0 {
		return fmt.Errorf("%w: not the author's persistent blob", ErrInvalid)
	}
	_, err = s.Submit(ctx, user, rec, pb.RecordType_BACKUP_META)
	return err
}
