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

// Restore authentication (D51, D105).
const (
	DefaultKdfMKib     = 65536
	DefaultKdfT        = 3
	DefaultKdfP        = 1
	MaxPersistentBlobs = 3 // live backup blobs per user (D50)
)

// RestoreLimits (D105): a stranger can slow a name down on one node, never lock it.
var RestoreLimits = store.AuthLimits{PerSourceHour: 5, FreePerName: 10, FreePerSource: 30,
	BaseDelay: 30 * time.Second, MaxDelay: 15 * time.Minute}

// fakeSalt answers backup.auth for unknown usernames (node-local; members publish a decoy BACKUP_META instead, C20).
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

// BackupAuth returns the KDF salt and parameters for a username; a stable fake salt when there is no backup. A name
// shared after a clash returns only the candidates "name#tag" (D103): the phone tries each with the typed password.
func (s *Service) BackupAuth(ctx context.Context, username string) (*pb.BackupAuthResponse, error) {
	if s.NoBackups() { // D113: no backups at rest here; phones restore through a node abroad
		return nil, fmt.Errorf("%w: restore through another node", ErrUnavailable)
	}
	name, cands, err := s.Store.ResolveUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if cands != nil {
		return &pb.BackupAuthResponse{Candidates: cands}, nil
	}
	_, m, err := s.currentBackup(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return &pb.BackupAuthResponse{Salt: s.fakeSalt(username), KdfMKib: DefaultKdfMKib, KdfT: DefaultKdfT, KdfP: DefaultKdfP}, nil
	}
	if err != nil {
		return nil, err
	}
	return &pb.BackupAuthResponse{Salt: m.Salt, KdfMKib: m.KdfMKib, KdfT: m.KdfT, KdfP: m.KdfP}, nil
}

// BackupFetch checks auth_secret against the verifier; on success returns both meta records and the blob key.
// A name shared after a clash is refused (D103). The attempt is reserved as a failure per (account, source) before
// the comparison and cleared when the secret is right or this node failed (D105, C4, C10).
func (s *Service) BackupFetch(ctx context.Context, username, source string, secret []byte) (*pb.BackupFetchResponse, []byte, error) {
	if s.NoBackups() { // D113, before the attempt is counted
		return nil, nil, fmt.Errorf("%w: restore through another node", ErrUnavailable)
	}
	name, cands, err := s.Store.ResolveUsername(ctx, username)
	if err != nil {
		return nil, nil, err
	}
	if cands != nil {
		return nil, nil, fmt.Errorf("%w: ambiguous username, use name#tag", ErrConflict)
	}
	username = name // one failure counter per account, typed with or without its tag
	id, err := s.Store.ReserveAuthAttempt(ctx, username, source, s.Now().UnixMilli(), RestoreLimits)
	var sd *store.SlowDown
	if errors.As(err, &sd) {
		return nil, nil, fmt.Errorf("%w: %w", ErrRetryLater, sd)
	}
	if err != nil {
		return nil, nil, err
	}
	keep := true // the reserved row stays as a failure unless the secret was right or this node failed
	defer func() {
		if !keep {
			if err := s.Store.ClearAuthAttempt(context.WithoutCancel(ctx), id); err != nil {
				s.logger().Warn("clearing a restore attempt failed", "err", err)
			}
		}
	}()
	wrong := fmt.Errorf("%w: wrong username or password", ErrUnauthorized)
	b, m, err := s.currentBackup(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, wrong
	}
	if err != nil {
		keep = false
		return nil, nil, err
	}
	if m.Version == 0 { // a decoy (C20): no secret opens it; counted like a wrong password
		return nil, nil, wrong
	}
	v := sha256.Sum256(secret)
	if len(secret) != 32 || subtle.ConstantTimeCompare(v[:], m.AuthVerifier) != 1 {
		return nil, nil, wrong
	}
	keep = false
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
	if err := s.diskRefuses(DiskLow); err != nil {
		return err
	}
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
	if m.Version == 0 { // a decoy has no blob (C20)
		_, err = s.Submit(ctx, user, rec, pb.RecordType_BACKUP_META)
		return err
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
