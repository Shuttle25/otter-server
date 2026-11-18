package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
	"ottermsg/server/internal/store"
)

// Limits for blobs (D44) and undelivered messages (D117), from the node config.
type Limits struct {
	UserQuota   int64 // live blob bytes per author
	MaxBlob     int64
	UserPending int64 // undelivered envelope bytes per author submitted here (D117); 0 = no cap
}

// ChunkFetcher asks connected peers for a chunk this node lacks (the replicator).
type ChunkFetcher interface {
	// FetchChunk returns the first peer answer that passes ok; ErrNoPeerHasChunk-like error if none had it.
	FetchChunk(ctx context.Context, key []byte, idx uint32, ok func([]byte) bool) ([]byte, error)
}

// FetchTimeout bounds one on-demand fetch from peers (proxy for a reader).
const FetchTimeout = 10 * time.Second

func (s *Service) status(ctx context.Context, b *store.Blob) (*pb.BlobStatus, error) {
	have, err := s.Store.BlobChunks(ctx, b.Key)
	if err != nil {
		return nil, err
	}
	st := &pb.BlobStatus{Chunks: uint32(len(b.Hashes))}
	for i := range b.Hashes {
		if !have[uint32(i)] {
			st.Missing = append(st.Missing, uint32(i))
		}
	}
	return st, nil
}

// CreateBlob accepts a BLOB_META from its author and returns which chunks the node still needs. Idempotent.
func (s *Service) CreateBlob(ctx context.Context, user []byte, rec *pb.Record) (*pb.BlobStatus, error) {
	if err := s.diskRefuses(DiskLow); err != nil {
		return nil, err
	}
	if s.Blobs == nil {
		return nil, fmt.Errorf("%w: blobs disabled", ErrInvalid)
	}
	body, err := s.validator(nil).Validate(rec)
	if err != nil {
		return nil, invalid(err)
	}
	if body.Type != pb.RecordType_BLOB_META {
		return nil, fmt.Errorf("%w: not a blob meta", ErrInvalid)
	}
	if !bytes.Equal(body.Author, user) {
		return nil, fmt.Errorf("%w: author is not the logged-in user", ErrUnauthorized)
	}
	key := append(append([]byte{}, body.Author...), body.Id...)
	if b, err := s.Store.Blob(ctx, key); err == nil {
		return s.status(ctx, b)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if gone, err := s.Store.BlobGone(ctx, key); err != nil {
		return nil, err
	} else if gone {
		return nil, fmt.Errorf("%w: blob was deleted", ErrNotFound)
	}
	var m pb.BlobMeta
	if err := proto.Unmarshal(body.Payload, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if int64(m.Size) > s.Limits.MaxBlob {
		return nil, fmt.Errorf("%w: blob of %d bytes exceeds %d", ErrQuota, m.Size, s.Limits.MaxBlob)
	}
	// Quota and backup-blob limit are counted in the insert's write transaction (D106).
	applied, err := s.Store.ApplyBlobMeta(ctx, rec, body, s.NodeID, int64(m.Size), m.Persistent,
		store.BlobLimits{UserQuota: s.Limits.UserQuota, MaxPersistent: MaxPersistentBlobs})
	if errors.Is(err, store.ErrOverLimit) {
		return nil, fmt.Errorf("%w: %v", ErrQuota, err)
	}
	if err != nil {
		return nil, err
	}
	if applied {
		s.afterApply(ctx, body, nil)
	}
	b, err := s.Store.Blob(ctx, key)
	if err != nil {
		return nil, err
	}
	return s.status(ctx, b)
}

func expectedLen(size int64, idx uint32) int64 {
	off := int64(idx) * records.BlobChunkSize
	if rest := size - off; rest < records.BlobChunkSize {
		return rest
	}
	return records.BlobChunkSize
}

// ChunkOK checks index, length and hash of a chunk against the signed meta (D44).
func ChunkOK(b *store.Blob, idx uint32, data []byte) bool {
	if int(idx) >= len(b.Hashes) || int64(len(data)) != expectedLen(b.Size, idx) {
		return false
	}
	h := sha256.Sum256(data)
	return bytes.Equal(h[:], b.Hashes[idx])
}

// StoreChunk verifies, writes and marks one chunk (uploads, the puller and proxied reads). Refused below the disk floor.
func (s *Service) StoreChunk(ctx context.Context, b *store.Blob, idx uint32, data []byte) error {
	if err := s.diskRefuses(DiskLow); err != nil {
		return err
	}
	if !ChunkOK(b, idx, data) {
		return fmt.Errorf("%w: chunk %d does not match the blob meta", ErrInvalid, idx)
	}
	if err := s.Blobs.Write(b.Key, idx, data); err != nil {
		return err
	}
	return s.Store.MarkChunk(ctx, b.Key, idx)
}

// PutChunk stores a chunk uploaded by the blob's author.
func (s *Service) PutChunk(ctx context.Context, user, key []byte, idx uint32, data []byte) error {
	if s.Blobs == nil {
		return fmt.Errorf("%w: blobs disabled", ErrInvalid)
	}
	if len(key) != 32 || !bytes.Equal(key[:16], user) {
		return fmt.Errorf("%w: only the author uploads", ErrUnauthorized)
	}
	b, err := s.Store.Blob(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("%w: unknown blob", ErrNotFound)
	}
	if err != nil {
		return err
	}
	return s.StoreChunk(ctx, b, idx, data)
}

// GetChunk serves a chunk to the author or a reader, fetching it from a peer when missing here (proxy, D45).
func (s *Service) GetChunk(ctx context.Context, user, key []byte, idx uint32) ([]byte, error) {
	if s.Blobs == nil {
		return nil, fmt.Errorf("%w: blobs disabled", ErrInvalid)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: blob key", ErrInvalid)
	}
	b, err := s.Store.Blob(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		if gone, err := s.Store.BlobGone(ctx, key); err != nil {
			return nil, err
		} else if gone {
			return nil, fmt.Errorf("%w: blob was deleted", ErrNotFound)
		}
		return nil, fmt.Errorf("%w: blob not replicated here yet", ErrRetryLater)
	}
	if err != nil {
		return nil, err
	}
	allowed := bytes.Equal(b.Owner, user)
	for _, r := range b.Readers {
		allowed = allowed || bytes.Equal(r, user)
	}
	if !allowed {
		return nil, fmt.Errorf("%w: not a reader of this blob", ErrUnauthorized)
	}
	if int(idx) >= len(b.Hashes) {
		return nil, fmt.Errorf("%w: chunk index", ErrInvalid)
	}
	if data, err := s.Blobs.Read(key, idx); err == nil {
		return data, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if s.Fetcher == nil {
		return nil, fmt.Errorf("%w: chunk not here yet", ErrRetryLater)
	}
	fctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()
	data, err := s.Fetcher.FetchChunk(fctx, key, idx, func(d []byte) bool { return ChunkOK(b, idx, d) })
	if err != nil {
		return nil, fmt.Errorf("%w: chunk not available yet: %v", ErrRetryLater, err)
	}
	if err := s.StoreChunk(ctx, b, idx, data); errors.Is(err, errDiskLow) {
		s.Log.Debug("not keeping a proxied chunk: disk below the floor", "blob", hex.EncodeToString(key), "idx", idx)
	} else if err != nil {
		s.Log.Warn("keeping a proxied chunk failed", "blob", hex.EncodeToString(key), "idx", idx, "err", err)
	}
	return data, nil
}

// LocalChunk returns a chunk held by this node (for peers); ok=false when it isn't here.
func (s *Service) LocalChunk(ctx context.Context, key []byte, idx uint32) ([]byte, bool, error) {
	if s.Blobs == nil {
		return nil, false, nil
	}
	data, err := s.Blobs.Read(key, idx)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return data, err == nil, err
}

// SweepBlobFiles removes chunk directories of blobs that no longer exist.
func (s *Service) SweepBlobFiles(ctx context.Context) (int, error) {
	if s.Blobs == nil {
		return 0, nil
	}
	onDisk, err := s.Blobs.Keys() // before the live set: a blob created meanwhile is in the live set
	if err != nil {
		return 0, err
	}
	live, err := s.Store.BlobKeys(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, k := range onDisk {
		if !live[hex.EncodeToString(k)] {
			if err := s.Blobs.Remove(k); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

func (s *Service) kickSweep() {
	select {
	case s.sweep <- struct{}{}:
	default:
	}
}

func (s *Service) runSweeper(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.sweep:
		}
		time.Sleep(200 * time.Millisecond) // debounce bursts of BLOB_FETCHED
		if n, err := s.SweepBlobFiles(ctx); err != nil {
			s.Log.Warn("blob sweep", "err", err)
		} else if n > 0 {
			s.Log.Info("blob sweep", "removed", n)
		}
	}
}
