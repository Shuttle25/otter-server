package service

import (
	"bytes"
	"context"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
)

// NodeNoBackups reports whether node id is marked no_backups in the manifest m (D113).
func NodeNoBackups(m *pb.Manifest, id []byte) bool {
	for _, n := range m.GetNodes() {
		if bytes.Equal(n.NodeId, id) {
			return n.NoBackups
		}
	}
	return false
}

// NoBackups: this node is marked no_backups in the current manifest (D113): it never keeps backups at rest.
func (s *Service) NoBackups() bool { return NodeNoBackups(s.CurrentManifest(), s.NodeID) }

// IsBackupRecord: BACKUP_META or a persistent BLOB_META.
func IsBackupRecord(b *pb.RecordBody) bool {
	switch b.Type {
	case pb.RecordType_BACKUP_META:
		return true
	case pb.RecordType_BLOB_META:
		var m pb.BlobMeta
		return proto.Unmarshal(b.Payload, &m) == nil && m.Persistent
	}
	return false
}

// Holds answers PeerHoldsQuery; a node with no_backups never vouches for anyone.
func (s *Service) Holds(ctx context.Context, key []byte) (bool, error) {
	if s.NoBackups() {
		return false, nil
	}
	return s.Store.Holds(ctx, key)
}

// DropBackupCopy deletes a handed-off backup record or blob; its chunk files go with the next sweep.
func (s *Service) DropBackupCopy(ctx context.Context, key []byte) error {
	if err := s.Store.DropBackupCopy(ctx, key); err != nil {
		return err
	}
	s.kickSweep()
	return nil
}
