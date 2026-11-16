package store

import (
	"context"
	"database/sql"
	"errors"

	pb "ottermsg/server/internal/proto/otterv1"
)

// Holds answers PeerHoldsQuery (D113): the record is stored here and, for a BLOB_META, every chunk too. A backup
// record this node received and later deleted as superseded (a newer backup replaced it, D50) also counts: the
// asking node must not keep a stale copy because the newer one got here first.
func (s *Store) Holds(ctx context.Context, key []byte) (bool, error) {
	var typ int32
	var chunks sql.NullInt64
	var have int64
	err := s.r.QueryRowContext(ctx, `SELECT r.type, b.chunks, (SELECT COUNT(*) FROM blob_chunks c WHERE c.blob_key=r.record_key)
		FROM records r LEFT JOIN blobs b ON b.blob_key=r.record_key WHERE r.record_key=?`, key).Scan(&typ, &chunks, &have)
	if err == nil {
		if pb.RecordType(typ) == pb.RecordType_BLOB_META {
			return chunks.Valid && have == chunks.Int64, nil
		}
		return true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	var x int
	err = s.r.QueryRowContext(ctx, `SELECT 1 FROM compacted WHERE record_key=?
		UNION ALL SELECT 1 FROM blob_tombstones WHERE blob_key=? LIMIT 1`, key, key).Scan(&x)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// LocalBackupItems lists the backup records stored here, persistent blobs first, for a node with no_backups to hand
// off (D113). A blob qualifies once a BACKUP_META references it or it was created before olderThanMs: the phone's
// backup.publish right after the upload must still find it here. A BACKUP_META qualifies once its blob is gone from
// here (dropping it first would make the blob wait for olderThanMs again).
func (s *Store) LocalBackupItems(ctx context.Context, olderThanMs int64) ([][]byte, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT b.blob_key FROM blobs b WHERE b.persistent=1 AND
		  (EXISTS (SELECT 1 FROM backups k WHERE k.blob_key=b.blob_key) OR b.created_ms < ?)
		UNION ALL SELECT r.record_key FROM records r LEFT JOIN backups k ON k.record_key=r.record_key
		  WHERE r.type=? AND (k.blob_key IS NULL OR NOT EXISTS (SELECT 1 FROM blobs b WHERE b.blob_key=k.blob_key))`,
		olderThanMs, int32(pb.RecordType_BACKUP_META))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var k []byte
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// DropBackupCopy deletes this node's copy of a handed-off backup record or blob (D113). A blob is tombstoned like a
// superseded backup (chunk files go with the next sweep); a BACKUP_META leaves its row in backups.
func (s *Store) DropBackupCopy(ctx context.Context, key []byte) error {
	return s.write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var typ int32
		err := tx.QueryRowContext(ctx, `SELECT type FROM records WHERE record_key=?`, key).Scan(&typ)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		switch pb.RecordType(typ) {
		case pb.RecordType_BLOB_META:
			return gcBlob(ctx, tx, key, true, s.now().UnixMilli())
		case pb.RecordType_BACKUP_META:
			if _, err := tx.ExecContext(ctx, `DELETE FROM backups WHERE record_key=?`, key); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `DELETE FROM records WHERE record_key=?`, key)
			return err
		}
		return nil
	})
}

// BlobPersistent: key is a backup blob stored here.
func (s *Store) BlobPersistent(ctx context.Context, key []byte) (bool, error) {
	var p bool
	err := s.r.QueryRowContext(ctx, `SELECT persistent FROM blobs WHERE blob_key=?`, key).Scan(&p)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return p, err
}
