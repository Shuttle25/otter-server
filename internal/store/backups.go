package store

import (
	"context"
	"database/sql"
	"errors"
)

// Backup is a user's current BACKUP_META (D50).
type Backup struct {
	UserID, RecordKey, BlobKey []byte
	Version                    int64
	Raw                        []byte // serialized pb.Record of the BACKUP_META
}

// BackupFor returns the current backup of the user with this username, or ErrNotFound.
func (s *Store) BackupFor(ctx context.Context, username string) (*Backup, error) {
	b := &Backup{}
	err := s.r.QueryRowContext(ctx, `SELECT k.user_id, k.record_key, k.blob_key, k.version, r.raw
		FROM backups k JOIN users u ON u.user_id = k.user_id JOIN records r ON r.record_key = k.record_key
		WHERE u.username = ? AND u.revoked = 0`, username).Scan(&b.UserID, &b.RecordKey, &b.BlobKey, &b.Version, &b.Raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}

// DeviceInstall returns the registration id and install time of the newest install of a device (D52).
func (s *Store) DeviceInstall(ctx context.Context, user []byte, device uint32) (uint32, int64, error) {
	var rid uint32
	var inst int64
	err := s.r.QueryRowContext(ctx, `SELECT registration_id, installed_ms FROM devices WHERE user_id=? AND device_id=?`,
		user, device).Scan(&rid, &inst)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, ErrNotFound
	}
	return rid, inst, err
}

// PersistentBlobs counts the user's live persistent blobs (D50 limit).
func (s *Store) PersistentBlobs(ctx context.Context, owner []byte) (int, error) {
	var n int
	err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM blobs WHERE owner=? AND persistent=1`, owner).Scan(&n)
	return n, err
}

// AddAuthFailure records a failed backup.fetch for a username (D51 rate limit).
func (s *Store) AddAuthFailure(ctx context.Context, username string, atMs int64) error {
	return s.write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO auth_failures(username, at_ms) VALUES(?,?)`, username, atMs)
		return err
	})
}

// AuthFailures counts failures for one username since sinceMs.
func (s *Store) AuthFailures(ctx context.Context, username string, sinceMs int64) (int, error) {
	var n int
	err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_failures WHERE username=? AND at_ms >= ?`, username, sinceMs).Scan(&n)
	return n, err
}

// AuthFailuresTotal counts failures for all usernames since sinceMs.
func (s *Store) AuthFailuresTotal(ctx context.Context, sinceMs int64) (int, error) {
	var n int
	err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_failures WHERE at_ms >= ?`, sinceMs).Scan(&n)
	return n, err
}
