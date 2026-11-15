package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
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

// InstallRecord returns the newest INSTALL record of a user (serialized pb.Record), or ErrNotFound (C14).
func (s *Store) InstallRecord(ctx context.Context, user []byte) ([]byte, error) {
	var raw []byte
	err := s.r.QueryRowContext(ctx, `SELECT r.raw FROM installs i JOIN records r ON r.record_key = i.record_key
		WHERE i.user_id = ?`, user).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return raw, err
}

// PersistentBlobs counts the user's live persistent blobs (D50 limit).
func (s *Store) PersistentBlobs(ctx context.Context, owner []byte) (int, error) {
	var n int
	err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM blobs WHERE owner=? AND persistent=1`, owner).Scan(&n)
	return n, err
}

// AuthLimits are the restore attempt limits (D105). Delays apply after the free failures of the last 24 h.
type AuthLimits struct {
	PerSourceHour       int           // failures per (username, source) per hour
	FreePerName         int           // failures per username, all sources, per 24 h before slowing down
	FreePerSource       int           // failures per source, all usernames, per 24 h before slowing down
	BaseDelay, MaxDelay time.Duration // wait after the last failure: BaseDelay·2^(n-free), at most MaxDelay
}

// SlowDown: the attempt is not allowed yet.
type SlowDown struct{ Wait time.Duration }

func (e *SlowDown) Error() string {
	return fmt.Sprintf("too many attempts, retry in %s", max(e.Wait.Round(time.Second), time.Second))
}

// AddAuthFailure records a failed backup.fetch (tests and imports; the service uses ReserveAuthAttempt).
func (s *Store) AddAuthFailure(ctx context.Context, username, source string, atMs int64) error {
	return s.write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO auth_failures(username, source, at_ms) VALUES(?,?,?)`, username, source, atMs)
		return err
	})
}

// ReserveAuthAttempt checks the limits and records the attempt as a failure in one write transaction, before the
// secret is compared, so parallel attempts cannot overshoot (C10). It returns the row id for ClearAuthAttempt, or a
// *SlowDown error. A correct secret does not bypass an active slow-down (it would make the limit a guessing oracle).
func (s *Store) ReserveAuthAttempt(ctx context.Context, username, source string, nowMs int64, l AuthLimits) (int64, error) {
	var id int64
	err := s.write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		hour, day := nowMs-time.Hour.Milliseconds(), nowMs-24*time.Hour.Milliseconds()
		var oldest sql.NullInt64 // the PerSourceHour-th newest failure of this (username, source) in the last hour
		err := tx.QueryRowContext(ctx, `SELECT at_ms FROM auth_failures WHERE username=? AND source=? AND at_ms>?
			ORDER BY at_ms DESC LIMIT 1 OFFSET ?`, username, source, hour, l.PerSourceHour-1).Scan(&oldest)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if oldest.Valid {
			return &SlowDown{Wait: time.Duration(oldest.Int64+time.Hour.Milliseconds()-nowMs) * time.Millisecond}
		}
		slow := func(q, arg string, free int) error {
			var n int
			var last sql.NullInt64
			if err := tx.QueryRowContext(ctx, q, arg, day).Scan(&n, &last); err != nil {
				return err
			}
			if n < free || !last.Valid {
				return nil
			}
			d := l.MaxDelay
			if shift := n - free; shift < 30 {
				d = min(l.BaseDelay<<shift, l.MaxDelay)
			}
			if wait := time.Duration(last.Int64+d.Milliseconds()-nowMs) * time.Millisecond; wait > 0 {
				return &SlowDown{Wait: wait}
			}
			return nil
		}
		if err := slow(`SELECT COUNT(*), MAX(at_ms) FROM auth_failures WHERE username=? AND at_ms>?`, username, l.FreePerName); err != nil {
			return err
		}
		if err := slow(`SELECT COUNT(*), MAX(at_ms) FROM auth_failures WHERE source=? AND at_ms>?`, source, l.FreePerSource); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO auth_failures(username, source, at_ms) VALUES(?,?,?)`, username, source, nowMs)
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	return id, err
}

// ClearAuthAttempt removes a reserved attempt (the secret was right, or the node failed).
func (s *Store) ClearAuthAttempt(ctx context.Context, id int64) error {
	return s.write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM auth_failures WHERE rowid=?`, id)
		return err
	})
}

// AuthFailures counts failures for one username since sinceMs.
func (s *Store) AuthFailures(ctx context.Context, username string, sinceMs int64) (int, error) {
	var n int
	err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_failures WHERE username=? AND at_ms >= ?`, username, sinceMs).Scan(&n)
	return n, err
}
