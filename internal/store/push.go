package store

import (
	"context"
	"database/sql"
	"errors"
)

// PushToken returns the device's current push token, or "" (D60).
func (s *Store) PushToken(ctx context.Context, user []byte, device uint32) (string, error) {
	var tok string
	err := s.r.QueryRowContext(ctx, `SELECT token FROM push_tokens WHERE user_id=? AND device_id=?`, user, device).Scan(&tok)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return tok, err
}

// PushTarget returns the device's push token ("" = none or withdrawn) and whether it wants call pushes only (D94).
func (s *Store) PushTarget(ctx context.Context, user []byte, device uint32) (string, bool, error) {
	var tok string
	var off bool
	err := s.r.QueryRowContext(ctx, `SELECT token, messages_off FROM push_tokens WHERE user_id=? AND device_id=?`,
		user, device).Scan(&tok, &off)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return tok, off, err
}

// DropPushToken forgets token if it is still the device's current one (FCM said UNREGISTERED). Local only.
func (s *Store) DropPushToken(ctx context.Context, user []byte, device uint32, token string) error {
	return s.write(ctx, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM push_tokens WHERE user_id=? AND device_id=? AND token=?`, user, device, token)
		return err
	})
}
