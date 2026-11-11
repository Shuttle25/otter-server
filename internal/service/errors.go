// Package service implements node business logic independent of transports.
package service

import (
	"errors"
	"fmt"

	"ottermsg/server/internal/records"
)

var (
	ErrInvalid      = errors.New("invalid")
	ErrNotFound     = errors.New("not found")
	ErrConflict     = errors.New("conflict")
	ErrUnauthorized = errors.New("unauthorized")
	ErrRevoked      = errors.New("revoked")
	// ErrRetryLater: the data is probably not replicated to this node yet.
	ErrRetryLater = errors.New("retry later")
	// ErrQuota: blob larger than max_blob, or the author's live blobs would exceed user_quota (D44).
	ErrQuota = errors.New("quota")
)

// invalid maps validator errors to service errors.
func invalid(err error) error {
	if errors.Is(err, records.ErrRevoked) {
		return fmt.Errorf("%w: %v", ErrRevoked, err)
	}
	return fmt.Errorf("%w: %v", ErrInvalid, err)
}
