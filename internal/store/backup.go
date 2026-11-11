package store

import (
	"context"
	"fmt"
	"os"
)

// Backup writes a consistent copy of the database to path, which must not exist yet. Safe while the node runs.
func (s *Store) Backup(ctx context.Context, path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}
	_, err := s.r.ExecContext(ctx, `VACUUM INTO ?`, path)
	return err
}
