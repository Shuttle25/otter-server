package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// Backup writes a consistent copy of the database to path, which must not exist yet. Safe while the node runs.
// The copy is created 0600 whatever the umask (C26), and O_EXCL|O_NOFOLLOW refuses an existing file or a planted
// link; VACUUM INTO fills an existing empty file and keeps its mode.
func (s *Store) Backup(ctx context.Context, path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s already exists", path)
		}
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	if _, err := s.r.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}
