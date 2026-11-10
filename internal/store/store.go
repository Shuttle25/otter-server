// Package store is the only package that touches SQL.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")

var errClosed = errors.New("store closed")

type Store struct {
	r       *sql.DB // readers
	w       *sql.DB // single writer connection
	reqs    chan *applyReq
	done    chan struct{}
	stopped chan struct{}
	now     func() time.Time
}

func dsn(path string) string {
	return fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)", path)
}

func Open(path string) (*Store, error) {
	w, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	if err := migrate(context.Background(), w); err != nil {
		w.Close()
		return nil, err
	}
	r, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(8)
	s := &Store{r: r, w: w, reqs: make(chan *applyReq, 1024), done: make(chan struct{}), stopped: make(chan struct{}), now: time.Now}
	go s.writer()
	return s, nil
}

func (s *Store) Close() error {
	select {
	case <-s.done:
		return nil
	default:
	}
	close(s.done)
	<-s.stopped
	return errors.Join(s.r.Close(), s.w.Close())
}
