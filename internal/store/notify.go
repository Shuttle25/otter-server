package store

import "sync"

type notifier struct {
	mu sync.Mutex
	ch chan struct{}
}

// Changed returns a channel that is closed after the next commit that applied a new record.
func (s *Store) Changed() <-chan struct{} {
	s.notify.mu.Lock()
	defer s.notify.mu.Unlock()
	if s.notify.ch == nil {
		s.notify.ch = make(chan struct{})
	}
	return s.notify.ch
}

func (s *Store) signalChanged() {
	s.notify.mu.Lock()
	defer s.notify.mu.Unlock()
	if s.notify.ch != nil {
		close(s.notify.ch)
		s.notify.ch = nil
	}
}
