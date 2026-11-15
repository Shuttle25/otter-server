package gateway

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/store"
)

type session struct {
	g      *Gateway
	conn   *websocket.Conn
	out    chan *pb.Frame
	wake   chan struct{}
	nonce  []byte
	ctx    context.Context
	cancel context.CancelFunc
	// blob.get may wait on a peer (proxy): run up to 4 off the read loop
	blobSem chan struct{}

	mu     sync.Mutex
	user   []byte
	device uint32
	// install time this session logged in with (or uploaded itself); a newer install elsewhere ends the session (D52)
	installedMs int64
	// granted by backup.fetch on a connection that is not logged in: blob.get of this one blob as its owner (D51)
	backupBlob, backupOwner []byte
}

func (s *session) loggedIn() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.user != nil }
func (s *session) userID() []byte { s.mu.Lock(); defer s.mu.Unlock(); return s.user }
func (s *session) hasGrant() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.backupBlob != nil }

// reader is the user a blob.get reads as: the logged-in user, or the backup owner for the granted blob; nil = denied.
func (s *session) reader(key []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.user != nil {
		return s.user
	}
	if s.backupBlob != nil && bytes.Equal(s.backupBlob, key) {
		return s.backupOwner
	}
	return nil
}

func (s *session) is(user []byte, device uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.user != nil && s.device == device && bytes.Equal(s.user, user)
}

// replaced reports whether another install of this session's device was registered after the session logged in
// (a restore on another phone, D52). Such a session must not receive or ack envelopes any more.
func (s *session) replaced() bool {
	s.mu.Lock()
	user, device, mine := s.user, s.device, s.installedMs
	s.mu.Unlock()
	if user == nil {
		return false
	}
	_, inst, err := s.g.svc.Store.DeviceInstall(s.ctx, user, device)
	return err == nil && inst > mine
}

// dropReplaced closes the connection of a replaced install; its next login shows it was superseded (D52).
func (s *session) dropReplaced() bool {
	if !s.replaced() {
		return false
	}
	s.cancel() // ends the read loop at once; the close handshake must not keep it serving requests
	go s.conn.Close(websocket.StatusPolicyViolation, "install replaced")
	return true
}

// keepalive pings the client every interval; a ping without a pong within timeout ends the session
// (cancel stops the read loop, which removes the session). Pongs are processed by the concurrent read loop.
func (s *session) keepalive(interval, timeout time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
		}
		ctx, cancel := context.WithTimeout(s.ctx, timeout)
		err := s.conn.Ping(ctx)
		cancel()
		if err != nil {
			if s.ctx.Err() != nil {
				return // the session ended anyway
			}
			s.mu.Lock()
			u, dev := s.user, s.device
			s.mu.Unlock()
			args := []any{"err", err}
			if u != nil {
				args = append(args, "user", fmt.Sprintf("%x", u[:min(len(u), 4)]), "device", dev)
			}
			s.g.log.Info("session ping failed", args...)
			s.cancel()
			s.conn.CloseNow()
			return
		}
	}
}

func (s *session) kick() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *session) send(f *pb.Frame) {
	select {
	case s.out <- f:
	case <-s.ctx.Done():
	}
}

func (s *session) event(typ string, body proto.Message) {
	b, _ := proto.Marshal(body)
	s.send(&pb.Frame{Kind: &pb.Frame_Event{Event: &pb.Event{Type: typ, Body: b}}})
}

func (s *session) writeLoop() {
	for {
		select {
		case f := <-s.out:
			b, err := proto.Marshal(f)
			if err != nil {
				continue
			}
			ctx, cancel := context.WithTimeout(s.ctx, writeTimeout)
			err = s.conn.Write(ctx, websocket.MessageBinary, b)
			cancel()
			if err != nil {
				s.cancel()
				return
			}
		case <-s.ctx.Done():
			return
		}
	}
}

// deliverLoop pushes mailbox entries not yet pushed in this session.
func (s *session) deliverLoop() {
	sent := map[string]bool{}
	for {
		select {
		case <-s.wake:
		case <-s.ctx.Done():
			return
		}
		if s.dropReplaced() {
			return
		}
		for {
			entries, err := s.g.svc.Mailbox(s.ctx, s.user, s.device, 1000)
			if err != nil {
				s.g.log.Warn("mailbox", "err", err)
				break
			}
			batch, full := nextBatch(entries, sent, deliverBatchBytes)
			if len(batch.Records) == 0 {
				break
			}
			s.event("envelopes", batch)
			if !full {
				break
			}
		}
	}
}

// nextBatch builds the next envelopes event from the mailbox entries not yet in sent: at most deliverBatch records
// and at most maxBytes of records, but always at least one record, so an event stays far below a phone's 4 MiB frame
// limit (D93). It marks the chosen entries sent and forgets sent keys no longer in the mailbox (acknowledged
// meanwhile). full reports that entries were left for the next event.
func nextBatch(entries []store.MailboxEntry, sent map[string]bool, maxBytes int) (batch *pb.RecordBatch, full bool) {
	next := make(map[string]bool, len(entries))
	batch = &pb.RecordBatch{}
	size := 0
	for _, e := range entries {
		k := string(e.Key)
		next[k] = true
		if sent[k] || full {
			continue
		}
		if len(batch.Records) >= deliverBatch || (len(batch.Records) > 0 && size+len(e.Raw) > maxBytes) {
			full = true // the rest goes in the next event
			continue
		}
		r := &pb.Record{}
		if proto.Unmarshal(e.Raw, r) == nil {
			batch.Records = append(batch.Records, r)
			size += len(e.Raw)
		}
		sent[k] = true
	}
	for k := range sent {
		if !next[k] {
			delete(sent, k) // acknowledged meanwhile
		}
	}
	return batch, full
}
