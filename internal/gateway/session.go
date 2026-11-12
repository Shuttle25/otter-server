package gateway

import (
	"bytes"
	"context"
	"sync"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
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
			next := make(map[string]bool, len(entries))
			batch := &pb.RecordBatch{}
			for _, e := range entries {
				k := string(e.Key)
				next[k] = true
				if sent[k] || len(batch.Records) >= deliverBatch {
					continue
				}
				r := &pb.Record{}
				if proto.Unmarshal(e.Raw, r) == nil {
					batch.Records = append(batch.Records, r)
				}
				sent[k] = true
			}
			for k := range sent {
				if !next[k] {
					delete(sent, k) // acknowledged meanwhile
				}
			}
			if len(batch.Records) == 0 {
				break
			}
			s.event("envelopes", batch)
			if len(batch.Records) < deliverBatch {
				break
			}
		}
	}
}
