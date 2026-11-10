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

	mu     sync.Mutex
	user   []byte
	device uint32
}

func (s *session) loggedIn() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.user != nil }

func (s *session) is(user []byte, device uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.user != nil && s.device == device && bytes.Equal(s.user, user)
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
