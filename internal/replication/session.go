package replication

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/blobs"
	"ottermsg/server/internal/netlog"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/service"
)

const (
	maxBatchRecords = 512
	maxBatchBytes   = 4 << 20
	window          = 4
	maxFrame        = 8 << 20
)

// Peer keep-alive (D130): a WebSocket ping every peerPing; no pong within peerPingTimeout ends the session. The pong
// is read by run()'s read loop, which may be busy with an 8 MiB batch on a throttled link, hence the long timeout.
var (
	peerPing        = 25 * time.Second
	peerPingTimeout = 60 * time.Second
)

type session struct {
	r      *Replicator
	c      *websocket.Conn
	peer   []byte
	dialer []byte
	ctx    context.Context
	cancel context.CancelFunc
	out    chan *pb.PeerFrame
	acks   chan struct{} // window slots
	in     chan *pb.PeerBatch
	start  time.Time

	bytesIn    atomic.Int64 // payload bytes received (throttling detection, D73)
	pingFailed atomic.Bool  // the session ended because the peer stopped answering pings (D130)

	mu       sync.Mutex
	caughtUp bool // peer's oplog fully received
	cursor   int64
	applyErr error // why applying the peer's batches stopped (ends the session)

	// blob chunk RPC (D45)
	reqID    atomic.Uint64
	pmu      sync.Mutex
	pending  map[uint64]chan *pb.PeerBlobChunk
	serveSem chan struct{}
	hpending map[uint64]chan bool // PeerHoldsQuery answers (D113)
}

func newSession(r *Replicator, c *websocket.Conn, peer, dialer []byte) *session {
	ctx, cancel := context.WithCancel(r.baseCtx())
	return &session{r: r, c: c, peer: peer, dialer: dialer, ctx: ctx, cancel: cancel,
		out: make(chan *pb.PeerFrame, 16), acks: make(chan struct{}, window), in: make(chan *pb.PeerBatch, window), start: time.Now(),
		pending: map[uint64]chan *pb.PeerBlobChunk{}, serveSem: make(chan struct{}, 4), hpending: map[uint64]chan bool{}}
}

func (s *session) close() { s.cancel(); s.c.CloseNow() }

// run blocks until the session ends.
func (s *session) run() error {
	defer s.close()
	cur, err := s.r.st.PeerCursor(s.ctx, s.peer)
	if err != nil {
		return err
	}
	s.setCursor(cur) // Status() reads it concurrently
	go s.writeLoop()
	go s.keepalive()
	go s.applyLoop()
	s.send(&pb.PeerFrame{Kind: &pb.PeerFrame_Subscribe{Subscribe: &pb.PeerSubscribe{Cursor: cur}}})
	started := false
	for {
		f, n, err := readFrame(s.ctx, s.c)
		s.bytesIn.Add(int64(n))
		if err != nil {
			if aerr := s.applyError(); aerr != nil {
				return aerr
			}
			return err
		}
		switch k := f.Kind.(type) {
		case *pb.PeerFrame_Subscribe:
			if !started {
				started = true
				go s.serve(k.Subscribe.Cursor)
			}
		case *pb.PeerFrame_Batch:
			// Applied by applyLoop so this loop keeps reading: a catch-up batch may take longer to apply than
			// peerPingTimeout, and the pong is only read here. An honest peer has at most `window` batches unacked.
			select {
			case s.in <- k.Batch:
			case <-s.ctx.Done():
				if aerr := s.applyError(); aerr != nil {
					return aerr
				}
				return s.ctx.Err()
			}
		case *pb.PeerFrame_BatchAck:
			select {
			case <-s.acks:
			default:
			}
		case *pb.PeerFrame_BlobGet:
			g := k.BlobGet
			if len(g.BlobKey) != blobs.KeyLen { // hostile or broken peer: answer "missing", keep the session (C11)
				s.r.log.Warn("peer asked for a malformed blob key", "peer", fmt.Sprintf("%x", s.peer), "len", len(g.BlobKey))
				s.send(blobChunk(g.Req, nil))
				continue
			}
			select {
			case s.serveSem <- struct{}{}:
			default: // busy: answer "missing" rather than block replication
				s.send(blobChunk(g.Req, nil))
				continue
			}
			go func() {
				defer func() { <-s.serveSem }()
				defer func() {
					if p := recover(); p != nil { // one bad request must never stop the node (D83)
						s.r.log.Error("serving a blob chunk panicked", "peer", fmt.Sprintf("%x", s.peer), "panic", p)
						s.send(blobChunk(g.Req, nil))
					}
				}()
				if s.r.peerNoBackups(s.peer) { // D113: no backup chunks to a node with no_backups
					if p, err := s.r.st.BlobPersistent(s.ctx, g.BlobKey); err != nil || p {
						s.send(blobChunk(g.Req, nil))
						return
					}
				}
				data, ok, err := s.r.svc.LocalChunk(s.ctx, g.BlobKey, g.Index)
				if err != nil || !ok {
					data = nil
				}
				s.send(blobChunk(g.Req, data))
			}()
		case *pb.PeerFrame_BlobChunk:
			s.pmu.Lock()
			ch := s.pending[k.BlobChunk.Req]
			delete(s.pending, k.BlobChunk.Req)
			s.pmu.Unlock()
			if ch != nil {
				ch <- k.BlobChunk // buffered 1
			}
		case *pb.PeerFrame_HoldsQuery:
			q := k.HoldsQuery
			select {
			case s.serveSem <- struct{}{}:
			default: // busy: "not held" only delays a handoff
				s.send(holdsFrame(q.Req, false))
				continue
			}
			go func() {
				defer func() { <-s.serveSem }()
				held, err := s.r.svc.Holds(s.ctx, q.RecordKey)
				s.send(holdsFrame(q.Req, err == nil && held))
			}()
		case *pb.PeerFrame_Holds:
			s.pmu.Lock()
			ch := s.hpending[k.Holds.Req]
			delete(s.hpending, k.Holds.Req)
			s.pmu.Unlock()
			if ch != nil {
				ch <- k.Holds.Held // buffered 1
			}
		case *pb.PeerFrame_Error:
			return fmt.Errorf("peer error: %s", k.Error.Message)
		}
	}
}

// keepalive ends the session when the peer stops answering pings, and logs it (netlog endpoint "ping").
func (s *session) keepalive() {
	t := time.NewTicker(peerPing)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
		}
		ctx, cancel := context.WithTimeout(s.ctx, peerPingTimeout)
		err := s.c.Ping(ctx)
		cancel()
		if err == nil {
			continue
		}
		if s.ctx.Err() != nil {
			return // the session ended anyway
		}
		dir := "in"
		if bytes.Equal(s.dialer, s.r.svc.NodeID) {
			dir = "out"
		}
		class := netlog.Classify(err, 0)
		s.pingFailed.Store(true)
		s.r.notePingFail(s.peer)
		s.r.log.Info("peer ping failed", "peer", fmt.Sprintf("%x", s.peer), "err", err)
		s.r.nlog.Add(s.r.baseCtx(), netlog.Entry{Peer: s.r.labelOf(s.peer), Endpoint: "ping", Direction: dir,
			Result: netlog.Result(class), Class: class, Detail: fmt.Sprintf("no pong within %s", peerPingTimeout)})
		s.close()
		return
	}
}

func (s *session) send(f *pb.PeerFrame) {
	select {
	case s.out <- f:
	case <-s.ctx.Done():
	}
}

func (s *session) writeLoop() {
	for {
		select {
		case f := <-s.out:
			ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
			err := writeFrame(ctx, s.c, f)
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

// serve streams our oplog after `from` to the peer.
func (s *session) serve(from int64) {
	cursor := from
	idleSent := false
	for s.ctx.Err() == nil {
		changed := s.r.st.Changed() // take before querying to avoid missing a commit
		entries, err := s.r.st.Since(s.ctx, cursor, maxBatchRecords)
		if err != nil {
			s.r.log.Warn("peer since", "err", err)
			s.cancel()
			return
		}
		if len(entries) == 0 {
			if !idleSent {
				s.send(&pb.PeerFrame{Kind: &pb.PeerFrame_Batch{Batch: &pb.PeerBatch{LastSeq: cursor, CaughtUp: true}}})
				idleSent = true
			}
			select {
			case <-changed:
			case <-s.ctx.Done():
				return
			case <-time.After(time.Minute): // safety net
			}
			continue
		}
		toNoBackups := s.r.peerNoBackups(s.peer)
		b := &pb.PeerBatch{}
		size := 0
		for _, e := range entries {
			if size+len(e.Raw) > maxBatchBytes && len(b.Records) > 0 {
				break
			}
			b.LastSeq = e.Seq
			if toNoBackups && backupEntry(e) {
				continue // D113: the cursor moves past it; the record never goes to a node with no_backups
			}
			b.Records = append(b.Records, e.Raw)
			size += len(e.Raw)
		}
		if len(b.Records) > 0 { // the peer acks only a batch with records: an empty one takes no window slot
			select {
			case s.acks <- struct{}{}: // take a window slot (released by BatchAck)
			case <-s.ctx.Done():
				return
			}
		}
		s.send(&pb.PeerFrame{Kind: &pb.PeerFrame_Batch{Batch: b}})
		cursor = b.LastSeq
		idleSent = false
	}
}

// applyLoop applies the peer's batches in arrival order; an error ends the session without advancing the cursor.
func (s *session) applyLoop() {
	for {
		select {
		case b := <-s.in:
			if err := s.receive(b); err != nil {
				s.mu.Lock()
				s.applyErr = err
				s.mu.Unlock()
				s.close()
				return
			}
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *session) applyError() error { s.mu.Lock(); defer s.mu.Unlock(); return s.applyErr }

func (s *session) receive(b *pb.PeerBatch) error {
	for _, raw := range b.Records {
		rec := &pb.Record{}
		if err := proto.Unmarshal(raw, rec); err != nil {
			s.r.log.Warn("peer sent undecodable record", "peer", fmt.Sprintf("%x", s.peer))
			continue
		}
		if _, err := s.r.svc.ApplyReplicated(s.ctx, s.peer, rec); err != nil {
			if !errors.Is(err, service.ErrInvalid) {
				// retry-later or a transient failure: stop without advancing the cursor; the redial re-sends from here
				return err
			}
			s.r.log.Warn("peer record rejected", "peer", fmt.Sprintf("%x", s.peer), "err", err)
		}
	}
	if b.LastSeq > s.cursorValue() {
		if err := s.r.st.SetPeerCursor(s.ctx, s.peer, b.LastSeq); err != nil {
			return err
		}
		s.setCursor(b.LastSeq)
	}
	s.mu.Lock()
	s.caughtUp = b.CaughtUp
	s.mu.Unlock()
	if len(b.Records) > 0 {
		s.send(&pb.PeerFrame{Kind: &pb.PeerFrame_BatchAck{BatchAck: &pb.PeerBatchAck{Seq: b.LastSeq}}})
	}
	return nil
}

func (s *session) cursorValue() int64 { s.mu.Lock(); defer s.mu.Unlock(); return s.cursor }
func (s *session) setCursor(c int64)  { s.mu.Lock(); s.cursor = c; s.mu.Unlock() }

func blobChunk(req uint64, data []byte) *pb.PeerFrame {
	return &pb.PeerFrame{Kind: &pb.PeerFrame_BlobChunk{BlobChunk: &pb.PeerBlobChunk{Req: req, Data: data, Missing: data == nil}}}
}

// getChunk asks this peer for one chunk; nil data with no error means the peer doesn't have it.
func (s *session) getChunk(ctx context.Context, key []byte, idx uint32) ([]byte, error) {
	id := s.reqID.Add(1)
	ch := make(chan *pb.PeerBlobChunk, 1)
	s.pmu.Lock()
	s.pending[id] = ch
	s.pmu.Unlock()
	defer func() {
		s.pmu.Lock()
		delete(s.pending, id)
		s.pmu.Unlock()
	}()
	s.send(&pb.PeerFrame{Kind: &pb.PeerFrame_BlobGet{BlobGet: &pb.PeerBlobGet{Req: id, BlobKey: key, Index: idx}}})
	select {
	case c := <-ch:
		if c.Missing {
			return nil, nil
		}
		return c.Data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}
