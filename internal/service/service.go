package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
	"ottermsg/server/internal/store"
)

const (
	LowPrekeys   = 10
	MaxClockSkew = 5 * time.Minute
)

// Notifier is implemented by the gateway.
type Notifier interface {
	Envelope(user []byte, device uint32)
	Directory()
	PrekeysLow(user []byte, device uint32, owner []byte, remaining int)
	Manifest(version uint64)
}

type nopNotifier struct{}

func (nopNotifier) Envelope([]byte, uint32)                {}
func (nopNotifier) Directory()                             {}
func (nopNotifier) PrekeysLow([]byte, uint32, []byte, int) {}
func (nopNotifier) Manifest(uint64)                        {}

type Service struct {
	Store       *store.Store
	NodeID      []byte
	NodeKeyPriv ed25519.PrivateKey
	NetworkPub  ed25519.PublicKey
	Notify      Notifier
	Now         func() time.Time
	Log         *slog.Logger

	mu         sync.RWMutex
	manifest   *pb.Manifest
	onManifest []func(*pb.Manifest)
}

func New(st *store.Store, nodeKey ed25519.PrivateKey, networkPub ed25519.PublicKey) *Service {
	return &Service{Store: st, NodeKeyPriv: nodeKey, NodeID: keys.ID16(nodeKey.Public().(ed25519.PublicKey)),
		NetworkPub: networkPub, Notify: nopNotifier{}, Now: time.Now, Log: slog.Default()}
}

// OnManifest registers a callback fired whenever the cached manifest version changes.
func (s *Service) OnManifest(f func(*pb.Manifest)) {
	s.mu.Lock()
	s.onManifest = append(s.onManifest, f)
	s.mu.Unlock()
}

func (s *Service) CurrentManifest() *pb.Manifest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.manifest
}

// LoadManifest refreshes the cache from the store; returns true if the version changed.
func (s *Service) LoadManifest(ctx context.Context) (bool, error) {
	rec, _, err := s.Manifest(ctx)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var body pb.RecordBody
	m := &pb.Manifest{}
	if err := proto.Unmarshal(rec.Body, &body); err != nil {
		return false, err
	}
	if err := proto.Unmarshal(body.Payload, m); err != nil {
		return false, err
	}
	s.mu.Lock()
	changed := s.manifest == nil || s.manifest.Version != m.Version
	s.manifest = m
	cbs := append([]func(*pb.Manifest){}, s.onManifest...)
	s.mu.Unlock()
	if changed {
		for _, f := range cbs {
			f(m)
		}
	}
	return changed, nil
}

// NodeKey implements records.NodeResolver from the current manifest.
func (s *Service) NodeKey(id []byte) (ed25519.PublicKey, bool) {
	m := s.CurrentManifest()
	if m == nil {
		return nil, false
	}
	for _, n := range m.Nodes {
		if bytes.Equal(n.NodeId, id) {
			return n.NodePub, true
		}
	}
	return nil, false
}

type overlay struct {
	base records.UserResolver
	id   []byte
	key  records.UserKey
}

func (o overlay) UserKey(id []byte) (records.UserKey, bool) {
	if o.id != nil && bytes.Equal(id, o.id) {
		return o.key, true
	}
	return o.base.UserKey(id)
}

func (s *Service) validator(res records.UserResolver) *records.Validator {
	if res == nil {
		res = s.Store
	}
	return &records.Validator{NetworkPub: s.NetworkPub, Users: res, Nodes: s, Now: s.Now}
}

func (s *Service) networkID() []byte { return keys.ID16(s.NetworkPub) }

func (s *Service) inviterAllowed(ctx context.Context, inviter []byte) error {
	if bytes.Equal(inviter, s.networkID()) {
		return nil
	}
	u, err := s.Store.UserByID(ctx, inviter)
	if err != nil {
		return err
	}
	switch {
	case u == nil:
		return fmt.Errorf("%w: unknown inviter", ErrUnauthorized)
	case u.Revoked:
		return fmt.Errorf("%w: inviter revoked", ErrRevoked)
	case !u.CanInvite:
		return fmt.Errorf("%w: inviter may not invite", ErrUnauthorized)
	}
	return nil
}

func (s *Service) VerifyLogin(ctx context.Context, nonce []byte, req *pb.LoginRequest) error {
	if req.DeviceId != 1 {
		return fmt.Errorf("%w: device %d", ErrInvalid, req.DeviceId)
	}
	skew := s.Now().Sub(time.UnixMilli(req.TsMs))
	if skew > MaxClockSkew || skew < -MaxClockSkew {
		return fmt.Errorf("%w: clock skew %v", ErrUnauthorized, skew)
	}
	u, err := s.Store.UserByID(ctx, req.UserId)
	if err != nil {
		return err
	}
	if u == nil {
		return fmt.Errorf("%w: unknown user", ErrRetryLater) // may not be replicated here yet
	}
	if u.Revoked {
		return ErrRevoked
	}
	if !ed25519.Verify(u.AccountPub, keys.AuthMessage(s.NodeID, nonce, req.TsMs), req.Signature) {
		return fmt.Errorf("%w: bad signature", ErrUnauthorized)
	}
	return nil
}

func (s *Service) Directory(ctx context.Context) ([]*pb.Record, error) {
	raws, err := s.Store.DirectoryEntries(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*pb.Record, 0, len(raws))
	for _, raw := range raws {
		r := &pb.Record{}
		if err := proto.Unmarshal(raw, r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (s *Service) Manifest(ctx context.Context) (*pb.Record, uint64, error) {
	v, raw, err := s.Store.LatestManifest(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return nil, 0, fmt.Errorf("%w: no manifest", ErrNotFound)
	}
	if err != nil {
		return nil, 0, err
	}
	r := &pb.Record{}
	return r, v, proto.Unmarshal(raw, r)
}

func (s *Service) Mailbox(ctx context.Context, user []byte, device uint32, limit int) ([]store.MailboxEntry, error) {
	return s.Store.Mailbox(ctx, user, device, limit)
}

func (s *Service) FetchPrekeys(ctx context.Context, req *pb.PreKeyFetchRequest) (*pb.PreKeyBundle, error) {
	dev := req.DeviceId
	if dev == 0 {
		dev = 1
	}
	u, err := s.Store.UserByID(ctx, req.UserId)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, fmt.Errorf("%w: user", ErrRetryLater)
	}
	if u.Revoked {
		return nil, fmt.Errorf("%w: user", ErrNotFound)
	}
	rows, err := s.Store.TakePrekeys(ctx, req.UserId, dev, s.NodeID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("%w: prekeys", ErrRetryLater)
	}
	if err != nil {
		return nil, err
	}
	var rec pb.Record
	var body pb.RecordBody
	var entry pb.DirectoryEntry
	if err := proto.Unmarshal(u.EntryRaw, &rec); err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(rec.Body, &body); err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(body.Payload, &entry); err != nil {
		return nil, err
	}
	if rows.OneTime != nil {
		if err := s.emitConsumed(ctx, req.UserId, dev, rows.OneTime.Id); err != nil {
			// e.g. this node is missing from the manifest (dev setup): the bundle is still valid
			s.Log.Warn("PREKEY_CONSUMED not recorded", "err", err)
		}
	}
	if rows.RemainingOwn < LowPrekeys {
		s.Notify.PrekeysLow(req.UserId, dev, s.NodeID, rows.RemainingOwn)
	}
	return &pb.PreKeyBundle{UserId: req.UserId, DeviceId: dev, RegistrationId: rows.RegistrationID,
		IdentityPub: entry.IdentityPub, SignedPrekey: rows.Signed, KyberPrekey: rows.Kyber, OneTime: rows.OneTime}, nil
}

// ImportRecord validates and applies a record from a trusted local file (manifest, bootstrap invite).
func (s *Service) ImportRecord(ctx context.Context, rec *pb.Record) (bool, error) {
	body, err := s.validator(nil).Validate(rec)
	if err != nil {
		return false, invalid(err)
	}
	_, applied, err := s.Store.ApplyFrom(ctx, rec, body, s.NodeID)
	if err == nil && applied {
		s.afterApply(ctx, body)
	}
	return applied, err
}

// emitConsumed records, as a node-signed record, that this node handed out a one-time prekey.
func (s *Service) emitConsumed(ctx context.Context, user []byte, dev, keyID uint32) error {
	p, _ := proto.Marshal(&pb.PrekeyConsumed{UserId: user, DeviceId: dev, KeyIds: []uint32{keyID}})
	id := make([]byte, 16)
	rand.Read(id)
	rec, err := records.Sign(&pb.RecordBody{Id: id, Type: pb.RecordType_PREKEY_CONSUMED, Author: s.NodeID,
		CreatedMs: s.Now().UnixMilli(), Payload: p}, s.NodeKeyPriv)
	if err != nil {
		return err
	}
	body, err := s.validator(nil).Validate(rec)
	if err != nil {
		return fmt.Errorf("own PREKEY_CONSUMED invalid (node missing from manifest?): %w", err)
	}
	_, _, err = s.Store.ApplyFrom(ctx, rec, body, s.NodeID)
	return err
}

type LowOwner struct {
	Node      []byte
	Remaining int
}

// PrekeyStatus lists manifest nodes that hold fewer than LowPrekeys unconsumed one-time keys of the user.
func (s *Service) PrekeyStatus(ctx context.Context, user []byte, device uint32) ([]LowOwner, error) {
	m := s.CurrentManifest()
	if m == nil {
		return nil, nil
	}
	counts, err := s.Store.PrekeyCounts(ctx, user, device)
	if err != nil {
		return nil, err
	}
	var out []LowOwner
	for _, n := range m.Nodes {
		if c := counts[string(n.NodeId)]; c < LowPrekeys {
			out = append(out, LowOwner{Node: n.NodeId, Remaining: c})
		}
	}
	return out, nil
}
