package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
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
	PrekeysLow(user []byte, device uint32, remaining int)
}

type nopNotifier struct{}

func (nopNotifier) Envelope([]byte, uint32)        {}
func (nopNotifier) Directory()                     {}
func (nopNotifier) PrekeysLow([]byte, uint32, int) {}

type Service struct {
	Store      *store.Store
	NodeID     []byte
	NetworkPub ed25519.PublicKey
	Notify     Notifier
	Now        func() time.Time
}

func New(st *store.Store, nodeID []byte, networkPub ed25519.PublicKey) *Service {
	return &Service{Store: st, NodeID: nodeID, NetworkPub: networkPub, Notify: nopNotifier{}, Now: time.Now}
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
	return &records.Validator{NetworkPub: s.NetworkPub, Users: res, Now: s.Now}
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
		return fmt.Errorf("%w: unknown user", ErrUnauthorized)
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
	if u == nil || u.Revoked {
		return nil, fmt.Errorf("%w: user", ErrNotFound)
	}
	rows, err := s.Store.TakePrekeys(ctx, req.UserId, dev, s.NodeID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("%w: prekeys", ErrNotFound)
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
	if rows.RemainingOwn < LowPrekeys {
		s.Notify.PrekeysLow(req.UserId, dev, rows.RemainingOwn)
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
	return applied, err
}
