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
	"ottermsg/server/internal/blobs"
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
	// Online reports a logged-in, non-replaced session of (user, device) on this node.
	Online(user []byte, device uint32) bool
	// News: an announcement was accepted or dropped; sessions re-fetch news.list (D67).
	News()
	// Revoked: the account was revoked or disabled; every session of it ends at once (C2). Returns the sessions closed.
	Revoked(user []byte) int
}

// Waker sends a push wake-up (internal/push.Pusher). nil = this node never pushes.
type Waker interface {
	// Wake sends a message wake-up; coalesced (≤ 1 per (user, device) per 10 s, D58).
	Wake(ctx context.Context, user []byte, device uint32)
	// WakeCall sends a call wake-up: never coalesced, so a quick redial still rings.
	WakeCall(ctx context.Context, user []byte, device uint32)
}

type nopNotifier struct{}

func (nopNotifier) Envelope([]byte, uint32)                {}
func (nopNotifier) Directory()                             {}
func (nopNotifier) PrekeysLow([]byte, uint32, []byte, int) {}
func (nopNotifier) Manifest(uint64)                        {}
func (nopNotifier) Online([]byte, uint32) bool             { return false }
func (nopNotifier) News()                                  {}
func (nopNotifier) Revoked([]byte) int                     { return 0 }

// ApkSource serves APK chunks (internal/apk.Dir). A missing file or chunk is an error wrapping os.ErrNotExist.
type ApkSource interface {
	Chunk(sum []byte, index uint32) ([]byte, uint64, error)
}

type Service struct {
	Store       *store.Store
	NodeID      []byte
	NodeKeyPriv ed25519.PrivateKey
	NetworkPub  ed25519.PublicKey
	Notify      Notifier
	Now         func() time.Time
	Log         *slog.Logger
	Blobs       *blobs.Dir   // chunk files; nil = blob methods unavailable
	Fetcher     ChunkFetcher // asks peers for missing chunks; nil = no peers
	Waker       Waker        // push wake-ups (D58); nil = this node never pushes
	Apks        ApkSource    // APK files (D68); nil = apk.get unavailable
	Turn        TurnIssuer   // TURN credentials (D77); nil = turn.credentials unavailable
	Limits      Limits
	Disk        *DiskGuard // free-space floor (D118); nil = no checks

	sweep      chan struct{}
	mu         sync.RWMutex
	manifest   *pb.Manifest
	onManifest []func(*pb.Manifest)
	// TURN user tag → account id of revoked or disabled accounts (RefreshRevoked)
	revokedTags map[string][]byte
	refusals    windowCounter // "login refused" / "turn refused" log lines per user (one a minute)
	submits     windowCounter // local submit rates per author (C8, D107)
	callWakes   windowCounter // call pushes per (sender, recipient device) (D108)
}

func New(st *store.Store, nodeKey ed25519.PrivateKey, networkPub ed25519.PublicKey) *Service {
	return &Service{Store: st, NodeKeyPriv: nodeKey, NodeID: keys.ID16(nodeKey.Public().(ed25519.PublicKey)),
		NetworkPub: networkPub, Notify: nopNotifier{}, Now: time.Now, Log: slog.Default(),
		Limits: Limits{UserQuota: 2 << 30, MaxBlob: 100 << 20}, sweep: make(chan struct{}, 1)}
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
		// here, not in afterApply, so a node that stopped before dropping finishes at the next start (D65)
		s.dropRevokedNews(context.WithoutCancel(ctx))
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
	return &records.Validator{NetworkPub: s.NetworkPub, Users: res, Nodes: s, News: s, Now: s.Now, V1Until: s.v1Until}
}

// v1Until is the current manifest's sig_v1_until_ms: v1 record signatures are valid only for records created before
// it (D109; 0 = no cut-over yet).
func (s *Service) v1Until() int64 { return s.CurrentManifest().GetSigV1UntilMs() }

// sigContext is how this node signs its own records (PREKEY_CONSUMED) under the current manifest (D109).
func (s *Service) sigContext() records.SigContext {
	return records.ContextFor(s.NetworkPub, s.CurrentManifest())
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

// VerifyLogin checks a login signature and returns the newest install this node knows for the device (D52) and the
// newest account-signed INSTALL record of the user (C14).
func (s *Service) VerifyLogin(ctx context.Context, nonce []byte, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	if req.DeviceId != 1 {
		return nil, fmt.Errorf("%w: device %d", ErrInvalid, req.DeviceId)
	}
	skew := s.Now().Sub(time.UnixMilli(req.TsMs))
	if skew > MaxClockSkew || skew < -MaxClockSkew {
		return nil, fmt.Errorf("%w: clock skew %v", ErrUnauthorized, skew)
	}
	u, err := s.Store.UserByID(ctx, req.UserId)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, fmt.Errorf("%w: unknown user", ErrRetryLater) // may not be replicated here yet
	}
	if u.Revoked {
		s.logRefusal("login refused", req.UserId)
		return nil, ErrRevoked
	}
	if !ed25519.Verify(u.AccountPub, keys.AuthMessage(s.NodeID, nonce, req.TsMs), req.Signature) {
		return nil, fmt.Errorf("%w: bad signature", ErrUnauthorized)
	}
	rid, inst, err := s.Store.DeviceInstall(ctx, req.UserId, req.DeviceId)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	resp := &pb.LoginResponse{RegistrationId: rid, InstalledMs: inst} // unsigned: for 0.8.x phones only (C14)
	raw, err := s.Store.InstallRecord(ctx, req.UserId)
	switch {
	case err == nil:
		resp.Install = &pb.Record{}
		if err := proto.Unmarshal(raw, resp.Install); err != nil {
			return nil, err
		}
	case !errors.Is(err, store.ErrNotFound):
		return nil, err
	}
	return resp, nil
}

func (s *Service) Directory(ctx context.Context) ([]*pb.Record, error) {
	raws, err := s.Store.DirectoryEntries(ctx)
	if err != nil {
		return nil, err
	}
	// phones verify revocations and invite rights with the network key themselves (D99, D104)
	more, err := s.Store.MembershipRecords(ctx)
	if err != nil {
		return nil, err
	}
	raws = append(raws, more...)
	// and the winning REKEYs, after the entries they refer to (D111)
	rekeys, err := s.Store.Rekeys(ctx)
	if err != nil {
		return nil, err
	}
	raws = append(raws, rekeys...)
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
	if body.Type == pb.RecordType_DIRECTORY_ENTRY {
		return false, fmt.Errorf("%w: accounts arrive by registration or replication", ErrInvalid)
	}
	_, applied, err := s.Store.ApplyFrom(ctx, rec, body, s.NodeID)
	if err == nil && applied {
		s.afterApply(ctx, body, nil)
	} else if err == nil && body.Type == pb.RecordType_MANIFEST {
		// already stored (e.g. by replication) but maybe never loaded: loading is idempotent
		if changed, lerr := s.LoadManifest(ctx); lerr == nil && changed {
			s.Notify.Manifest(s.CurrentManifest().Version)
		}
	}
	return applied, err
}

// emitConsumed records, as a node-signed record, that this node handed out a one-time prekey.
func (s *Service) emitConsumed(ctx context.Context, user []byte, dev, keyID uint32) error {
	p, _ := proto.Marshal(&pb.PrekeyConsumed{UserId: user, DeviceId: dev, KeyIds: []uint32{keyID}})
	id := make([]byte, 16)
	rand.Read(id)
	rec, err := records.SignWith(&pb.RecordBody{Id: id, Type: pb.RecordType_PREKEY_CONSUMED, Author: s.NodeID,
		CreatedMs: s.Now().UnixMilli(), Payload: p}, s.NodeKeyPriv, s.sigContext())
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
