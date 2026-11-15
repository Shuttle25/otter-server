package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
	"ottermsg/server/internal/store"
)

type rec struct {
	env, dir  int
	news      int
	low       []int
	lowOwner  [][]byte
	manifests []uint64
}

func (r *rec) Envelope([]byte, uint32) { r.env++ }
func (r *rec) Directory()              { r.dir++ }
func (r *rec) PrekeysLow(_ []byte, _ uint32, owner []byte, n int) {
	r.low = append(r.low, n)
	r.lowOwner = append(r.lowOwner, owner)
}
func (r *rec) Manifest(v uint64)          { r.manifests = append(r.manifests, v) }
func (r *rec) Online([]byte, uint32) bool { return false }
func (r *rec) News()                      { r.news++ }

type fx struct {
	t       *testing.T
	svc     *Service
	netPriv ed25519.PrivateKey
	notes   *rec
}

func newFx(t *testing.T) *fx {
	st, err := store.Open(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	pub, priv, _ := ed25519.GenerateKey(nil)
	_, nodeKey, _ := ed25519.GenerateKey(nil)
	s := New(st, nodeKey, pub)
	n := &rec{}
	s.Notify = n
	return &fx{t: t, svc: s, netPriv: priv, notes: n}
}

// manifestRec builds a network-signed manifest listing this node (plus extra nodes).
func (f *fx) manifestRec(version uint64, extra ...*pb.NodeInfo) *pb.Record {
	nodes := append([]*pb.NodeInfo{{NodeId: f.svc.NodeID, NodePub: f.svc.NodeKeyPriv.Public().(ed25519.PublicKey), Label: "self"}}, extra...)
	m := &pb.Manifest{Version: version, NetworkPub: f.svc.NetworkPub, Nodes: nodes}
	return sign(f.t, pb.RecordType_MANIFEST, keys.ID16(f.svc.NetworkPub), m, f.netPriv)
}

func (f *fx) withManifest(version uint64, extra ...*pb.NodeInfo) {
	if _, err := f.svc.ImportRecord(context.Background(), f.manifestRec(version, extra...)); err != nil {
		f.t.Fatal(err)
	}
}

func r16() []byte { b := make([]byte, 16); rand.Read(b); return b }

func sign(t *testing.T, typ pb.RecordType, author []byte, payload proto.Message, k ed25519.PrivateKey) *pb.Record {
	p, _ := proto.Marshal(payload)
	r, err := records.Sign(&pb.RecordBody{Id: r16(), Type: typ, Author: author, CreatedMs: time.Now().UnixMilli(), Payload: p}, k)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

type user struct {
	id   []byte
	priv ed25519.PrivateKey
}

// invite publishes an invite signed by the network (inviter == nil) or by a user; returns the secret.
func (f *fx) invite(inviter *user, ttl time.Duration) []byte {
	secret := make([]byte, 32)
	rand.Read(secret)
	id := sha256.Sum256(secret)
	inv := &pb.Invite{InviteId: id[:], ExpiresMs: time.Now().Add(ttl).UnixMilli()}
	if inviter == nil {
		if _, err := f.svc.ImportRecord(context.Background(), sign(f.t, pb.RecordType_INVITE, keys.ID16(f.svc.NetworkPub), inv, f.netPriv)); err != nil {
			f.t.Fatal(err)
		}
	} else {
		if _, err := f.svc.Submit(context.Background(), inviter.id, sign(f.t, pb.RecordType_INVITE, inviter.id, inv, inviter.priv), pb.RecordType_INVITE); err != nil {
			f.t.Fatal(err)
		}
	}
	return secret
}

func (f *fx) registerReq(secret []byte, username string) (*user, *pb.RegisterRequest) {
	return f.registerReqWith(secret, username, nil)
}

func (f *fx) registerReqWith(secret []byte, username string, mod func(*pb.DirectoryEntry, *pb.PreKeys, *pb.InviteUsed)) (*user, *pb.RegisterRequest) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	id := keys.ID16(pub)
	u := &user{id: id, priv: priv}
	entry := &pb.DirectoryEntry{UserId: id, Username: username, DisplayName: username, AccountPub: pub,
		IdentityPub: make([]byte, 33), IdentitySig: make([]byte, 64), Version: 1, CanInvite: true}
	pk := &pb.PreKeys{DeviceId: 1, RegistrationId: 5,
		SignedPrekey: &pb.SignedPreKey{Id: 1, PublicKey: make([]byte, 33), Signature: make([]byte, 64)},
		KyberPrekey:  &pb.SignedPreKey{Id: 1, PublicKey: make([]byte, 1569), Signature: make([]byte, 64)}}
	for i := 0; i < 12; i++ {
		pk.OneTime = append(pk.OneTime, &pb.OneTimePreKey{Id: uint32(100 + i), PublicKey: make([]byte, 33), OwnerNode: f.svc.NodeID})
	}
	sum := sha256.Sum256(secret)
	used := &pb.InviteUsed{InviteId: sum[:], UserId: id}
	if mod != nil {
		mod(entry, pk, used)
	}
	return u, &pb.RegisterRequest{InviteSecret: secret,
		DirectoryEntry: sign(f.t, pb.RecordType_DIRECTORY_ENTRY, id, entry, priv),
		Prekeys:        sign(f.t, pb.RecordType_PREKEYS, id, pk, priv),
		InviteUsed:     sign(f.t, pb.RecordType_INVITE_USED, id, used, priv)}
}

func (f *fx) mustRegister(secret []byte, name string) *user {
	u, req := f.registerReq(secret, name)
	if _, err := f.svc.Register(context.Background(), req); err != nil {
		f.t.Fatal(err)
	}
	return u
}

func TestRegisterFlow(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna")
	if f.notes.dir != 1 {
		t.Fatal("directory notification")
	}

	secret := f.invite(anna, time.Hour)
	f.mustRegister(secret, "boris")
	_, again := f.registerReq(secret, "vera")
	if _, err := f.svc.Register(ctx, again); !errors.Is(err, ErrConflict) {
		t.Fatalf("reused invite: %v", err)
	}

	_, taken := f.registerReq(f.invite(anna, time.Hour), "anna")
	if _, err := f.svc.Register(ctx, taken); !errors.Is(err, ErrConflict) {
		t.Fatalf("taken username: %v", err)
	}

	_, unknown := f.registerReq(make([]byte, 32), "gleb")
	if _, err := f.svc.Register(ctx, unknown); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown invite: %v", err)
	}

	_, expired := f.registerReq(f.invite(anna, -time.Minute+time.Second), "dina")
	f.svc.Now = func() time.Time { return time.Now().Add(time.Hour) }
	if _, err := f.svc.Register(ctx, expired); err == nil {
		t.Fatal("expired invite accepted")
	}
	f.svc.Now = time.Now

	_, bad := f.registerReq(f.invite(anna, time.Hour), "egor")
	bad.Prekeys.Signature[0] ^= 1
	if _, err := f.svc.Register(ctx, bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad prekeys sig: %v", err)
	}

	dir, _ := f.svc.Directory(ctx)
	if len(dir) != 2 {
		t.Fatalf("directory has %d entries", len(dir))
	}
}

func TestLogin(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	u := f.mustRegister(f.invite(nil, time.Hour), "anna")
	nonce := make([]byte, 32)
	rand.Read(nonce)
	ts := time.Now().UnixMilli()
	good := &pb.LoginRequest{UserId: u.id, DeviceId: 1, TsMs: ts, Signature: ed25519.Sign(u.priv, keys.AuthMessage(f.svc.NodeID, nonce, ts))}
	resp, err := f.svc.VerifyLogin(ctx, nonce, good)
	if err != nil {
		t.Fatal(err)
	}
	if resp.RegistrationId != 5 || resp.InstalledMs != 0 {
		t.Fatalf("login response: %+v", resp)
	}
	other := make([]byte, 32)
	if _, err := f.svc.VerifyLogin(ctx, other, good); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong nonce: %v", err)
	}
	old := time.Now().Add(-10 * time.Minute).UnixMilli()
	stale := &pb.LoginRequest{UserId: u.id, DeviceId: 1, TsMs: old, Signature: ed25519.Sign(u.priv, keys.AuthMessage(f.svc.NodeID, nonce, old))}
	if _, err := f.svc.VerifyLogin(ctx, nonce, stale); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("stale: %v", err)
	}
	if _, err := f.svc.VerifyLogin(ctx, nonce, &pb.LoginRequest{UserId: r16(), DeviceId: 1, TsMs: ts}); !errors.Is(err, ErrRetryLater) {
		t.Fatal("unknown user")
	}
}

func TestSubmitAndPrekeys(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	a := f.mustRegister(f.invite(nil, time.Hour), "anna")
	b := f.mustRegister(f.invite(a, time.Hour), "boris")

	env := &pb.Envelope{SenderUser: b.id, SenderDevice: 1, Kind: pb.Envelope_PREKEY_SIGNAL, Urgent: true,
		Recipients: []*pb.Recipient{{User: a.id, Device: 1, Content: []byte("ct")}}}
	r := sign(t, pb.RecordType_ENVELOPE, b.id, env, b.priv)
	if _, err := f.svc.Submit(ctx, a.id, r, pb.RecordType_ENVELOPE); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("foreign author: %v", err)
	}
	if _, err := f.svc.Submit(ctx, b.id, r, pb.RecordType_ACK); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong type: %v", err)
	}
	if _, err := f.svc.Submit(ctx, b.id, r, pb.RecordType_ENVELOPE); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Submit(ctx, b.id, r, pb.RecordType_ENVELOPE); err != nil {
		t.Fatal("resend must be idempotent")
	}
	if f.notes.env != 1 {
		t.Fatalf("envelope notifications %d", f.notes.env)
	}
	box, _ := f.svc.Mailbox(ctx, a.id, 1, 10)
	if len(box) != 1 {
		t.Fatalf("mailbox %d", len(box))
	}

	ghost := &pb.Envelope{SenderUser: b.id, SenderDevice: 1, Kind: pb.Envelope_SIGNAL,
		Recipients: []*pb.Recipient{{User: r16(), Device: 1, Content: []byte("x")}}}
	if _, err := f.svc.Submit(ctx, b.id, sign(t, pb.RecordType_ENVELOPE, b.id, ghost, b.priv), pb.RecordType_ENVELOPE); !errors.Is(err, ErrRetryLater) {
		t.Fatalf("unknown recipient: %v", err)
	}

	bundle, err := f.svc.FetchPrekeys(ctx, &pb.PreKeyFetchRequest{UserId: a.id, DeviceId: 1})
	if err != nil || bundle.OneTime == nil || bundle.RegistrationId != 5 || len(bundle.IdentityPub) != 33 {
		t.Fatalf("%v %v", bundle, err)
	}
	for i := 0; i < 12; i++ {
		f.svc.FetchPrekeys(ctx, &pb.PreKeyFetchRequest{UserId: a.id, DeviceId: 1})
	}
	last, _ := f.svc.FetchPrekeys(ctx, &pb.PreKeyFetchRequest{UserId: a.id, DeviceId: 1})
	if last.OneTime != nil {
		t.Fatal("one-time keys should be exhausted")
	}
	if len(f.notes.low) == 0 {
		t.Fatal("prekeys_low not signalled")
	}
}

func TestRegisterErrors(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna")

	_, incomplete := f.registerReq(f.invite(anna, time.Hour), "boris")
	incomplete.Prekeys = nil
	if _, err := f.svc.Register(ctx, incomplete); !errors.Is(err, ErrInvalid) {
		t.Fatalf("incomplete: %v", err)
	}
	short := &pb.RegisterRequest{InviteSecret: []byte{1}}
	if _, err := f.svc.Register(ctx, short); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short secret: %v", err)
	}

	_, badName := f.registerReqWith(f.invite(anna, time.Hour), "Bad Name!", nil)
	if _, err := f.svc.Register(ctx, badName); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad username: %v", err)
	}

	// the same account registering again through a fresh invite
	u, first := f.registerReq(f.invite(anna, time.Hour), "boris")
	if _, err := f.svc.Register(ctx, first); err != nil {
		t.Fatal(err)
	}
	secret := f.invite(anna, time.Hour)
	sum := sha256.Sum256(secret)
	again := &pb.RegisterRequest{InviteSecret: secret, DirectoryEntry: first.DirectoryEntry, Prekeys: first.Prekeys,
		InviteUsed: sign(t, pb.RecordType_INVITE_USED, u.id, &pb.InviteUsed{InviteId: sum[:], UserId: u.id}, u.priv)}
	if _, err := f.svc.Register(ctx, again); !errors.Is(err, ErrConflict) {
		t.Fatalf("already registered: %v", err)
	}

	_, noKyber := f.registerReqWith(f.invite(anna, time.Hour), "vera", func(_ *pb.DirectoryEntry, p *pb.PreKeys, _ *pb.InviteUsed) {
		p.KyberPrekey = nil
	})
	if _, err := f.svc.Register(ctx, noKyber); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no kyber: %v", err)
	}

	_, wrongInvite := f.registerReqWith(f.invite(anna, time.Hour), "vera", func(_ *pb.DirectoryEntry, _ *pb.PreKeys, u *pb.InviteUsed) {
		u.InviteId = make([]byte, 32)
	})
	if _, err := f.svc.Register(ctx, wrongInvite); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invite_used for another invite: %v", err)
	}

	// an inviter whose invite rights the admin withdrew cannot create invites (D101); the entry's own claim is ignored (C6)
	noRights, req := f.registerReqWith(f.invite(anna, time.Hour), "gleb", nil)
	if _, err := f.svc.Register(ctx, req); err != nil {
		t.Fatal(err)
	}
	withdraw := sign(t, pb.RecordType_INVITE_RIGHTS, keys.ID16(f.svc.NetworkPub), &pb.InviteRights{UserId: noRights.id, Version: 1}, f.netPriv)
	if _, err := f.svc.ImportRecord(ctx, withdraw); err != nil {
		t.Fatal(err)
	}
	inv := &pb.Invite{InviteId: make([]byte, 32), ExpiresMs: time.Now().Add(time.Hour).UnixMilli()}
	if _, err := f.svc.Submit(ctx, noRights.id, sign(t, pb.RecordType_INVITE, noRights.id, inv, noRights.priv), pb.RecordType_INVITE); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("invite without rights: %v", err)
	}
	// nothing from the failed attempts leaked into the directory
	dir, _ := f.svc.Directory(ctx)
	if len(dir) != 3 {
		t.Fatalf("directory has %d entries", len(dir))
	}
}

func TestMiscErrors(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	u := f.mustRegister(f.invite(nil, time.Hour), "anna")
	nonce := make([]byte, 32)
	ts := time.Now().UnixMilli()
	dev2 := &pb.LoginRequest{UserId: u.id, DeviceId: 2, TsMs: ts, Signature: ed25519.Sign(u.priv, keys.AuthMessage(f.svc.NodeID, nonce, ts))}
	if _, err := f.svc.VerifyLogin(ctx, nonce, dev2); !errors.Is(err, ErrInvalid) {
		t.Fatalf("device 2: %v", err)
	}
	future := time.Now().Add(10 * time.Minute).UnixMilli()
	ahead := &pb.LoginRequest{UserId: u.id, DeviceId: 1, TsMs: future, Signature: ed25519.Sign(u.priv, keys.AuthMessage(f.svc.NodeID, nonce, future))}
	if _, err := f.svc.VerifyLogin(ctx, nonce, ahead); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("future ts: %v", err)
	}
	if _, err := f.svc.FetchPrekeys(ctx, &pb.PreKeyFetchRequest{UserId: r16(), DeviceId: 1}); !errors.Is(err, ErrRetryLater) {
		t.Fatalf("prekeys unknown user: %v", err)
	}
	if _, _, err := f.svc.Manifest(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no manifest: %v", err)
	}
	m := &pb.Manifest{Version: 2, NetworkPub: f.svc.NetworkPub}
	if _, err := f.svc.ImportRecord(ctx, sign(t, pb.RecordType_MANIFEST, keys.ID16(f.svc.NetworkPub), m, f.netPriv)); err != nil {
		t.Fatal(err)
	}
	if _, v, err := f.svc.Manifest(ctx); err != nil || v != 2 {
		t.Fatalf("manifest: %d %v", v, err)
	}
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	if _, err := f.svc.ImportRecord(ctx, sign(t, pb.RecordType_MANIFEST, keys.ID16(f.svc.NetworkPub), m, otherPriv)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("forged manifest: %v", err)
	}
}
