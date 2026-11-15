package records

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

const (
	MaxBodySize        = 300 * 1024
	MaxRecipients      = 100
	MaxEnvelopeContent = 256 * 1024
	MaxAckIDs          = 1000
	MaxOneTimePrekeys  = 200
	MaxBlobSize        = 100 << 20 // ciphertext bytes of one blob (D44)
	BlobChunkSize      = 256 << 10
	MaxBlobReaders     = 100
	MaxBlobTTL         = 31 * 24 * time.Hour
	MaxPushToken       = 4096             // bytes of an FCM token (D60)
	MaxNewsText        = 4000             // runes per language of an announcement (D66)
	MaxInstallSkew     = 10 * time.Minute // INSTALL.installed_ms may be at most this far ahead of the node clock (C14)
	MaxRegistrationID  = 16380            // Signal registration ids are 1..16380
)

var (
	ErrMalformed      = errors.New("malformed record")
	ErrBadAuthor      = errors.New("author binding invalid")
	ErrBadSignature   = errors.New("signature invalid")
	ErrUnknownAuthor  = errors.New("unknown author")
	ErrRevoked        = errors.New("author revoked")
	ErrExpired        = errors.New("record expired")
	ErrBadPayload     = errors.New("payload invalid")
	ErrKeyMismatch    = errors.New("user already registered with another key")
	ErrUnknownNewsKey = errors.New("announcement key not in the manifest")
)

var usernameRe = regexp.MustCompile(`^[a-z0-9_]{3,32}$`)

type UserKey struct {
	Pub     ed25519.PublicKey
	Revoked bool
}

// UserResolver looks up a user's current account key (implemented by the store/directory).
type UserResolver interface {
	UserKey(userID []byte) (UserKey, bool)
}

// NodeResolver looks up nodes of the current manifest (node-authored records).
type NodeResolver interface {
	NodeKey(nodeID []byte) (ed25519.PublicKey, bool)
}

// NewsResolver looks up news keys of the current manifest by ID16(pub) (D65).
type NewsResolver interface {
	NewsKey(id []byte) (ed25519.PublicKey, bool)
}

type Validator struct {
	NetworkPub ed25519.PublicKey
	Users      UserResolver
	Nodes      NodeResolver // nil: node-authored records are rejected
	News       NewsResolver // nil: announcements are rejected
	Now        func() time.Time
}

func networkAuthored(t pb.RecordType) bool {
	return t == pb.RecordType_MANIFEST || t == pb.RecordType_REVOCATION || t == pb.RecordType_INVITE_RIGHTS
}

// Validate checks structure, author binding, signature and type-specific payload rules.
// It returns the parsed body on success.
func (v *Validator) Validate(r *pb.Record) (*pb.RecordBody, error) {
	if len(r.GetBody()) == 0 || len(r.GetBody()) > MaxBodySize || len(r.GetSignature()) != ed25519.SignatureSize {
		return nil, ErrMalformed
	}
	var body pb.RecordBody
	if err := proto.Unmarshal(r.Body, &body); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if len(body.Id) != 16 || len(body.Author) != 16 {
		return nil, ErrMalformed
	}
	if _, known := pb.RecordType_name[int32(body.Type)]; !known || body.Type == pb.RecordType_RECORD_TYPE_UNSPECIFIED {
		return nil, ErrMalformed
	}
	if body.ExpiresMs != 0 && body.ExpiresMs < v.Now().UnixMilli() {
		return nil, ErrExpired
	}
	key, err := v.signerKey(&body)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(key, r.Body, r.Signature) {
		return nil, ErrBadSignature
	}
	if err := v.checkPayload(&body); err != nil {
		return nil, err
	}
	return &body, nil
}

func (v *Validator) signerKey(b *pb.RecordBody) (ed25519.PublicKey, error) {
	switch {
	case networkAuthored(b.Type):
		if !bytes.Equal(b.Author, keys.ID16(v.NetworkPub)) {
			return nil, ErrBadAuthor
		}
		return v.NetworkPub, nil
	case b.Type == pb.RecordType_INVITE && bytes.Equal(b.Author, keys.ID16(v.NetworkPub)):
		return v.NetworkPub, nil // bootstrap invite for the first member
	case b.Type == pb.RecordType_DIRECTORY_ENTRY:
		var e pb.DirectoryEntry
		if err := proto.Unmarshal(b.Payload, &e); err != nil || len(e.AccountPub) != ed25519.PublicKeySize {
			return nil, ErrBadPayload
		}
		if !bytes.Equal(b.Author, e.UserId) || !bytes.Equal(e.UserId, keys.ID16(e.AccountPub)) {
			return nil, ErrBadAuthor
		}
		if k, ok := v.Users.UserKey(e.UserId); ok {
			if k.Revoked {
				return nil, ErrRevoked
			}
			if !bytes.Equal(k.Pub, e.AccountPub) {
				return nil, ErrKeyMismatch
			}
		}
		return ed25519.PublicKey(e.AccountPub), nil
	case b.Type == pb.RecordType_PREKEY_CONSUMED:
		if v.Nodes == nil {
			return nil, ErrUnknownAuthor
		}
		k, ok := v.Nodes.NodeKey(b.Author)
		if !ok {
			return nil, ErrUnknownAuthor
		}
		return k, nil
	case b.Type == pb.RecordType_ANNOUNCEMENT || b.Type == pb.RecordType_ANNOUNCEMENT_DELETED:
		if v.News == nil {
			return nil, ErrUnknownNewsKey
		}
		k, ok := v.News.NewsKey(b.Author)
		if !ok {
			return nil, ErrUnknownNewsKey
		}
		return k, nil
	default:
		k, ok := v.Users.UserKey(b.Author)
		if !ok {
			return nil, ErrUnknownAuthor
		}
		if k.Revoked {
			return nil, ErrRevoked
		}
		return k.Pub, nil
	}
}

// MaxInviteTTL: an invite lives at most this long, created_ms to expires_ms (C8, D107).
const MaxInviteTTL = 30 * 24 * time.Hour

// InviteLifetimeOK: an invite expires after its creation and lives at most MaxInviteTTL (C8, D107).
func InviteLifetimeOK(createdMs, expiresMs int64) bool {
	return expiresMs > createdMs && expiresMs-createdMs <= MaxInviteTTL.Milliseconds()
}

func (v *Validator) checkPayload(b *pb.RecordBody) error {
	switch b.Type {
	case pb.RecordType_BLOB_META:
		return checkBlobMeta(b)
	case pb.RecordType_BACKUP_META:
		return checkBackupMeta(b)
	case pb.RecordType_PUSH_TOKEN:
		return checkPushToken(b)
	case pb.RecordType_ANNOUNCEMENT:
		return checkAnnouncement(b)
	case pb.RecordType_ANNOUNCEMENT_DELETED:
		var d pb.AnnouncementDeleted
		if err := proto.Unmarshal(b.Payload, &d); err != nil || len(d.Target) != 32 || b.ExpiresMs != 0 {
			return ErrBadPayload
		}
	case pb.RecordType_BLOB_FETCHED:
		var f pb.BlobFetched
		if err := proto.Unmarshal(b.Payload, &f); err != nil || len(f.BlobKey) != 32 {
			return ErrBadPayload
		}
	case pb.RecordType_MANIFEST:
		var m pb.Manifest
		if err := proto.Unmarshal(b.Payload, &m); err != nil || !bytes.Equal(m.NetworkPub, v.NetworkPub) || m.Version == 0 {
			return ErrBadPayload
		}
	case pb.RecordType_REVOCATION: // D99: permanent, so no expiry
		var r pb.Revocation
		if err := proto.Unmarshal(b.Payload, &r); err != nil || len(r.UserId) != 16 || !utf8.ValidString(r.Reason) ||
			utf8.RuneCountInString(r.Reason) > 200 || b.ExpiresMs != 0 {
			return ErrBadPayload
		}
	case pb.RecordType_INVITE_RIGHTS:
		var r pb.InviteRights
		if err := proto.Unmarshal(b.Payload, &r); err != nil || len(r.UserId) != 16 || r.Version == 0 || b.ExpiresMs != 0 {
			return ErrBadPayload
		}
	case pb.RecordType_DIRECTORY_ENTRY:
		var e pb.DirectoryEntry
		_ = proto.Unmarshal(b.Payload, &e) // already parsed in signerKey
		n := utf8.RuneCountInString(e.DisplayName)
		if !usernameRe.MatchString(e.Username) || n < 1 || n > 64 || !utf8.ValidString(e.DisplayName) ||
			len(e.IdentityPub) != 33 || len(e.IdentitySig) != 64 || e.Version == 0 {
			return ErrBadPayload
		}
		if e.RegisteredMs > b.CreatedMs+int64(5*time.Minute/time.Millisecond) { // D40: registration precedes the entry
			return ErrBadPayload
		}
	case pb.RecordType_ACK:
		var a pb.Ack
		if err := proto.Unmarshal(b.Payload, &a); err != nil || len(a.EnvelopeIds) == 0 || len(a.EnvelopeIds) > MaxAckIDs {
			return ErrBadPayload
		}
		for _, id := range a.EnvelopeIds {
			if len(id) != 32 {
				return ErrBadPayload
			}
		}
	case pb.RecordType_INVITE:
		var i pb.Invite
		if err := proto.Unmarshal(b.Payload, &i); err != nil || len(i.InviteId) != 32 || !InviteLifetimeOK(b.CreatedMs, i.ExpiresMs) {
			return ErrBadPayload
		}
	case pb.RecordType_INVITE_USED:
		var u pb.InviteUsed
		if err := proto.Unmarshal(b.Payload, &u); err != nil || len(u.InviteId) != 32 || !bytes.Equal(u.UserId, b.Author) {
			return ErrBadPayload
		}
	case pb.RecordType_PREKEY_CONSUMED:
		var c pb.PrekeyConsumed
		if err := proto.Unmarshal(b.Payload, &c); err != nil || len(c.UserId) != 16 || c.DeviceId == 0 ||
			len(c.KeyIds) == 0 || len(c.KeyIds) > MaxOneTimePrekeys {
			return ErrBadPayload
		}
	case pb.RecordType_ENVELOPE:
		return checkEnvelope(b)
	case pb.RecordType_PREKEYS:
		return checkPrekeys(b)
	case pb.RecordType_INSTALL:
		var in pb.Install
		if err := proto.Unmarshal(b.Payload, &in); err != nil || in.RegistrationId < 1 || in.RegistrationId > MaxRegistrationID ||
			in.InstalledMs < 0 || in.InstalledMs > v.Now().Add(MaxInstallSkew).UnixMilli() || b.ExpiresMs != 0 {
			return ErrBadPayload
		}
	}
	return nil
}

func checkEnvelope(b *pb.RecordBody) error {
	var e pb.Envelope
	if err := proto.Unmarshal(b.Payload, &e); err != nil {
		return ErrBadPayload
	}
	if !bytes.Equal(e.SenderUser, b.Author) || e.SenderDevice != 1 || e.Kind == pb.Envelope_KIND_UNSPECIFIED ||
		len(e.Recipients) == 0 || len(e.Recipients) > MaxRecipients {
		return ErrBadPayload
	}
	// SENDER_KEY: one shared ciphertext, no per-recipient content; SIGNAL/PREKEY_SIGNAL: the opposite.
	isGroup := e.Kind == pb.Envelope_SENDER_KEY
	if isGroup != (len(e.SharedContent) > 0) {
		return ErrBadPayload
	}
	total := len(e.SharedContent)
	for _, r := range e.Recipients {
		if len(r.User) != 16 || r.Device == 0 || isGroup != (len(r.Content) == 0) {
			return ErrBadPayload
		}
		total += len(r.Content)
	}
	if total > MaxEnvelopeContent {
		return ErrBadPayload
	}
	return nil
}

// checkPushToken: device 1, kind FCM; a 1..MaxPushToken-byte UTF-8 token, or withdrawn with no token (D60, D94).
func checkPushToken(b *pb.RecordBody) error {
	var p pb.PushToken
	if err := proto.Unmarshal(b.Payload, &p); err != nil || p.DeviceId != 1 || p.Kind != pb.PushToken_FCM {
		return ErrBadPayload
	}
	if p.Withdrawn {
		if p.Token != "" || p.MessagesOff {
			return ErrBadPayload
		}
		return nil
	}
	if len(p.Token) == 0 || len(p.Token) > MaxPushToken || !utf8.ValidString(p.Token) {
		return ErrBadPayload
	}
	return nil
}

// checkAnnouncement: texts and the optional app update (D66).
func checkAnnouncement(b *pb.RecordBody) error {
	var a pb.Announcement
	if err := proto.Unmarshal(b.Payload, &a); err != nil || b.ExpiresMs != 0 {
		return ErrBadPayload
	}
	text := func(s string) bool {
		return utf8.ValidString(s) && utf8.RuneCountInString(s) <= MaxNewsText
	}
	if !text(a.TextRu) || !text(a.TextEn) || strings.TrimSpace(a.TextRu)+strings.TrimSpace(a.TextEn) == "" {
		return ErrBadPayload
	}
	if u := a.Update; u != nil {
		if n := utf8.RuneCountInString(u.VersionName); n < 1 || n > 32 || u.VersionCode == 0 || len(u.Sha256) != 32 ||
			u.Size == 0 || u.Size > MaxBlobSize {
			return ErrBadPayload
		}
	}
	return nil
}

func checkSigned(k *pb.SignedPreKey, minPub, maxPub int) bool {
	return k == nil || (len(k.PublicKey) >= minPub && len(k.PublicKey) <= maxPub && len(k.Signature) == 64)
}

func checkPrekeys(b *pb.RecordBody) error {
	var p pb.PreKeys
	if err := proto.Unmarshal(b.Payload, &p); err != nil {
		return ErrBadPayload
	}
	if p.DeviceId != 1 || p.RegistrationId == 0 || !checkSigned(p.SignedPrekey, 33, 33) ||
		!checkSigned(p.KyberPrekey, 1000, 2000) || len(p.OneTime) > MaxOneTimePrekeys {
		return ErrBadPayload
	}
	for _, k := range p.OneTime {
		if len(k.PublicKey) != 33 || len(k.OwnerNode) != 16 {
			return ErrBadPayload
		}
	}
	return nil
}

// checkBlobMeta: size, chunk layout, hashes, readers and expiry of a blob announcement (D44).
func checkBlobMeta(b *pb.RecordBody) error {
	var m pb.BlobMeta
	if err := proto.Unmarshal(b.Payload, &m); err != nil {
		return ErrBadPayload
	}
	if m.Size == 0 || m.Size > MaxBlobSize || m.ChunkSize != BlobChunkSize {
		return ErrBadPayload
	}
	n := (m.Size + BlobChunkSize - 1) / BlobChunkSize
	if uint64(len(m.ChunkSha256)) != n {
		return ErrBadPayload
	}
	for _, h := range m.ChunkSha256 {
		if len(h) != 32 {
			return ErrBadPayload
		}
	}
	if m.Persistent {
		if len(m.Readers) != 0 || b.ExpiresMs != 0 {
			return ErrBadPayload
		}
		return nil
	}
	if len(m.Readers) == 0 || len(m.Readers) > MaxBlobReaders {
		return ErrBadPayload
	}
	seen := map[string]bool{}
	for _, r := range m.Readers {
		if len(r) != 16 || bytes.Equal(r, b.Author) || seen[string(r)] {
			return ErrBadPayload
		}
		seen[string(r)] = true
	}
	if b.ExpiresMs == 0 || b.ExpiresMs > b.CreatedMs+MaxBlobTTL.Milliseconds() {
		return ErrBadPayload
	}
	return nil
}

// checkBackupMeta: a user's password backup pointer (D50), or a decoy (version 0, C20): no blob, size 0 and blob key
// author ‖ 16 zero bytes, so backup.auth answers alike for members with and without a backup.
func checkBackupMeta(b *pb.RecordBody) error {
	var m pb.BackupMeta
	if err := proto.Unmarshal(b.Payload, &m); err != nil {
		return ErrBadPayload
	}
	switch {
	case b.ExpiresMs != 0, len(m.Salt) != 16, len(m.AuthVerifier) != 32,
		m.KdfMKib < 19456 || m.KdfMKib > 262144, m.KdfT < 1 || m.KdfT > 10, m.KdfP < 1 || m.KdfP > 4,
		len(m.BlobKey) != 32 || !bytes.Equal(m.BlobKey[:16], b.Author):
		return ErrBadPayload
	case m.Version == 0:
		if m.Size != 0 || !bytes.Equal(m.BlobKey[16:], make([]byte, 16)) {
			return ErrBadPayload
		}
	case m.Size == 0 || m.Size > MaxBlobSize:
		return ErrBadPayload
	}
	return nil
}
