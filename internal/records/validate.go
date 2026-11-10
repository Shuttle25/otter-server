package records

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
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
)

var (
	ErrMalformed     = errors.New("malformed record")
	ErrBadAuthor     = errors.New("author binding invalid")
	ErrBadSignature  = errors.New("signature invalid")
	ErrUnknownAuthor = errors.New("unknown author")
	ErrRevoked       = errors.New("author revoked")
	ErrExpired       = errors.New("record expired")
	ErrBadPayload    = errors.New("payload invalid")
	ErrKeyMismatch   = errors.New("user already registered with another key")
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

type Validator struct {
	NetworkPub ed25519.PublicKey
	Users      UserResolver
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

func (v *Validator) checkPayload(b *pb.RecordBody) error {
	switch b.Type {
	case pb.RecordType_MANIFEST:
		var m pb.Manifest
		if err := proto.Unmarshal(b.Payload, &m); err != nil || !bytes.Equal(m.NetworkPub, v.NetworkPub) || m.Version == 0 {
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
		if err := proto.Unmarshal(b.Payload, &i); err != nil || len(i.InviteId) != 32 || i.ExpiresMs <= 0 {
			return ErrBadPayload
		}
	case pb.RecordType_INVITE_USED:
		var u pb.InviteUsed
		if err := proto.Unmarshal(b.Payload, &u); err != nil || len(u.InviteId) != 32 || !bytes.Equal(u.UserId, b.Author) {
			return ErrBadPayload
		}
	case pb.RecordType_ENVELOPE:
		return checkEnvelope(b)
	case pb.RecordType_PREKEYS:
		return checkPrekeys(b)
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
	total := len(e.SharedContent)
	for _, r := range e.Recipients {
		if len(r.User) != 16 || r.Device == 0 || (len(r.Content) == 0 && len(e.SharedContent) == 0) {
			return ErrBadPayload
		}
		total += len(r.Content)
	}
	if total > MaxEnvelopeContent {
		return ErrBadPayload
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
