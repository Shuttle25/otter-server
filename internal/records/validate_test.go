package records

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

type fakeUsers map[string]UserKey

func (f fakeUsers) UserKey(id []byte) (UserKey, bool) { k, ok := f[string(id)]; return k, ok }

var now = time.UnixMilli(1_800_000_000_000)

func rid() []byte { b := make([]byte, 16); rand.Read(b); return b }

func mustSign(t *testing.T, b *pb.RecordBody, k ed25519.PrivateKey) *pb.Record {
	t.Helper()
	r, err := Sign(b, k)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func payload(m proto.Message) []byte { b, _ := proto.Marshal(m); return b }

func TestValidate(t *testing.T) {
	netPub, netPriv, _ := ed25519.GenerateKey(nil)
	netID := keys.ID16(netPub)
	userPub, userPriv, _ := ed25519.GenerateKey(nil)
	userID := keys.ID16(userPub)
	revPub, revPriv, _ := ed25519.GenerateKey(nil)
	revID := keys.ID16(revPub)
	otherPub, otherPriv, _ := ed25519.GenerateKey(nil)
	_ = otherPub

	users := fakeUsers{string(userID): {Pub: userPub}, string(revID): {Pub: revPub, Revoked: true}}
	v := &Validator{NetworkPub: netPub, Users: users, Now: func() time.Time { return now }}

	entry := func(pub ed25519.PublicKey, username string) *pb.DirectoryEntry {
		return &pb.DirectoryEntry{UserId: keys.ID16(pub), Username: username, DisplayName: "Мама",
			AccountPub: pub, IdentityPub: make([]byte, 33), IdentitySig: make([]byte, 64), Version: 1, CanInvite: true}
	}
	newPub, newPriv, _ := ed25519.GenerateKey(nil)
	manifest := &pb.Manifest{Version: 1, NetworkPub: netPub}
	ack := payload(&pb.Ack{EnvelopeIds: [][]byte{make([]byte, 32)}, DeviceId: 1})

	cases := []struct {
		name string
		rec  func() *pb.Record
		want error
	}{
		{"manifest ok", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_MANIFEST, Author: netID, Payload: payload(manifest)}, netPriv)
		}, nil},
		{"manifest signed by user", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_MANIFEST, Author: netID, Payload: payload(manifest)}, userPriv)
		}, ErrBadSignature},
		{"manifest wrong author", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_MANIFEST, Author: userID, Payload: payload(manifest)}, netPriv)
		}, ErrBadAuthor},
		{"manifest foreign network_pub", func() *pb.Record {
			m := &pb.Manifest{Version: 1, NetworkPub: userPub}
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_MANIFEST, Author: netID, Payload: payload(m)}, netPriv)
		}, ErrBadPayload},
		{"new directory entry ok", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_DIRECTORY_ENTRY, Author: keys.ID16(newPub), Payload: payload(entry(newPub, "mama_1"))}, newPriv)
		}, nil},
		{"directory entry bad username", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_DIRECTORY_ENTRY, Author: keys.ID16(newPub), Payload: payload(entry(newPub, "Mama!"))}, newPriv)
		}, ErrBadPayload},
		{"directory entry long display name", func() *pb.Record {
			e := entry(newPub, "mama")
			e.DisplayName = strings.Repeat("я", 65)
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_DIRECTORY_ENTRY, Author: keys.ID16(newPub), Payload: payload(e)}, newPriv)
		}, ErrBadPayload},
		{"directory entry registered_ms = created_ms ok", func() *pb.Record {
			e := entry(newPub, "mama")
			e.RegisteredMs = now.UnixMilli()
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_DIRECTORY_ENTRY, Author: keys.ID16(newPub), CreatedMs: now.UnixMilli(), Payload: payload(e)}, newPriv)
		}, nil},
		{"directory entry registered after created", func() *pb.Record {
			e := entry(newPub, "mama")
			e.RegisteredMs = now.Add(10 * time.Minute).UnixMilli()
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_DIRECTORY_ENTRY, Author: keys.ID16(newPub), CreatedMs: now.UnixMilli(), Payload: payload(e)}, newPriv)
		}, ErrBadPayload},
		{"directory entry author != user_id", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_DIRECTORY_ENTRY, Author: userID, Payload: payload(entry(newPub, "mama"))}, newPriv)
		}, ErrBadAuthor},
		{"directory entry key takeover", func() *pb.Record {
			e := entry(otherPub, "x_y_z")
			e.UserId = userID
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_DIRECTORY_ENTRY, Author: userID, Payload: payload(e)}, otherPriv)
		}, ErrBadAuthor},
		{"directory entry by revoked user", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_DIRECTORY_ENTRY, Author: revID, Payload: payload(entry(revPub, "revoked"))}, revPriv)
		}, ErrRevoked},
		{"ack by known user ok", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ACK, Author: userID, Payload: ack}, userPriv)
		}, nil},
		{"ack by unknown user", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ACK, Author: keys.ID16(otherPub), Payload: ack}, otherPriv)
		}, ErrUnknownAuthor},
		{"ack by revoked user", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ACK, Author: revID, Payload: ack}, revPriv)
		}, ErrRevoked},
		{"expired", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ACK, Author: userID, ExpiresMs: now.UnixMilli() - 1, Payload: ack}, userPriv)
		}, ErrExpired},
		{"unspecified type", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Author: userID}, userPriv)
		}, ErrMalformed},
		{"short id", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: []byte{1}, Type: pb.RecordType_ACK, Author: userID, Payload: ack}, userPriv)
		}, ErrMalformed},
		{"oversized", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ACK, Author: userID, Payload: make([]byte, MaxBodySize+1)}, userPriv)
		}, ErrMalformed},
		{"truncated signature", func() *pb.Record {
			r := mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ACK, Author: userID, Payload: ack}, userPriv)
			r.Signature = r.Signature[:10]
			return r
		}, ErrMalformed},
		{"network invite ok", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_INVITE, Author: netID,
				Payload: payload(&pb.Invite{InviteId: make([]byte, 32), ExpiresMs: now.UnixMilli() + 1000})}, netPriv)
		}, nil},
		{"user invite ok", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_INVITE, Author: userID,
				Payload: payload(&pb.Invite{InviteId: make([]byte, 32), ExpiresMs: now.UnixMilli() + 1000})}, userPriv)
		}, nil},
		{"invite short id", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_INVITE, Author: userID,
				Payload: payload(&pb.Invite{InviteId: make([]byte, 31), ExpiresMs: 1})}, userPriv)
		}, ErrBadPayload},
		{"invite no expiry", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_INVITE, Author: userID,
				Payload: payload(&pb.Invite{InviteId: make([]byte, 32)})}, userPriv)
		}, ErrBadPayload},
		{"invite_used ok", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_INVITE_USED, Author: userID,
				Payload: payload(&pb.InviteUsed{InviteId: make([]byte, 32), UserId: userID})}, userPriv)
		}, nil},
		{"invite_used short id", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_INVITE_USED, Author: userID,
				Payload: payload(&pb.InviteUsed{InviteId: make([]byte, 16), UserId: userID})}, userPriv)
		}, ErrBadPayload},
		{"invite_used for someone else", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_INVITE_USED, Author: userID,
				Payload: payload(&pb.InviteUsed{InviteId: make([]byte, 32), UserId: revID})}, userPriv)
		}, ErrBadPayload},
		{"envelope ok", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ENVELOPE, Author: userID,
				Payload: payload(envelope(userID, 1, pb.Envelope_SIGNAL, []*pb.Recipient{{User: revID, Device: 1, Content: []byte{1}}}))}, userPriv)
		}, nil},
		{"envelope shared content ok", func() *pb.Record {
			e := envelope(userID, 1, pb.Envelope_SENDER_KEY, []*pb.Recipient{{User: revID, Device: 1}})
			e.SharedContent = []byte{1}
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ENVELOPE, Author: userID, Payload: payload(e)}, userPriv)
		}, nil},
		{"sender_key with per-recipient content", func() *pb.Record {
			e := envelope(userID, 1, pb.Envelope_SENDER_KEY, []*pb.Recipient{{User: revID, Device: 1, Content: []byte{1}}})
			e.SharedContent = []byte{1}
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ENVELOPE, Author: userID, Payload: payload(e)}, userPriv)
		}, ErrBadPayload},
		{"sender_key without shared content", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ENVELOPE, Author: userID,
				Payload: payload(envelope(userID, 1, pb.Envelope_SENDER_KEY, []*pb.Recipient{{User: revID, Device: 1}}))}, userPriv)
		}, ErrBadPayload},
		{"sender_key many recipients ok", func() *pb.Record {
			e := envelope(userID, 1, pb.Envelope_SENDER_KEY, []*pb.Recipient{{User: revID, Device: 1}, {User: userID, Device: 1}})
			e.SharedContent = make([]byte, 100)
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ENVELOPE, Author: userID, Payload: payload(e)}, userPriv)
		}, nil},
		{"signal with shared content", func() *pb.Record {
			e := envelope(userID, 1, pb.Envelope_SIGNAL, []*pb.Recipient{{User: revID, Device: 1, Content: []byte{1}}})
			e.SharedContent = []byte{1}
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ENVELOPE, Author: userID, Payload: payload(e)}, userPriv)
		}, ErrBadPayload},
		{"prekey_signal with shared content only", func() *pb.Record {
			e := envelope(userID, 1, pb.Envelope_PREKEY_SIGNAL, []*pb.Recipient{{User: revID, Device: 1}})
			e.SharedContent = []byte{1}
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ENVELOPE, Author: userID, Payload: payload(e)}, userPriv)
		}, ErrBadPayload},
		{"envelope spoofed sender", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ENVELOPE, Author: userID,
				Payload: payload(envelope(revID, 1, pb.Envelope_SIGNAL, []*pb.Recipient{{User: revID, Device: 1, Content: []byte{1}}}))}, userPriv)
		}, ErrBadPayload},
		{"envelope sender device 2", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ENVELOPE, Author: userID,
				Payload: payload(envelope(userID, 2, pb.Envelope_SIGNAL, []*pb.Recipient{{User: revID, Device: 1, Content: []byte{1}}}))}, userPriv)
		}, ErrBadPayload},
		{"envelope unspecified kind", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ENVELOPE, Author: userID,
				Payload: payload(envelope(userID, 1, pb.Envelope_KIND_UNSPECIFIED, []*pb.Recipient{{User: revID, Device: 1, Content: []byte{1}}}))}, userPriv)
		}, ErrBadPayload},
		{"envelope no recipients", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ENVELOPE, Author: userID,
				Payload: payload(envelope(userID, 1, pb.Envelope_SIGNAL, nil))}, userPriv)
		}, ErrBadPayload},
		{"envelope too many recipients", func() *pb.Record {
			rs := make([]*pb.Recipient, MaxRecipients+1)
			for i := range rs {
				rs[i] = &pb.Recipient{User: revID, Device: 1, Content: []byte{1}}
			}
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ENVELOPE, Author: userID,
				Payload: payload(envelope(userID, 1, pb.Envelope_SIGNAL, rs))}, userPriv)
		}, ErrBadPayload},
		{"envelope recipient short user", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ENVELOPE, Author: userID,
				Payload: payload(envelope(userID, 1, pb.Envelope_SIGNAL, []*pb.Recipient{{User: revID[:15], Device: 1, Content: []byte{1}}}))}, userPriv)
		}, ErrBadPayload},
		{"envelope recipient device 0", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ENVELOPE, Author: userID,
				Payload: payload(envelope(userID, 1, pb.Envelope_SIGNAL, []*pb.Recipient{{User: revID, Device: 0, Content: []byte{1}}}))}, userPriv)
		}, ErrBadPayload},
		{"envelope empty content", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ENVELOPE, Author: userID,
				Payload: payload(envelope(userID, 1, pb.Envelope_SIGNAL, []*pb.Recipient{{User: revID, Device: 1}}))}, userPriv)
		}, ErrBadPayload},
		{"envelope content too large", func() *pb.Record {
			half := MaxEnvelopeContent/2 + 1
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ENVELOPE, Author: userID,
				Payload: payload(envelope(userID, 1, pb.Envelope_SIGNAL, []*pb.Recipient{
					{User: revID, Device: 1, Content: make([]byte, half)}, {User: userID, Device: 1, Content: make([]byte, half)}}))}, userPriv)
		}, ErrBadPayload},
		{"ack bad id length", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ACK, Author: userID,
				Payload: payload(&pb.Ack{EnvelopeIds: [][]byte{make([]byte, 16)}, DeviceId: 1})}, userPriv)
		}, ErrBadPayload},
		{"ack empty", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ACK, Author: userID,
				Payload: payload(&pb.Ack{DeviceId: 1})}, userPriv)
		}, ErrBadPayload},
		{"ack too many ids", func() *pb.Record {
			ids := make([][]byte, MaxAckIDs+1)
			for i := range ids {
				ids[i] = make([]byte, 32)
			}
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ACK, Author: userID,
				Payload: payload(&pb.Ack{EnvelopeIds: ids, DeviceId: 1})}, userPriv)
		}, ErrBadPayload},
		{"prekeys ok", func() *pb.Record {
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_PREKEYS, Author: userID,
				Payload: payload(validPrekeys())}, userPriv)
		}, nil},
		{"prekeys one-time only ok", func() *pb.Record {
			p := validPrekeys()
			p.SignedPrekey, p.KyberPrekey = nil, nil
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_PREKEYS, Author: userID, Payload: payload(p)}, userPriv)
		}, nil},
		{"prekeys bad device", func() *pb.Record {
			p := validPrekeys()
			p.DeviceId = 2
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_PREKEYS, Author: userID, Payload: payload(p)}, userPriv)
		}, ErrBadPayload},
		{"prekeys no registration id", func() *pb.Record {
			p := validPrekeys()
			p.RegistrationId = 0
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_PREKEYS, Author: userID, Payload: payload(p)}, userPriv)
		}, ErrBadPayload},
		{"prekeys bad signed key", func() *pb.Record {
			p := validPrekeys()
			p.SignedPrekey.PublicKey = make([]byte, 32)
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_PREKEYS, Author: userID, Payload: payload(p)}, userPriv)
		}, ErrBadPayload},
		{"prekeys bad signed sig", func() *pb.Record {
			p := validPrekeys()
			p.SignedPrekey.Signature = make([]byte, 63)
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_PREKEYS, Author: userID, Payload: payload(p)}, userPriv)
		}, ErrBadPayload},
		{"prekeys kyber too small", func() *pb.Record {
			p := validPrekeys()
			p.KyberPrekey.PublicKey = make([]byte, 999)
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_PREKEYS, Author: userID, Payload: payload(p)}, userPriv)
		}, ErrBadPayload},
		{"prekeys kyber too large", func() *pb.Record {
			p := validPrekeys()
			p.KyberPrekey.PublicKey = make([]byte, 2001)
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_PREKEYS, Author: userID, Payload: payload(p)}, userPriv)
		}, ErrBadPayload},
		{"prekeys too many one-time", func() *pb.Record {
			p := validPrekeys()
			for len(p.OneTime) <= MaxOneTimePrekeys {
				p.OneTime = append(p.OneTime, &pb.OneTimePreKey{Id: uint32(len(p.OneTime) + 1), PublicKey: make([]byte, 33), OwnerNode: make([]byte, 16)})
			}
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_PREKEYS, Author: userID, Payload: payload(p)}, userPriv)
		}, ErrBadPayload},
		{"prekeys bad one-time pub", func() *pb.Record {
			p := validPrekeys()
			p.OneTime[0].PublicKey = make([]byte, 32)
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_PREKEYS, Author: userID, Payload: payload(p)}, userPriv)
		}, ErrBadPayload},
		{"prekeys bad one-time owner", func() *pb.Record {
			p := validPrekeys()
			p.OneTime[0].OwnerNode = nil
			return mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_PREKEYS, Author: userID, Payload: payload(p)}, userPriv)
		}, ErrBadPayload},
		{"tampered body", func() *pb.Record {
			r := mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_ACK, Author: userID, Payload: ack}, userPriv)
			r.Body[len(r.Body)-1] ^= 1
			return r
		}, ErrBadSignature},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := v.Validate(c.rec())
			if c.want == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("want %v, got %v", c.want, err)
			}
		})
	}
}

func validPrekeys() *pb.PreKeys {
	return &pb.PreKeys{DeviceId: 1, RegistrationId: 7,
		SignedPrekey: &pb.SignedPreKey{Id: 1, PublicKey: make([]byte, 33), Signature: make([]byte, 64)},
		KyberPrekey:  &pb.SignedPreKey{Id: 1, PublicKey: make([]byte, 1569), Signature: make([]byte, 64)},
		OneTime:      []*pb.OneTimePreKey{{Id: 1, PublicKey: make([]byte, 33), OwnerNode: make([]byte, 16)}}}
}

func envelope(sender []byte, device uint32, kind pb.Envelope_Kind, rs []*pb.Recipient) *pb.Envelope {
	return &pb.Envelope{SenderUser: sender, SenderDevice: device, Kind: kind, Recipients: rs}
}

type fakeNodes map[string]ed25519.PublicKey

func (f fakeNodes) NodeKey(id []byte) (ed25519.PublicKey, bool) { k, ok := f[string(id)]; return k, ok }

func TestNodeAuthoredRecords(t *testing.T) {
	netPub, _, _ := ed25519.GenerateKey(nil)
	nodePub, nodePriv, _ := ed25519.GenerateKey(nil)
	nodeID := keys.ID16(nodePub)
	otherPub, otherPriv, _ := ed25519.GenerateKey(nil)
	userPub, userPriv, _ := ed25519.GenerateKey(nil)
	userID := keys.ID16(userPub)
	users := fakeUsers{string(userID): {Pub: userPub}}
	v := &Validator{NetworkPub: netPub, Users: users, Nodes: fakeNodes{string(nodeID): nodePub}, Now: func() time.Time { return now }}
	consumed := func(ids ...uint32) []byte {
		return payload(&pb.PrekeyConsumed{UserId: userID, DeviceId: 1, KeyIds: ids})
	}
	many := make([]uint32, MaxOneTimePrekeys+1)

	cases := []struct {
		name string
		v    *Validator
		rec  *pb.Record
		want error
	}{
		{"node signed ok", v, mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_PREKEY_CONSUMED, Author: nodeID, Payload: consumed(7)}, nodePriv), nil},
		{"unknown node", v, mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_PREKEY_CONSUMED, Author: keys.ID16(otherPub), Payload: consumed(7)}, otherPriv), ErrUnknownAuthor},
		{"user signed", v, mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_PREKEY_CONSUMED, Author: userID, Payload: consumed(7)}, userPriv), ErrUnknownAuthor},
		{"wrong node key", v, mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_PREKEY_CONSUMED, Author: nodeID, Payload: consumed(7)}, otherPriv), ErrBadSignature},
		{"no key ids", v, mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_PREKEY_CONSUMED, Author: nodeID, Payload: consumed()}, nodePriv), ErrBadPayload},
		{"too many key ids", v, mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_PREKEY_CONSUMED, Author: nodeID, Payload: consumed(many...)}, nodePriv), ErrBadPayload},
		{"short user id", v, mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_PREKEY_CONSUMED, Author: nodeID,
			Payload: payload(&pb.PrekeyConsumed{UserId: userID[:15], DeviceId: 1, KeyIds: []uint32{1}})}, nodePriv), ErrBadPayload},
		{"device 0", v, mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_PREKEY_CONSUMED, Author: nodeID,
			Payload: payload(&pb.PrekeyConsumed{UserId: userID, KeyIds: []uint32{1}})}, nodePriv), ErrBadPayload},
		{"no node resolver", &Validator{NetworkPub: netPub, Users: users, Now: v.Now},
			mustSign(t, &pb.RecordBody{Id: rid(), Type: pb.RecordType_PREKEY_CONSUMED, Author: nodeID, Payload: consumed(7)}, nodePriv), ErrUnknownAuthor},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.v.Validate(c.rec)
			if c.want == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("want %v, got %v", c.want, err)
			}
		})
	}
}

func backupMetaBody(t *testing.T, author []byte, mut func(*pb.BackupMeta, *pb.RecordBody)) *pb.RecordBody {
	t.Helper()
	m := &pb.BackupMeta{Version: 1, Salt: make([]byte, 16), KdfMKib: 65536, KdfT: 3, KdfP: 1,
		AuthVerifier: make([]byte, 32), BlobKey: append(append([]byte{}, author...), make([]byte, 16)...), Size: 1000}
	b := &pb.RecordBody{Id: make([]byte, 16), Type: pb.RecordType_BACKUP_META, Author: author, CreatedMs: 1}
	if mut != nil {
		mut(m, b)
	}
	b.Payload, _ = proto.Marshal(m)
	return b
}

func TestCheckBackupMeta(t *testing.T) {
	a := bytes.Repeat([]byte{7}, 16)
	if err := checkBackupMeta(backupMetaBody(t, a, nil)); err != nil {
		t.Fatalf("valid meta rejected: %v", err)
	}
	bad := map[string]func(*pb.BackupMeta, *pb.RecordBody){
		"version 0":    func(m *pb.BackupMeta, _ *pb.RecordBody) { m.Version = 0 },
		"short salt":   func(m *pb.BackupMeta, _ *pb.RecordBody) { m.Salt = make([]byte, 8) },
		"weak kdf":     func(m *pb.BackupMeta, _ *pb.RecordBody) { m.KdfMKib = 1024 },
		"t 0":          func(m *pb.BackupMeta, _ *pb.RecordBody) { m.KdfT = 0 },
		"p 9":          func(m *pb.BackupMeta, _ *pb.RecordBody) { m.KdfP = 9 },
		"verifier":     func(m *pb.BackupMeta, _ *pb.RecordBody) { m.AuthVerifier = nil },
		"foreign blob": func(m *pb.BackupMeta, _ *pb.RecordBody) { m.BlobKey = make([]byte, 32) },
		"size 0":       func(m *pb.BackupMeta, _ *pb.RecordBody) { m.Size = 0 },
		"too big":      func(m *pb.BackupMeta, _ *pb.RecordBody) { m.Size = MaxBlobSize + 1 },
		"expires":      func(_ *pb.BackupMeta, b *pb.RecordBody) { b.ExpiresMs = 5 },
	}
	for name, mut := range bad {
		if err := checkBackupMeta(backupMetaBody(t, a, mut)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCheckBlobMetaPersistent(t *testing.T) {
	a := bytes.Repeat([]byte{7}, 16)
	mk := func(readers [][]byte, expires int64) *pb.RecordBody {
		m := &pb.BlobMeta{Size: 10, ChunkSize: BlobChunkSize, ChunkSha256: [][]byte{make([]byte, 32)}, Readers: readers, Persistent: true}
		p, _ := proto.Marshal(m)
		return &pb.RecordBody{Id: make([]byte, 16), Type: pb.RecordType_BLOB_META, Author: a, CreatedMs: 1, ExpiresMs: expires, Payload: p}
	}
	if err := checkBlobMeta(mk(nil, 0)); err != nil {
		t.Fatalf("persistent blob rejected: %v", err)
	}
	if checkBlobMeta(mk([][]byte{bytes.Repeat([]byte{8}, 16)}, 0)) == nil {
		t.Error("persistent blob with readers accepted")
	}
	if checkBlobMeta(mk(nil, 1000)) == nil {
		t.Error("persistent blob with expiry accepted")
	}
}

func pushTokenBody(author []byte, mut func(*pb.PushToken)) *pb.RecordBody {
	p := &pb.PushToken{DeviceId: 1, Kind: pb.PushToken_FCM, Token: "fcm-token-abc"}
	if mut != nil {
		mut(p)
	}
	b := &pb.RecordBody{Id: make([]byte, 16), Type: pb.RecordType_PUSH_TOKEN, Author: author, CreatedMs: 1}
	b.Payload, _ = proto.Marshal(p)
	return b
}

func TestCheckPushToken(t *testing.T) {
	a := bytes.Repeat([]byte{3}, 16)
	if err := checkPushToken(pushTokenBody(a, nil)); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	good := map[string]func(*pb.PushToken){
		"messages off": func(p *pb.PushToken) { p.MessagesOff = true },
		"withdrawn":    func(p *pb.PushToken) { p.Token = ""; p.Withdrawn = true },
	}
	for name, mut := range good {
		if err := checkPushToken(pushTokenBody(a, mut)); err != nil {
			t.Errorf("%s: rejected: %v", name, err)
		}
	}
	bad := map[string]func(*pb.PushToken){
		"withdrawn with a token":     func(p *pb.PushToken) { p.Withdrawn = true },
		"withdrawn and messages off": func(p *pb.PushToken) { p.Token = ""; p.Withdrawn = true; p.MessagesOff = true },
		"device 2":                   func(p *pb.PushToken) { p.DeviceId = 2 },
		"no kind":                    func(p *pb.PushToken) { p.Kind = pb.PushToken_KIND_UNSPECIFIED },
		"empty":                      func(p *pb.PushToken) { p.Token = "" },
		"too long":                   func(p *pb.PushToken) { p.Token = strings.Repeat("x", MaxPushToken+1) },
		"bad utf-8":                  func(p *pb.PushToken) { p.Token = string([]byte{0xff, 0xfe}) },
	}
	for name, mut := range bad {
		if err := checkPushToken(pushTokenBody(a, mut)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

type newsKeys map[string]ed25519.PublicKey

func (n newsKeys) NewsKey(id []byte) (ed25519.PublicKey, bool) { k, ok := n[string(id)]; return k, ok }

func newsRec(t *testing.T, typ pb.RecordType, priv ed25519.PrivateKey, payload proto.Message, expires int64) *pb.Record {
	t.Helper()
	p, _ := proto.Marshal(payload)
	return mustSign(t, &pb.RecordBody{Id: rid(), Type: typ, Author: keys.ID16(priv.Public().(ed25519.PublicKey)),
		CreatedMs: time.Now().UnixMilli(), ExpiresMs: expires, Payload: p}, priv)
}

func TestAnnouncementValidation(t *testing.T) {
	netPub, _, _ := ed25519.GenerateKey(nil)
	newsPub, newsPriv, _ := ed25519.GenerateKey(nil)
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	v := &Validator{NetworkPub: netPub, Users: fakeUsers{}, News: newsKeys{string(keys.ID16(newsPub)): newsPub}, Now: time.Now}
	sha := make([]byte, 32)
	good := []*pb.Announcement{
		{TextRu: "Привет"}, {TextEn: "Hello"}, {TextRu: "Привет", TextEn: "Hello"},
		{TextRu: strings.Repeat("я", MaxNewsText)},
		{TextRu: "Обновление", Update: &pb.AppUpdate{VersionName: "0.6.0", VersionCode: 6, Sha256: sha, Size: 50 << 20}},
	}
	for i, a := range good {
		if _, err := v.Validate(newsRec(t, pb.RecordType_ANNOUNCEMENT, newsPriv, a, 0)); err != nil {
			t.Errorf("good %d: %v", i, err)
		}
	}
	bad := []*pb.Announcement{
		{}, {TextRu: "  \n"}, {TextRu: strings.Repeat("я", MaxNewsText+1)}, {TextEn: string([]byte{0xff})},
		{TextRu: "x", Update: &pb.AppUpdate{VersionCode: 6, Sha256: sha, Size: 1}},
		{TextRu: "x", Update: &pb.AppUpdate{VersionName: "0.6.0", Sha256: sha, Size: 1}},
		{TextRu: "x", Update: &pb.AppUpdate{VersionName: "0.6.0", VersionCode: 6, Sha256: sha[:31], Size: 1}},
		{TextRu: "x", Update: &pb.AppUpdate{VersionName: "0.6.0", VersionCode: 6, Sha256: sha, Size: 0}},
		{TextRu: "x", Update: &pb.AppUpdate{VersionName: "0.6.0", VersionCode: 6, Sha256: sha, Size: MaxBlobSize + 1}},
		{TextRu: "x", Update: &pb.AppUpdate{VersionName: strings.Repeat("1", 33), VersionCode: 6, Sha256: sha, Size: 1}},
	}
	for i, a := range bad {
		if _, err := v.Validate(newsRec(t, pb.RecordType_ANNOUNCEMENT, newsPriv, a, 0)); !errors.Is(err, ErrBadPayload) {
			t.Errorf("bad %d: got %v", i, err)
		}
	}
	if _, err := v.Validate(newsRec(t, pb.RecordType_ANNOUNCEMENT, newsPriv, good[0], time.Now().Add(time.Hour).UnixMilli())); !errors.Is(err, ErrBadPayload) {
		t.Errorf("expiring announcement: %v", err)
	}
	if _, err := v.Validate(newsRec(t, pb.RecordType_ANNOUNCEMENT, otherPriv, good[0], 0)); !errors.Is(err, ErrUnknownNewsKey) {
		t.Errorf("unknown key: %v", err)
	}
	r := newsRec(t, pb.RecordType_ANNOUNCEMENT, newsPriv, good[0], 0)
	r.Signature[0] ^= 1
	if _, err := v.Validate(r); !errors.Is(err, ErrBadSignature) {
		t.Errorf("bad signature: %v", err)
	}
	v.News = nil
	if _, err := v.Validate(newsRec(t, pb.RecordType_ANNOUNCEMENT, newsPriv, good[0], 0)); !errors.Is(err, ErrUnknownNewsKey) {
		t.Errorf("no resolver: %v", err)
	}
}

func TestNewsDeletedValidation(t *testing.T) {
	netPub, _, _ := ed25519.GenerateKey(nil)
	newsPub, newsPriv, _ := ed25519.GenerateKey(nil)
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	v := &Validator{NetworkPub: netPub, Users: fakeUsers{}, News: newsKeys{string(keys.ID16(newsPub)): newsPub}, Now: time.Now}
	if _, err := v.Validate(newsRec(t, pb.RecordType_ANNOUNCEMENT_DELETED, newsPriv, &pb.AnnouncementDeleted{Target: make([]byte, 32)}, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Validate(newsRec(t, pb.RecordType_ANNOUNCEMENT_DELETED, newsPriv, &pb.AnnouncementDeleted{Target: make([]byte, 31)}, 0)); !errors.Is(err, ErrBadPayload) {
		t.Fatalf("short target: %v", err)
	}
	if _, err := v.Validate(newsRec(t, pb.RecordType_ANNOUNCEMENT_DELETED, newsPriv, &pb.AnnouncementDeleted{Target: make([]byte, 32)}, time.Now().Add(time.Hour).UnixMilli())); !errors.Is(err, ErrBadPayload) {
		t.Fatalf("expiring deletion: %v", err)
	}
	if _, err := v.Validate(newsRec(t, pb.RecordType_ANNOUNCEMENT_DELETED, otherPriv, &pb.AnnouncementDeleted{Target: make([]byte, 32)}, 0)); !errors.Is(err, ErrUnknownNewsKey) {
		t.Fatalf("unknown key: %v", err)
	}
}
