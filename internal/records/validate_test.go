package records

import (
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
	ack := payload(&pb.Ack{EnvelopeIds: [][]byte{rid()}})

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
