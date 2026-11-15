package admin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

// Member is one account as the admin sees it after verifying every record on this machine.
type Member struct {
	UserID            []byte
	Username, Display string
	Revoked           bool
	Reason            string
	// Admitted: founding member (founding.json) or an invite chain that verifies back to the network key.
	// Accounts from before M9.2 have no chain until 'user found'.
	Admitted, Founding bool
	CanInvite          bool
	RightsVersion      uint64
}

func (m Member) Tag() string { return m.Username + "#" + hex.EncodeToString(m.UserID[:4]) }

type entry struct {
	e       *pb.DirectoryEntry
	version uint64
}

// Members builds the member list from an admin.users batch. Records that do not verify are dropped: a node can
// hide accounts or revocations (refusal), it cannot alter them or forge the admin's records. An account the node
// made up has no verifiable invite chain and shows as not admitted. Duplicate redemptions (C5) and node-side clash
// names are not reproduced here; the list shows each account's own entry. Invite rights follow D101 as changed by
// the owner: every member may invite unless the newest INVITE_RIGHTS says no (equal versions: "no" wins).
func Members(batch []*pb.Record, netPub ed25519.PublicKey, founding [][]byte) []Member {
	netID := keys.ID16(netPub)
	entries := map[string]entry{}
	type rights struct {
		v   uint64
		can bool
	}
	rs := map[string]rights{}
	revoked := map[string]string{}
	for _, r := range batch {
		var b pb.RecordBody
		if r == nil || proto.Unmarshal(r.Body, &b) != nil {
			continue
		}
		switch b.Type {
		case pb.RecordType_DIRECTORY_ENTRY:
			var e pb.DirectoryEntry
			if proto.Unmarshal(b.Payload, &e) != nil || len(e.AccountPub) != ed25519.PublicKeySize ||
				!bytes.Equal(e.UserId, keys.ID16(e.AccountPub)) || !bytes.Equal(b.Author, e.UserId) ||
				!ed25519.Verify(e.AccountPub, r.Body, r.Signature) {
				continue
			}
			if cur, ok := entries[string(e.UserId)]; !ok || e.Version > cur.version {
				entries[string(e.UserId)] = entry{&e, e.Version}
			}
		case pb.RecordType_REVOCATION, pb.RecordType_INVITE_RIGHTS:
			if !bytes.Equal(b.Author, netID) || !ed25519.Verify(netPub, r.Body, r.Signature) {
				continue
			}
			if b.Type == pb.RecordType_REVOCATION {
				var v pb.Revocation
				if proto.Unmarshal(b.Payload, &v) == nil {
					revoked[string(v.UserId)] = v.Reason
				}
				continue
			}
			var v pb.InviteRights
			if proto.Unmarshal(b.Payload, &v) == nil {
				cur, ok := rs[string(v.UserId)]
				if !ok || v.Version > cur.v || (v.Version == cur.v && !v.CanInvite) {
					rs[string(v.UserId)] = rights{v.Version, v.CanInvite}
				}
			}
		}
	}

	isFounding := map[string]bool{}
	for _, f := range founding {
		isFounding[string(f)] = true
	}
	// admitted: founding, or invited (proof valid) by the network key or by an admitted member; repeat until stable
	admitted := map[string]bool{}
	for id := range entries {
		if isFounding[id] {
			admitted[id] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for id, en := range entries {
			if !admitted[id] && chainOK(en.e, netPub, netID, entries, admitted) {
				admitted[id], changed = true, true
			}
		}
	}

	out := make([]Member, 0, len(entries))
	for id, en := range entries {
		m := Member{UserID: en.e.UserId, Username: en.e.Username, Display: en.e.DisplayName,
			Admitted: admitted[id], Founding: isFounding[id], CanInvite: true}
		if r, ok := rs[id]; ok {
			m.CanInvite, m.RightsVersion = r.can, r.v
		}
		m.Reason, m.Revoked = revoked[id]
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Username < out[j].Username ||
			(out[i].Username == out[j].Username && bytes.Compare(out[i].UserID, out[j].UserID) < 0)
	})
	return out
}

// chainOK: the entry's INVITE is signed by the network key or an admitted member and its proof matches (D100).
func chainOK(e *pb.DirectoryEntry, netPub ed25519.PublicKey, netID []byte, entries map[string]entry, admitted map[string]bool) bool {
	var rec pb.Record
	var b pb.RecordBody
	var inv pb.Invite
	if len(e.InviteRecord) == 0 || proto.Unmarshal(e.InviteRecord, &rec) != nil || proto.Unmarshal(rec.Body, &b) != nil ||
		b.Type != pb.RecordType_INVITE || proto.Unmarshal(b.Payload, &inv) != nil || len(inv.RedeemPub) != ed25519.PublicKeySize ||
		len(e.InviteProof) != ed25519.SignatureSize {
		return false
	}
	signer := netPub
	if !bytes.Equal(b.Author, netID) {
		inviter, ok := entries[string(b.Author)]
		if !ok || !admitted[string(b.Author)] {
			return false
		}
		signer = inviter.e.AccountPub
	}
	return ed25519.Verify(signer, rec.Body, rec.Signature) &&
		ed25519.Verify(inv.RedeemPub, keys.RedeemMessage(inv.InviteId, e.UserId, e.AccountPub), e.InviteProof)
}

// Find resolves a user id (32 hex), "name#tag" or a unique username.
func Find(ms []Member, who string) (Member, error) {
	var hits []Member
	for _, m := range ms {
		if hex.EncodeToString(m.UserID) == strings.ToLower(who) || m.Tag() == who || m.Username == who {
			hits = append(hits, m)
		}
	}
	switch len(hits) {
	case 1:
		return hits[0], nil
	case 0:
		return Member{}, fmt.Errorf("no member %q", who)
	}
	var tags []string
	for _, h := range hits {
		tags = append(tags, h.Tag())
	}
	return Member{}, fmt.Errorf("%q is ambiguous: use one of %s or the user id", who, strings.Join(tags, ", "))
}

// SignRevocation signs a REVOCATION and keeps a copy in DIR/revocations/<user hex>.bin.
func SignRevocation(dir string, priv ed25519.PrivateKey, user []byte, reason string, now time.Time) (*pb.Record, error) {
	return signNetwork(dir, "revocations", priv, pb.RecordType_REVOCATION, user, &pb.Revocation{UserId: user, Reason: reason}, now)
}

// SignInviteRights signs INVITE_RIGHTS version v and keeps a copy in DIR/invite-rights/<user hex>.bin.
func SignInviteRights(dir string, priv ed25519.PrivateKey, user []byte, can bool, v uint64, now time.Time) (*pb.Record, error) {
	return signNetwork(dir, "invite-rights", priv, pb.RecordType_INVITE_RIGHTS, user, &pb.InviteRights{UserId: user, CanInvite: can, Version: v}, now)
}

func signNetwork(dir, sub string, priv ed25519.PrivateKey, typ pb.RecordType, user []byte, payload proto.Message, now time.Time) (*pb.Record, error) {
	p, err := proto.Marshal(payload)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 16)
	rand.Read(id)
	rec, err := records.Sign(&pb.RecordBody{Id: id, Type: typ, Author: keys.ID16(priv.Public().(ed25519.PublicKey)),
		CreatedMs: now.UnixMilli(), Payload: p}, priv)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
		return nil, err
	}
	raw, err := proto.Marshal(rec)
	if err != nil {
		return nil, err
	}
	return rec, os.WriteFile(filepath.Join(dir, sub, hex.EncodeToString(user)+".bin"), raw, 0o600)
}

// LoadFounding reads DIR/founding.json (hex user ids) for 'manifest sign' (D100). No file: none.
func LoadFounding(dir string) ([][]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, "founding.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var hs []string
	if err := json.Unmarshal(b, &hs); err != nil {
		return nil, fmt.Errorf("founding.json: %w", err)
	}
	var out [][]byte
	for _, h := range hs {
		id, err := hex.DecodeString(h)
		if err != nil || len(id) != 16 {
			return nil, fmt.Errorf("founding.json: bad user id %q", h)
		}
		out = append(out, id)
	}
	return out, nil
}

// AddFounding adds user ids to DIR/founding.json (kept in order, no duplicates).
func AddFounding(dir string, ids [][]byte) error {
	cur, err := LoadFounding(dir)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	hs := []string{}
	for _, id := range append(cur, ids...) {
		h := hex.EncodeToString(id)
		if !seen[h] {
			seen[h] = true
			hs = append(hs, h)
		}
	}
	b, _ := json.MarshalIndent(hs, "", "  ")
	return os.WriteFile(filepath.Join(dir, "founding.json"), append(b, '\n'), 0o600)
}

// SavedRightsVersion is the version of the INVITE_RIGHTS last signed on this machine for user (0: none). The next
// version is above both this and what the node showed, so a node hiding the newest record cannot make the admin
// sign one that loses.
func SavedRightsVersion(dir string, user []byte) uint64 {
	raw, err := os.ReadFile(filepath.Join(dir, "invite-rights", hex.EncodeToString(user)+".bin"))
	if err != nil {
		return 0
	}
	var rec pb.Record
	var b pb.RecordBody
	var v pb.InviteRights
	if proto.Unmarshal(raw, &rec) != nil || proto.Unmarshal(rec.Body, &b) != nil || proto.Unmarshal(b.Payload, &v) != nil {
		return 0
	}
	return v.Version
}
