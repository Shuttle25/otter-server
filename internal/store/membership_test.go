package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
)

var netAuthor = []byte("network-network1")

func revocation(t *testing.T, user []byte, created int64) Item {
	return mkItemAt(t, pb.RecordType_REVOCATION, netAuthor, &pb.Revocation{UserId: user, Reason: "left"}, created)
}

func rights(t *testing.T, user []byte, can bool, version uint64, created int64) Item {
	return mkItemAt(t, pb.RecordType_INVITE_RIGHTS, netAuthor, &pb.InviteRights{UserId: user, CanInvite: can, Version: version}, created)
}

func TestRevocationAppliesInBothOrders(t *testing.T) {
	ctx := context.Background()
	for _, order := range []string{"entry-first", "revocation-first"} {
		s, _ := open(t)
		u := r16()
		e := mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, u, entry(u, "anna", 1), 1000)
		r := revocation(t, u, 2000)
		if order == "entry-first" {
			replicate(t, s, e)
			if err := s.write(ctx, func(ctx context.Context, tx *sql.Tx) error { // a queued envelope, a prekey, a push token
				if _, err := tx.ExecContext(ctx, `INSERT INTO mailbox(user_id,device_id,record_key,origin_node,received_ms) VALUES(?,1,?,?,1)`, u, r16(), r16()); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO prekeys(user_id,device_id,key_id,kind,public) VALUES(?,1,1,3,x'00')`, u); err != nil {
					return err
				}
				_, err := tx.ExecContext(ctx, `INSERT INTO push_tokens(user_id,device_id,kind,token,created_ms) VALUES(?,1,1,'t',1)`, u)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			replicate(t, s, r)
		} else {
			replicate(t, s, r)
			replicate(t, s, e)
		}
		got, _ := s.UserByID(ctx, u)
		if got == nil || !got.Revoked {
			t.Fatalf("%s: not revoked: %+v", order, got)
		}
		for _, tbl := range []string{"mailbox", "prekeys", "push_tokens"} {
			var n int
			if err := s.r.QueryRow(`SELECT COUNT(*) FROM `+tbl+` WHERE user_id=?`, u).Scan(&n); err != nil || n != 0 {
				t.Fatalf("%s: %s kept (%d, %v)", order, tbl, n, err)
			}
		}
		var reason string
		if err := s.r.QueryRow(`SELECT revoke_reason FROM users WHERE user_id=?`, u).Scan(&reason); err != nil || reason != "left" {
			t.Fatalf("%s: reason %q %v", order, reason, err)
		}
		if at, ok, _ := s.RevokedAt(ctx, u); !ok || at != 2000 {
			t.Fatalf("%s: revoked at %d %v", order, at, ok)
		}
	}
}

func TestEarliestRevocationKept(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	u := r16()
	replicate(t, s, revocation(t, u, 5000))
	replicate(t, s, revocation(t, u, 3000))
	replicate(t, s, revocation(t, u, 4000))
	if at, ok, _ := s.RevokedAt(ctx, u); !ok || at != 3000 {
		t.Fatalf("revoked at %d %v, want 3000", at, ok)
	}
	if _, ok, _ := s.RevokedAt(ctx, r16()); ok {
		t.Fatal("unknown user revoked")
	}
	if ids, _ := s.RevokedUsers(ctx); len(ids) != 0 { // no users row yet
		t.Fatalf("revoked users without entry: %d", len(ids))
	}
	replicate(t, s, mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, u, entry(u, "anna", 1), 1000))
	if ids, _ := s.RevokedUsers(ctx); len(ids) != 1 || !bytes.Equal(ids[0], u) {
		t.Fatalf("revoked users: %x", ids)
	}
}

// D101 (owner, 2026-11-15): every member may invite by default; INVITE_RIGHTS withdraws or restores.
func TestInviteRightsNewestVersionWins(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	u := r16()
	replicate(t, s, rights(t, u, false, 2, 2000))                                             // before the entry
	replicate(t, s, mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, u, entry(u, "anna", 1), 1000)) // entry says CanInvite: true
	if got, _ := s.UserByID(ctx, u); got.CanInvite {
		t.Fatal("rights v2 (withdrawn) not applied to the late entry")
	}
	replicate(t, s, rights(t, u, true, 1, 3000)) // older version arrives later: ignored
	if got, _ := s.UserByID(ctx, u); got.CanInvite {
		t.Fatal("older version won")
	}
	replicate(t, s, rights(t, u, true, 3, 4000))
	if got, _ := s.UserByID(ctx, u); !got.CanInvite {
		t.Fatal("restore v3 not applied")
	}
	replicate(t, s, rights(t, u, false, 3, 4001)) // same version, other value: "no" wins on every node
	replicate(t, s, rights(t, u, true, 3, 4002))  // and stays "no" whatever arrives next with that version
	if got, _ := s.UserByID(ctx, u); got.CanInvite {
		t.Fatal("tie must resolve to false")
	}
	for _, c := range []struct {
		at   int64
		want bool
	}{
		{1500, true},  // no rights record yet: the default (every member)
		{2500, false}, // v2 withdrew
		{3500, false}, // v1 is older than v2
		{4000, true},  // v3 "yes" only
		{4001, false}, // v3 "no" counts from its own created_ms
		{9000, false},
	} {
		if ok, err := s.CanInviteAt(ctx, u, c.at); err != nil || ok != c.want {
			t.Fatalf("CanInviteAt(%d) = %v %v, want %v", c.at, ok, err, c.want)
		}
	}
	if ok, _ := s.CanInviteAt(ctx, r16(), 9000); ok {
		t.Fatal("unknown user may invite")
	}
}

func TestInviteRightsTieIndependentOfOrder(t *testing.T) {
	ctx := context.Background()
	u := r16()
	yes, no := rights(t, u, true, 5, 100), rights(t, u, false, 5, 100)
	for _, order := range [][]Item{{yes, no}, {no, yes}} {
		s, _ := open(t)
		replicate(t, s, mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, u, entry(u, "anna", 1), 50))
		for _, it := range order {
			replicate(t, s, it)
		}
		if got, _ := s.UserByID(ctx, u); got.CanInvite {
			t.Fatal("tie must resolve to false in any order")
		}
	}
}

func TestEntryCanInviteIgnored(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	u := r16()
	e := entry(u, "anna", 1)
	e.CanInvite = false // ignored both ways (C6): rights come from the default and INVITE_RIGHTS only
	replicate(t, s, mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, u, e, 1000))
	if got, _ := s.UserByID(ctx, u); !got.CanInvite {
		t.Fatal("can_invite taken from the applicant's own entry (C6)")
	}
	replicate(t, s, rights(t, u, false, 1, 2000))
	e2 := entry(u, "anna", 2) // the user's next version claims CanInvite: true
	replicate(t, s, mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, u, e2, 3000))
	if got, _ := s.UserByID(ctx, u); got.CanInvite {
		t.Fatal("a later entry version restored withdrawn rights")
	}
	v := r16()
	it := mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, v, entry(v, "boris", 1), 1000)
	it.Admission = &Admission{RankMs: 1000}
	if _, _, err := s.ApplyReplicatedItem(ctx, it, peer); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.UserByID(ctx, v); got == nil || !got.CanInvite {
		t.Fatal("admitted member has no default rights")
	}
}

func TestMembershipRecords(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	u := r16()
	r1, r2 := rights(t, u, false, 1, 2000), revocation(t, u, 1000)
	replicate(t, s, r1)
	replicate(t, s, mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, u, entry(u, "anna", 1), 500))
	replicate(t, s, r2)
	raws, err := s.MembershipRecords(ctx)
	if err != nil || len(raws) != 2 {
		t.Fatalf("membership records: %d %v", len(raws), err)
	}
	var first pb.Record
	if err := proto.Unmarshal(raws[0], &first); err != nil || !bytes.Equal(first.Body, r2.Record.Body) {
		t.Fatal("not oldest first")
	}
}

// Accounts from before M9.2: everyone may invite (D101), clashed names are remembered (D103).
func TestMembershipMigrationOfOldAccounts(t *testing.T) {
	ctx := context.Background()
	s, p := open(t)
	s.Close()
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	a, b := r16(), r16()
	for _, q := range []string{
		`DROP TABLE revocations`, `DROP TABLE invite_rights`, `DROP TABLE redemptions`, `DROP TABLE username_clashes`,
		`ALTER TABLE users DROP COLUMN revoke_reason`, `DELETE FROM schema_migrations WHERE name='0011_membership.sql'`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	for _, u := range []struct {
		id       []byte
		name     string
		conflict int
	}{{a, "anna", 0}, {b, "anna#0a0b0c0d", 1}} {
		if _, err := db.Exec(`INSERT INTO users(user_id,username,account_pub,entry_key,version,can_invite,created_ms,entry_created_ms,username_conflict)
			VALUES(?,?,x'00',?,1,0,1,1,?)`, u.id, u.name, r16(), u.conflict); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	for _, u := range [][]byte{a, b} {
		var can int
		if err := s2.r.QueryRowContext(ctx, `SELECT can_invite FROM users WHERE user_id=?`, u).Scan(&can); err != nil || can != 1 {
			t.Fatalf("old account without invite rights: %d %v", can, err)
		}
	}
	var n int
	if err := s2.r.QueryRow(`SELECT COUNT(*) FROM username_clashes WHERE username='anna'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("clash not remembered: %d %v", n, err)
	}
}

// admitted: a version-1 entry claiming registeredMs, admitted with the given invite, rank and rank time.
func admitted(t *testing.T, user []byte, name string, invite, rank []byte, rankMs, registeredMs int64) Item {
	e := entry(user, name, 1)
	e.RegisteredMs = registeredMs
	it := mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, user, e, max(registeredMs, rankMs))
	it.Admission = &Admission{InviteID: invite, Rank: rank, RankMs: rankMs, Inviter: netInviter}
	return it
}

// netInviter stands for the network's id16 as the author of a bootstrap invite.
var netInviter = bytes.Repeat([]byte{0xee}, 16)

// invitedBy is admitted with a member as the INVITE's author.
func invitedBy(t *testing.T, inviter, user []byte, name string, invite, rank []byte) Item {
	it := admitted(t, user, name, invite, rank, 1000, 1000)
	it.Admission.Inviter = inviter
	return it
}

// D102/D104: a duplicate loser never admits anyone. x loses invite inv to y; x invited z, z invited w. In every arrival
// order (an invitee only after its inviter, as the service's RETRY_LATER makes it) x, z and w end up disabled, y and an
// account invited by y do not.
func TestDuplicateLoserNeverAdmits(t *testing.T) {
	ctx := context.Background()
	inv := bytes.Repeat([]byte{1}, 32)
	x, y, z, w, v := r16(), r16(), r16(), r16(), r16()
	lo, hi := bytes.Repeat([]byte{0x10}, 32), bytes.Repeat([]byte{0x20}, 32)
	items := map[string]Item{
		"x": admitted(t, x, "xenia", inv, hi, 1000, 1000),
		"y": admitted(t, y, "yuri", inv, lo, 1000, 1000),
		"z": invitedBy(t, x, z, "zed", r16(), r16()),
		"w": invitedBy(t, z, w, "wen", r16(), r16()),
		"v": invitedBy(t, y, v, "vera", r16(), r16()),
	}
	after := map[string]string{"z": "x", "w": "z", "v": "y"}
	var perms func(done string, rest []string)
	n := 0
	perms = func(done string, rest []string) {
		if len(rest) == 0 {
			n++
			s, _ := open(t)
			for _, k := range done {
				if _, _, err := s.ApplyReplicatedItem(ctx, items[string(k)], peer); err != nil {
					t.Fatal(done, err)
				}
			}
			want := map[string]struct {
				id     []byte
				reason string
			}{"x": {x, ReasonDuplicateInvite}, "z": {z, ReasonInvitedByDuplicate}, "w": {w, ReasonInvitedByDuplicate},
				"y": {y, ""}, "v": {v, ""}}
			for k, c := range want {
				var revoked int
				var reason string
				if err := s.r.QueryRow(`SELECT revoked, revoke_reason FROM users WHERE user_id=?`, c.id).Scan(&revoked, &reason); err != nil {
					t.Fatal(done, k, err)
				}
				if (revoked == 1) != (c.reason != "") || reason != c.reason {
					t.Fatalf("order %s: %s revoked=%d reason=%q", done, k, revoked, reason)
				}
			}
			return
		}
		for i, k := range rest {
			if p, ok := after[k]; ok && !strings.Contains(done, p) {
				continue
			}
			r := append(append([]string{}, rest[:i]...), rest[i+1:]...)
			perms(done+k, r)
		}
	}
	perms("", []string{"x", "y", "z", "w", "v"})
	if n < 10 {
		t.Fatalf("only %d orders", n)
	}
}

// C5 (D102): of two redemptions of one invite, the lowest rank stays in any arrival order; locally a second one is refused.
func TestDoubleRedemptionLowestRankStays(t *testing.T) {
	ctx := context.Background()
	inv := bytes.Repeat([]byte{1}, 32)
	x, y := r16(), r16()
	lo, hi := bytes.Repeat([]byte{0x10}, 32), bytes.Repeat([]byte{0x20}, 32)
	for _, order := range []string{"x-first", "y-first"} {
		s, _ := open(t)
		ix := admitted(t, x, "xenia", inv, hi, 1000, 1000)
		iy := admitted(t, y, "yuri", inv, lo, 1000, 1000)
		apply2 := func(it Item) {
			if _, _, err := s.ApplyReplicatedItem(ctx, it, peer); err != nil {
				t.Fatal(err)
			}
		}
		if order == "x-first" {
			apply2(ix)
			apply2(iy)
		} else {
			apply2(iy)
			apply2(ix)
		}
		ux, _ := s.UserByID(ctx, x)
		uy, _ := s.UserByID(ctx, y)
		if !ux.Revoked || uy.Revoked {
			t.Fatalf("%s: x revoked=%v y revoked=%v", order, ux.Revoked, uy.Revoked)
		}
		var reason string
		if err := s.r.QueryRow(`SELECT revoke_reason FROM users WHERE user_id=?`, x).Scan(&reason); err != nil || reason != ReasonDuplicateInvite {
			t.Fatalf("%s: reason %q %v", order, reason, err)
		}
	}
	// locally a second redemption is refused
	s, _ := open(t)
	if _, _, err := s.ApplyReplicatedItem(ctx, admitted(t, x, "xenia", inv, hi, 1000, 1000), peer); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyAll(ctx, nil, []Item{admitted(t, y, "yuri", inv, lo, 1000, 1000)}); !errors.Is(err, ErrInviteUnavailable) {
		t.Fatalf("local second redemption: %v", err)
	}
	if u, _ := s.UserByID(ctx, y); u != nil {
		t.Fatal("refused redemption stored an account")
	}
}

// C12 (D103): the clash rank is the invite's created_ms, fixed at admission; a backdated registered_ms changes nothing.
func TestClashRankFixedAtAdmission(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	victim, attacker := r16(), r16()
	if _, _, err := s.ApplyReplicatedItem(ctx, admitted(t, victim, "anna", r16(), r16(), 5000, 5000), peer); err != nil {
		t.Fatal(err)
	}
	// the attacker claims registered_ms 1 but was invited later (rank 9000): loses
	if _, _, err := s.ApplyReplicatedItem(ctx, admitted(t, attacker, "anna", r16(), r16(), 9000, 1), peer); err != nil {
		t.Fatal(err)
	}
	// and a newer version with a backdated registered_ms changes nothing
	e2 := entry(attacker, "anna", 2)
	e2.RegisteredMs = 1
	replicate(t, s, mkItemAt(t, pb.RecordType_DIRECTORY_ENTRY, attacker, e2, 9999))
	uv, _ := s.UserByID(ctx, victim)
	ua, _ := s.UserByID(ctx, attacker)
	if uv.Username != "anna" || ua.Username != "anna#"+hex.EncodeToString(attacker[:4]) {
		t.Fatalf("victim=%s attacker=%s", uv.Username, ua.Username)
	}
	name, cands, err := s.ResolveUsername(ctx, "anna")
	if err != nil || name != "" || len(cands) != 2 {
		t.Fatalf("ambiguous name: %q %v %v", name, cands, err)
	}
	if name, _, _ := s.ResolveUsername(ctx, "anna#"+hex.EncodeToString(victim[:4])); name != "anna" {
		t.Fatalf("winner's tag resolves to %q", name)
	}
	if name, _, _ := s.ResolveUsername(ctx, "anna#"+hex.EncodeToString(attacker[:4])); name != "anna#"+hex.EncodeToString(attacker[:4]) {
		t.Fatalf("loser's tag resolves to %q", name)
	}
	if name, cands, _ := s.ResolveUsername(ctx, "boris"); name != "boris" || cands != nil {
		t.Fatalf("plain name: %q %v", name, cands)
	}
}
