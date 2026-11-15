package store

import (
	"bytes"
	"context"
	"database/sql"
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
