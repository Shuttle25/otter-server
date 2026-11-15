package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"

	pb "ottermsg/server/internal/proto/otterv1"
)

// ReasonDuplicateInvite is users.revoke_reason of an account that lost a double redemption (D102).
const ReasonDuplicateInvite = "duplicate invite"

// ReasonInvitedByDuplicate is users.revoke_reason of an account whose inviter (or an inviter further up its chain) is
// disabled as a duplicate: such an account never admits anyone (D102, as the phone checks it, D104).
const ReasonInvitedByDuplicate = "invited by a duplicate"

// Admission is what the service derived from a new account's invite chain (D100). Invite rights are not part of it:
// every member may invite unless the admin withdrew it with INVITE_RIGHTS (D101 as changed by the owner, 2026-11-15).
type Admission struct {
	InviteID []byte // nil for founding members
	Rank     []byte // SHA-256(invite_proof): the lowest keeps a doubly redeemed invite (D102)
	RankMs   int64  // username clash rank: the INVITE's created_ms, or registered_ms of a founding member (D103)
	Inviter  []byte // the INVITE's author (the network's id16 for a bootstrap invite); nil for founding members
}

// rightsNow is the user's current invite right: the newest INVITE_RIGHTS version ("no" wins a tie), else yes (D101).
const rightsNow = `COALESCE((SELECT can_invite FROM invite_rights WHERE user_id=?1
	ORDER BY version DESC, can_invite ASC LIMIT 1), 1)`

// revokeUser disables an account on this node: no login, no queued mail, no new sessions with it, no wake-ups.
func revokeUser(ctx context.Context, tx *sql.Tx, user []byte, reason string) error {
	if _, err := tx.ExecContext(ctx, `UPDATE users SET revoked=1, revoke_reason=? WHERE user_id=? AND revoked=0`, reason, user); err != nil {
		return err
	}
	for _, q := range []string{`DELETE FROM mailbox WHERE user_id=?`, `DELETE FROM prekeys WHERE user_id=?`,
		`DELETE FROM push_tokens WHERE user_id=?`} {
		if _, err := tx.ExecContext(ctx, q, user); err != nil {
			return err
		}
	}
	return nil
}

// applyRevocation stores a network-signed REVOCATION (D99). Several revocations of one user: the earliest time (and
// its reason) counts, because it decides which of the user's invites still count. A user not known yet is revoked
// when the entry arrives (insertUser).
func applyRevocation(ctx context.Context, tx *sql.Tx, b *pb.RecordBody, r *pb.Revocation) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO revocations(user_id,created_ms,reason) VALUES(?,?,?)
		ON CONFLICT(user_id) DO UPDATE SET
		  reason=CASE WHEN excluded.created_ms < created_ms THEN excluded.reason ELSE reason END,
		  created_ms=MIN(created_ms, excluded.created_ms)`, r.UserId, b.CreatedMs, r.Reason); err != nil {
		return err
	}
	var reason string
	if err := tx.QueryRowContext(ctx, `SELECT reason FROM revocations WHERE user_id=?`, r.UserId).Scan(&reason); err != nil {
		return err
	}
	return revokeUser(ctx, tx, r.UserId, reason)
}

// applyInviteRights stores a network-signed INVITE_RIGHTS (D99, D101): the highest version wins in any arrival order;
// equal versions with different values resolve to "no". Rights for a user not known yet apply when the entry arrives.
func applyInviteRights(ctx context.Context, tx *sql.Tx, b *pb.RecordBody, r *pb.InviteRights) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO invite_rights(user_id,version,can_invite,created_ms) VALUES(?,?,?,?)
		ON CONFLICT(user_id,version,can_invite) DO UPDATE SET created_ms=MIN(created_ms, excluded.created_ms)`,
		r.UserId, r.Version, boolInt(r.CanInvite), b.CreatedMs); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE users SET can_invite=`+rightsNow+` WHERE user_id=?1`, r.UserId)
	return err
}

// RevokedAt returns the created_ms of the user's (earliest) revocation.
func (s *Store) RevokedAt(ctx context.Context, user []byte) (int64, bool, error) {
	var at int64
	err := s.r.QueryRowContext(ctx, `SELECT created_ms FROM revocations WHERE user_id=?`, user).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return at, err == nil, err
}

// CanInviteAt reports the user's invite rights as of atMs: the newest INVITE_RIGHTS version created at or before atMs
// ("no" wins a tie), else yes, the default of every member (D101). Unknown user: false. Revocation is not considered
// here (see RevokedAt).
func (s *Store) CanInviteAt(ctx context.Context, user []byte, atMs int64) (bool, error) {
	var v int
	err := s.r.QueryRowContext(ctx, `SELECT COALESCE(
		(SELECT can_invite FROM invite_rights WHERE user_id=?1 AND created_ms<=?2 ORDER BY version DESC, can_invite ASC LIMIT 1), 1)
		FROM users WHERE user_id=?1`, user, atMs).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return v != 0, err
}

// RevokeReason returns why the account was revoked or disabled ("" if it is not).
func (s *Store) RevokeReason(ctx context.Context, user []byte) (string, error) {
	var r sql.NullString
	err := s.r.QueryRowContext(ctx, `SELECT revoke_reason FROM users WHERE user_id=? AND revoked=1`, user).Scan(&r)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return r.String, err
}

// RevokedUsers lists every revoked or disabled account (TURN refusal, session closing).
func (s *Store) RevokedUsers(ctx context.Context) ([][]byte, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT user_id FROM users WHERE revoked=1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var id []byte
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// MembershipRecords returns every stored REVOCATION and INVITE_RIGHTS (serialized), oldest first, for directory.sync.
func (s *Store) MembershipRecords(ctx context.Context) ([][]byte, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT raw FROM records WHERE type IN (?,?) ORDER BY created_ms, record_key`,
		int32(pb.RecordType_REVOCATION), int32(pb.RecordType_INVITE_RIGHTS))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}

// insertUser creates the account row with the state the network-signed records give it (D99, D101, D102): revoked if a
// REVOCATION arrived first or the account lost a double redemption of its invite, invite rights from INVITE_RIGHTS or
// the default, never from DirectoryEntry.can_invite (C6).
func insertUser(ctx context.Context, tx *sql.Tx, it item, e *pb.DirectoryEntry, name string, conflict int, rank, now int64) error {
	if err := redeem(ctx, tx, it, e.UserId); err != nil {
		return err
	}
	revoked, reason := false, ""
	var rr string
	err := tx.QueryRowContext(ctx, `SELECT reason FROM revocations WHERE user_id=?`, e.UserId).Scan(&rr)
	switch {
	case err == nil:
		revoked, reason = true, rr
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO users(user_id,username,account_pub,entry_key,version,can_invite,created_ms,entry_created_ms,username_conflict)
		 VALUES(?1,?2,?3,?4,?5,`+rightsNow+`,?6,?7,?8)`,
		e.UserId, name, e.AccountPub, it.key, e.Version, now, rank, conflict); err != nil {
		return err
	}
	if revoked {
		if err := revokeUser(ctx, tx, e.UserId, reason); err != nil {
			return err
		}
	}
	return disableDuplicates(ctx, tx)
}

// redeem records the account's redemption (D102). A redemption on this node of an invite already redeemed by someone
// else is refused; a replicated one is stored and disableDuplicates decides.
func redeem(ctx context.Context, tx *sql.Tx, it item, user []byte) error {
	a := it.adm
	if a == nil || a.InviteID == nil {
		return nil
	}
	if !it.fromPeer {
		var x int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM redemptions WHERE invite_id=? AND user_id<>?`, a.InviteID, user).Scan(&x)
		if err == nil {
			return ErrInviteUnavailable
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO redemptions(invite_id,user_id,rank,inviter) VALUES(?,?,?,?)`,
		a.InviteID, user, a.Rank, a.Inviter)
	return err
}

// duplicates is every account disabled by the single-use rule (D102), the same set the phone computes (D104): of all
// accounts that redeemed one invite, all but the lowest rank (SHA-256(invite_proof), then user_id) lose; and an account
// whose inviter lost, or was itself invited through a loser, never counts as admitted. All redeemers of one invite share
// its inviter, so this never changes who wins another invite, and it depends only on the stored redemptions: every
// node reaches the same set in any arrival order. Rows only ever get added, so the set only grows.
const duplicates = `WITH RECURSIVE bad(user_id, dup) AS (
	SELECT r.user_id, 1 FROM redemptions r WHERE EXISTS (SELECT 1 FROM redemptions o WHERE o.invite_id=r.invite_id
	  AND (o.rank < r.rank OR (o.rank = r.rank AND o.user_id < r.user_id)))
	UNION
	SELECT r.user_id, 0 FROM redemptions r JOIN bad b ON r.inviter = b.user_id)
SELECT b.user_id, MAX(b.dup) FROM bad b JOIN users u ON u.user_id = b.user_id WHERE u.revoked = 0 GROUP BY b.user_id`

// disableDuplicates disables every account of the duplicates set not disabled yet.
func disableDuplicates(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, duplicates)
	if err != nil {
		return err
	}
	type hit struct {
		id  []byte
		dup bool
	}
	var hits []hit
	for rows.Next() {
		var h hit
		if err := rows.Scan(&h.id, &h.dup); err != nil {
			rows.Close()
			return err
		}
		hits = append(hits, h)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, h := range hits {
		reason := ReasonInvitedByDuplicate
		if h.dup {
			reason = ReasonDuplicateInvite
		}
		if err := revokeUser(ctx, tx, h.id, reason); err != nil {
			return err
		}
	}
	return nil
}

// ResolveUsername maps a name typed for a restore to the stored username (D103): a name that never clashed as is;
// "name#<8 hex>" to either side of a clash (the winner is stored as plain "name", the loser literally as "name#tag").
// A clashed plain name returns the candidates ("name#tag" of every account sharing it) instead of guessing.
func (s *Store) ResolveUsername(ctx context.Context, typed string) (string, []string, error) {
	base, tag, tagged := strings.Cut(typed, "#")
	if !tagged {
		var x int
		err := s.r.QueryRowContext(ctx, `SELECT 1 FROM username_clashes WHERE username=?`, base).Scan(&x)
		if errors.Is(err, sql.ErrNoRows) {
			return typed, nil, nil
		}
		if err != nil {
			return "", nil, err
		}
		rows, err := s.r.QueryContext(ctx, `SELECT user_id FROM users WHERE username=?1 OR substr(username,1,length(?1)+1)=?1||'#'
			ORDER BY username`, base)
		if err != nil {
			return "", nil, err
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var id []byte
			if err := rows.Scan(&id); err != nil {
				return "", nil, err
			}
			out = append(out, conflictName(base, id))
		}
		if err := rows.Err(); err != nil {
			return "", nil, err
		}
		if len(out) == 0 { // remembered clash, but no account here holds the name any more
			return typed, nil, nil
		}
		return "", out, nil
	}
	tag = strings.ToLower(tag)
	var id []byte
	err := s.r.QueryRowContext(ctx, `SELECT user_id FROM users WHERE username=?`, base).Scan(&id)
	if err == nil && hex.EncodeToString(id[:4]) == tag {
		return base, nil, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", nil, err
	}
	return base + "#" + tag, nil, nil // the loser's row is literally "name#tag"; anything else finds nothing
}
