package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"

	pb "ottermsg/server/internal/proto/otterv1"
)

// ReasonRekey is the revocation reason of an account replaced by a REKEY (D111).
const ReasonRekey = "rekey"

// applyRekey stores a network-signed REKEY{old, new} (D111). Every REKEY revokes old (like a REVOCATION created at the
// same time). Of several REKEYs of one old account the later created_ms (then the lower record key) wins; the winner's
// new account inherits old's clash rank and takes over old's username once both entries are here, in any arrival
// order. The winner is never disabled as a duplicate redemption: the admin confirmed this account (D102 exception).
func applyRekey(ctx context.Context, tx *sql.Tx, key, old, nw []byte, created int64) error {
	if err := applyRevocation(ctx, tx, &pb.RecordBody{CreatedMs: created}, &pb.Revocation{UserId: old, Reason: ReasonRekey}); err != nil {
		return err
	}
	var prevNew, prevKey []byte
	var prevCreated int64
	var prevOwn sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT new_user_id, record_key, created_ms, new_own_rank FROM rekeys WHERE old_user_id=?`, old).
		Scan(&prevNew, &prevKey, &prevCreated, &prevOwn)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx, `INSERT INTO rekeys(old_user_id,new_user_id,record_key,created_ms) VALUES(?,?,?,?)`,
			old, nw, key, created); err != nil {
			return err
		}
	case err != nil:
		return err
	case created < prevCreated || (created == prevCreated && bytes.Compare(key, prevKey) >= 0):
		return nil // an earlier REKEY of the same account: stored, no effect beyond the revocation
	case bytes.Equal(prevNew, nw):
		_, err := tx.ExecContext(ctx, `UPDATE rekeys SET record_key=?, created_ms=? WHERE old_user_id=?`, key, created, old)
		return err
	default:
		// the previous new account loses what it inherited: its own rank back, its name decided again
		if prevOwn.Valid {
			if _, err := tx.ExecContext(ctx, `UPDATE users SET entry_created_ms=? WHERE user_id=?`, prevOwn.Int64, prevNew); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE rekeys SET new_user_id=?, record_key=?, created_ms=?, new_own_rank=NULL
			WHERE old_user_id=?`, nw, key, created, old); err != nil {
			return err
		}
		var prevName string
		err := tx.QueryRowContext(ctx, `SELECT username FROM users WHERE user_id=?`, prevNew).Scan(&prevName)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil {
			if err := settleName(ctx, tx, baseName(prevName)); err != nil {
				return err
			}
		}
		if err := disableDuplicates(ctx, tx); err != nil { // prev is no longer exempt
			return err
		}
	}
	// a REKEY that arrives after nw lost a double redemption re-enables it (unless the admin revoked it as well)
	if _, err := tx.ExecContext(ctx, `UPDATE users SET revoked=0, revoke_reason='' WHERE user_id=?1 AND revoked=1
		AND revoke_reason IN (?2, ?3) AND NOT EXISTS (SELECT 1 FROM revocations WHERE user_id=?1)`,
		nw, ReasonDuplicateInvite, ReasonInvitedByDuplicate); err != nil {
		return err
	}
	return linkRekey(ctx, tx, old)
}

func baseName(n string) string { base, _, _ := strings.Cut(n, "#"); return base }

// linkRekey applies the winning REKEY of old once both accounts' entries are here and new registered under old's
// name: new's clash rank becomes min(own, old's) (its own is kept in rekeys.new_own_rank) and the name is settled.
func linkRekey(ctx context.Context, tx *sql.Tx, old []byte) error {
	var nw []byte
	var own sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT new_user_id, new_own_rank FROM rekeys WHERE old_user_id=?`, old).Scan(&nw, &own)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var oldName, newName string
	var oldRank, newRank int64
	err = tx.QueryRowContext(ctx, `SELECT username, entry_created_ms FROM users WHERE user_id=?`, old).Scan(&oldName, &oldRank)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // old's entry arrives later
	}
	if err != nil {
		return err
	}
	err = tx.QueryRowContext(ctx, `SELECT username, entry_created_ms FROM users WHERE user_id=?`, nw).Scan(&newName, &newRank)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // new's entry arrives later
	}
	if err != nil {
		return err
	}
	base := baseName(oldName)
	if baseName(newName) != base {
		return nil // registered under another name: phones still map old → new, the names stay as they are
	}
	if !own.Valid {
		own = sql.NullInt64{Int64: newRank, Valid: true}
		if _, err := tx.ExecContext(ctx, `UPDATE rekeys SET new_own_rank=? WHERE old_user_id=?`, own.Int64, old); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET entry_created_ms=? WHERE user_id=?`, min(own.Int64, oldRank), nw); err != nil {
		return err
	}
	return settleName(ctx, tx, base)
}

// rekeyTouched re-links every winning REKEY the user takes part in (old or new side), after its entry was applied.
func rekeyTouched(ctx context.Context, tx *sql.Tx, user []byte) error {
	rows, err := tx.QueryContext(ctx, `SELECT old_user_id FROM rekeys WHERE old_user_id=?1 OR new_user_id=?1`, user)
	if err != nil {
		return err
	}
	var olds [][]byte
	for rows.Next() {
		var o []byte
		if err := rows.Scan(&o); err != nil {
			rows.Close()
			return err
		}
		olds = append(olds, o)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, o := range olds {
		if err := linkRekey(ctx, tx, o); err != nil {
			return err
		}
	}
	return nil
}

// settleName decides who holds base among every account claiming it (holding it, or "base#tag" after losing a
// clash): the lowest (rank, user_id), except that an account replaced by a winning REKEY loses to its successor when
// the successor claims the same name (D111). Only used for names a REKEY touches, so the result does not depend on
// the order in which the entries and REKEYs arrived.
func settleName(ctx context.Context, tx *sql.Tx, base string) error {
	type claimant struct {
		id   []byte
		name string
		rank int64
		away bool
	}
	rows, err := tx.QueryContext(ctx, `SELECT u.user_id, u.username, u.entry_created_ms,
		EXISTS (SELECT 1 FROM rekeys k JOIN users n ON n.user_id=k.new_user_id WHERE k.old_user_id=u.user_id
		  AND (n.username=?1 OR substr(n.username,1,length(?1)+1)=?1||'#'))
		FROM users u WHERE u.username=?1 OR substr(u.username,1,length(?1)+1)=?1||'#'`, base)
	if err != nil {
		return err
	}
	var cs []claimant
	for rows.Next() {
		var c claimant
		if err := rows.Scan(&c.id, &c.name, &c.rank, &c.away); err != nil {
			rows.Close()
			return err
		}
		cs = append(cs, c)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(cs) == 0 {
		return nil
	}
	best := -1
	for _, onlyStaying := range []bool{true, false} { // a cycle of REKEYs (all away) falls back to every claimant
		for i, c := range cs {
			if (!onlyStaying || !c.away) && (best < 0 || wins(c.rank, c.id, cs[best].rank, cs[best].id)) {
				best = i
			}
		}
		if best >= 0 {
			break
		}
	}
	for i, c := range cs { // losers first: usernames are unique
		if i != best && c.name != conflictName(base, c.id) {
			if _, err := tx.ExecContext(ctx, `UPDATE users SET username=?, username_conflict=1 WHERE user_id=?`,
				conflictName(base, c.id), c.id); err != nil {
				return err
			}
		}
	}
	if cs[best].name != base {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET username=?, username_conflict=0 WHERE user_id=?`, base, cs[best].id); err != nil {
			return err
		}
	}
	if len(cs) > 1 {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO username_clashes(username) VALUES(?)`, base); err != nil {
			return err
		}
	}
	return nil
}

// IsRekeyTarget reports whether a winning REKEY names user as the new account (D111).
func (s *Store) IsRekeyTarget(ctx context.Context, user []byte) (bool, error) {
	var x int
	err := s.r.QueryRowContext(ctx, `SELECT 1 FROM rekeys WHERE new_user_id=? LIMIT 1`, user).Scan(&x)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// Rekeys returns the winning REKEY record of every replaced account (serialized), oldest first, for directory.sync.
func (s *Store) Rekeys(ctx context.Context) ([][]byte, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT r.raw FROM rekeys k JOIN records r ON r.record_key=k.record_key
		ORDER BY k.created_ms, k.record_key`)
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
