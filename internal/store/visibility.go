package store

import "context"

// DirRow is one member's current directory entry (the raw Record) with its user id (M9.5, D135).
type DirRow struct {
	UserID []byte
	Raw    []byte
}

// DirectoryRows returns every member's current entry with its id, in DirectoryEntries order.
func (s *Store) DirectoryRows(ctx context.Context) ([]DirRow, error) {
	rows, err := s.r.QueryContext(ctx,
		`SELECT u.user_id, r.raw FROM users u JOIN records r ON r.record_key=u.entry_key ORDER BY u.created_ms, u.user_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DirRow
	for rows.Next() {
		var d DirRow
		if err := rows.Scan(&d.UserID, &d.Raw); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) ids(ctx context.Context, q string, args ...any) ([][]byte, error) {
	rows, err := s.r.QueryContext(ctx, q, args...)
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

// Inviters returns the authors of the invites user redeemed (the network's id16 for a bootstrap invite). A founding
// member and a re-key target admitted without a chain have none.
func (s *Store) Inviters(ctx context.Context, user []byte) ([][]byte, error) {
	return s.ids(ctx, `SELECT inviter FROM redemptions WHERE user_id=?`, user)
}

// Invitees returns the members who redeemed an invite written by user.
func (s *Store) Invitees(ctx context.Context, user []byte) ([][]byte, error) {
	return s.ids(ctx, `SELECT user_id FROM redemptions WHERE inviter=?`, user)
}

// Rivals returns the other members who redeemed the same invite as user (the phone needs all of them for D102).
func (s *Store) Rivals(ctx context.Context, user []byte) ([][]byte, error) {
	return s.ids(ctx, `SELECT b.user_id FROM redemptions a JOIN redemptions b ON a.invite_id=b.invite_id
		WHERE a.user_id=? AND b.user_id<>a.user_id`, user)
}

// RekeyedTo returns the account old was re-keyed to (D111), nil when none.
func (s *Store) RekeyedTo(ctx context.Context, old []byte) ([]byte, error) {
	ids, err := s.ids(ctx, `SELECT new_user_id FROM rekeys WHERE old_user_id=?`, old)
	if err != nil || len(ids) == 0 {
		return nil, err
	}
	return ids[0], nil
}

// RekeyedFrom returns the old accounts that were re-keyed to newID (D111).
func (s *Store) RekeyedFrom(ctx context.Context, newID []byte) ([][]byte, error) {
	return s.ids(ctx, `SELECT old_user_id FROM rekeys WHERE new_user_id=?`, newID)
}
