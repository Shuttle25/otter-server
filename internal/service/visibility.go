package service

import (
	"context"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/store"
)

// entryListed reports the signed `listed` flag of a raw DIRECTORY_ENTRY Record (false when unreadable).
func entryListed(raw []byte) bool {
	var r pb.Record
	var b pb.RecordBody
	var e pb.DirectoryEntry
	if proto.Unmarshal(raw, &r) != nil || proto.Unmarshal(r.Body, &b) != nil || proto.Unmarshal(b.Payload, &e) != nil {
		return false
	}
	return e.Listed
}

type idSet map[string]bool

func (s idSet) add(ids ...[]byte) {
	for _, id := range ids {
		s[string(id)] = true
	}
}

// maxRekeyHops bounds a walk along re-keys (D111); a real account is re-keyed a handful of times at most.
const maxRekeyHops = 16

// related returns the direct inviter(s) and invitees of user, following re-keys (D111) both ways (D135): the
// relations of every older account of user count, and a related account that was re-keyed brings its newer ones.
func (s *Service) related(ctx context.Context, user []byte) (idSet, error) {
	lineage, todo := idSet{}, [][]byte{user}
	for len(todo) > 0 { // user and every older account that was re-keyed into it
		id := todo[0]
		todo = todo[1:]
		if lineage[string(id)] {
			continue
		}
		lineage.add(id)
		olds, err := s.Store.RekeyedFrom(ctx, id)
		if err != nil {
			return nil, err
		}
		todo = append(todo, olds...)
	}
	out := idSet{}
	for l := range lineage {
		for _, q := range []func(context.Context, []byte) ([][]byte, error){s.Store.Inviters, s.Store.Invitees} {
			ids, err := q(ctx, []byte(l))
			if err != nil {
				return nil, err
			}
			for _, id := range ids {
				for cur, n := id, 0; cur != nil && n < maxRekeyHops; n++ { // the account and every newer one it moved to
					out.add(cur)
					next, err := s.Store.RekeyedTo(ctx, cur)
					if err != nil {
						return nil, err
					}
					cur = next
				}
			}
		}
	}
	return out, nil
}

// closure adds what a phone needs to admit the seeds (D104, D135): every invite ancestor, every rival redemption of
// the same invite (D102) and every older account of a re-keyed one.
func (s *Service) closure(ctx context.Context, seeds idSet) (idSet, error) {
	out, todo := idSet{}, make([][]byte, 0, len(seeds))
	for id := range seeds {
		todo = append(todo, []byte(id))
	}
	for len(todo) > 0 {
		id := todo[0]
		todo = todo[1:]
		if out[string(id)] {
			continue
		}
		out.add(id)
		for _, q := range []func(context.Context, []byte) ([][]byte, error){s.Store.Inviters, s.Store.Rivals, s.Store.RekeyedFrom} {
			more, err := q(ctx, id)
			if err != nil {
				return nil, err
			}
			todo = append(todo, more...)
		}
	}
	return out, nil
}

// entries returns the current entries of the members in keep, in Directory order (ids without an entry, such as the
// network's id16 as a bootstrap inviter, are skipped).
func (s *Service) entries(ctx context.Context, rows []store.DirRow, keep idSet) ([]*pb.Record, error) {
	var out []*pb.Record
	for _, row := range rows {
		if !keep[string(row.UserID)] {
			continue
		}
		r := &pb.Record{}
		if err := proto.Unmarshal(row.Raw, r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// VisibleDirectory is what directory.sync and directory.list return to user (D135): own entry, listed members,
// direct inviter and invitees, the ancestry of all of these, and every REVOCATION, INVITE_RIGHTS and REKEY.
func (s *Service) VisibleDirectory(ctx context.Context, user []byte) ([]*pb.Record, error) {
	rows, err := s.Store.DirectoryRows(ctx)
	if err != nil {
		return nil, err
	}
	seeds, err := s.related(ctx, user)
	if err != nil {
		return nil, err
	}
	seeds.add(user)
	for _, row := range rows {
		if entryListed(row.Raw) {
			seeds.add(row.UserID)
		}
	}
	keep, err := s.closure(ctx, seeds)
	if err != nil {
		return nil, err
	}
	out, err := s.entries(ctx, rows, keep)
	if err != nil {
		return nil, err
	}
	extra, err := s.membershipRecords(ctx)
	if err != nil {
		return nil, err
	}
	return append(out, extra...), nil
}
