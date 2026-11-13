package service

import (
	"context"
	"fmt"
	"time"

	pb "ottermsg/server/internal/proto/otterv1"
)

// TurnIssuer issues TURN-REST credentials for this node's relay (turnsrv.Issuer).
type TurnIssuer interface {
	Issue(userID []byte, now time.Time) *pb.TurnCredentials
}

// TurnCredentials issues credentials valid only on this node's relay.
// M9 (user revocation) must make this refuse revoked users (spec "Server: new RPCs").
func (s *Service) TurnCredentials(user []byte) (*pb.TurnCredentials, error) {
	if s.Turn == nil {
		return nil, fmt.Errorf("%w: turn relay is off on this node", ErrUnavailable)
	}
	return s.Turn.Issue(user, s.Now()), nil
}

// PushStatus reports whether this node holds a push token for the user's phone (device 1). Records replicate, so
// any node can answer.
func (s *Service) PushStatus(ctx context.Context, user []byte) (bool, error) {
	if len(user) == 0 {
		return false, fmt.Errorf("%w: user_id", ErrInvalid)
	}
	tok, err := s.Store.PushToken(ctx, user, 1)
	return tok != "", err
}
