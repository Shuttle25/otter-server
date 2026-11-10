package gateway

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/service"
)

var public = map[string]bool{"ping": true, "manifest.get": true, "register": true, "auth.login": true}

func status(err error) pb.Status {
	switch {
	case errors.Is(err, service.ErrInvalid):
		return pb.Status_STATUS_INVALID
	case errors.Is(err, service.ErrNotFound):
		return pb.Status_STATUS_NOT_FOUND
	case errors.Is(err, service.ErrConflict):
		return pb.Status_STATUS_CONFLICT
	case errors.Is(err, service.ErrUnauthorized):
		return pb.Status_STATUS_UNAUTHORIZED
	case errors.Is(err, service.ErrRevoked):
		return pb.Status_STATUS_REVOKED
	default:
		return pb.Status_STATUS_INTERNAL
	}
}

func (s *session) handle(ctx context.Context, req *pb.Request) {
	resp := &pb.Response{Id: req.Id}
	body, err := s.dispatch(ctx, req)
	if err != nil {
		resp.Status = status(err)
		resp.Error = err.Error()
		if resp.Status == pb.Status_STATUS_INTERNAL {
			s.g.log.Error("request failed", "method", req.Method, "err", err)
			resp.Error = "internal error"
		}
	} else if body != nil {
		resp.Body, _ = proto.Marshal(body)
	}
	s.send(&pb.Frame{Kind: &pb.Frame_Response{Response: resp}})
}

func decode(b []byte, m proto.Message) error {
	if err := proto.Unmarshal(b, m); err != nil {
		return fmt.Errorf("%w: %v", service.ErrInvalid, err)
	}
	return nil
}

func (s *session) dispatch(ctx context.Context, req *pb.Request) (proto.Message, error) {
	if !public[req.Method] && !s.loggedIn() {
		return nil, fmt.Errorf("%w: login required", service.ErrUnauthorized)
	}
	svc := s.g.svc
	switch req.Method {
	case "ping":
		return &pb.Empty{}, nil
	case "manifest.get":
		rec, _, err := svc.Manifest(ctx)
		if err != nil {
			return nil, err
		}
		return &pb.ManifestResponse{Manifest: rec}, nil
	case "register":
		var r pb.RegisterRequest
		if err := decode(req.Body, &r); err != nil {
			return nil, err
		}
		_, err := svc.Register(ctx, &r)
		return &pb.Empty{}, err
	case "auth.login":
		if s.loggedIn() {
			return nil, fmt.Errorf("%w: already logged in", service.ErrInvalid)
		}
		var r pb.LoginRequest
		if err := decode(req.Body, &r); err != nil {
			return nil, err
		}
		if err := svc.VerifyLogin(ctx, s.nonce, &r); err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.user, s.device = r.UserId, r.DeviceId
		s.mu.Unlock()
		s.g.add(s)
		go s.deliverLoop()
		s.kick()
		return &pb.Empty{}, nil
	case "directory.sync":
		recs, err := svc.Directory(ctx)
		if err != nil {
			return nil, err
		}
		return &pb.RecordBatch{Records: recs}, nil
	case "prekeys.fetch":
		var r pb.PreKeyFetchRequest
		if err := decode(req.Body, &r); err != nil {
			return nil, err
		}
		return svc.FetchPrekeys(ctx, &r)
	case "prekeys.upload", "msg.send", "msg.ack", "invite.create":
		var r pb.RecordRequest
		if err := decode(req.Body, &r); err != nil {
			return nil, err
		}
		if r.Record == nil {
			return nil, fmt.Errorf("%w: record missing", service.ErrInvalid)
		}
		allowed := map[string]pb.RecordType{"prekeys.upload": pb.RecordType_PREKEYS, "msg.send": pb.RecordType_ENVELOPE,
			"msg.ack": pb.RecordType_ACK, "invite.create": pb.RecordType_INVITE}[req.Method]
		_, err := svc.Submit(ctx, s.user, r.Record, allowed)
		return &pb.Empty{}, err
	default:
		return nil, fmt.Errorf("%w: unknown method %q", service.ErrInvalid, req.Method)
	}
}
