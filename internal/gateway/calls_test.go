package gateway

import (
	"bytes"
	"strings"
	"testing"

	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/turnsrv"
)

func TestTurnCredentialsAndPushStatus(t *testing.T) {
	n := startNode(t)
	anna, ca := newTestUser(t, n, "anna")
	boris, cb := newTestUser(t, n, "boris")
	// not logged in
	if st, _ := ca.call("turn.credentials", &pb.Empty{}, nil); st != pb.Status_STATUS_UNAUTHORIZED {
		t.Fatalf("not logged in: %v", st)
	}
	if st, _ := ca.call("push.status", &pb.PushStatusRequest{UserId: boris.id}, nil); st != pb.Status_STATUS_UNAUTHORIZED {
		t.Fatalf("push.status not logged in: %v", st)
	}
	login(t, ca, anna)
	// TURN off
	if st, _ := ca.call("turn.credentials", &pb.Empty{}, nil); st != pb.Status_STATUS_UNAVAILABLE {
		t.Fatalf("turn off: %v", st)
	}
	// TURN on
	n.svc.Turn = turnsrv.Issuer{Secret: bytes.Repeat([]byte{1}, 32), RelayIP: "203.0.113.7", TLS: true, UDPPort: 3478, TCPPort: 3478, TLSPort: 5349}
	var cr pb.TurnCredentials
	if st, msg := ca.call("turn.credentials", &pb.Empty{}, &cr); st != pb.Status_STATUS_OK {
		t.Fatalf("turn on: %v %s", st, msg)
	}
	if len(cr.Urls) != 3 || cr.Urls[0] != "turn:203.0.113.7:3478?transport=udp" || !strings.HasSuffix(cr.Username, ":"+turnsrv.UserTag(anna.id)) {
		t.Fatalf("creds %+v", &cr)
	}
	// push.status
	var ps pb.PushStatus
	if st, _ := ca.call("push.status", &pb.PushStatusRequest{UserId: boris.id}, &ps); st != pb.Status_STATUS_OK || ps.HasPush {
		t.Fatalf("no token yet: %v %v", st, ps.HasPush)
	}
	login(t, cb, boris)
	tokReq := &pb.RecordRequest{Record: sign(t, pb.RecordType_PUSH_TOKEN, boris.id, &pb.PushToken{DeviceId: 1, Kind: pb.PushToken_FCM, Token: "tok"}, boris.priv)}
	if st, msg := cb.call("push.register", tokReq, nil); st != pb.Status_STATUS_OK {
		t.Fatalf("register: %v %s", st, msg)
	}
	if st, _ := ca.call("push.status", &pb.PushStatusRequest{UserId: boris.id}, &ps); st != pb.Status_STATUS_OK || !ps.HasPush {
		t.Fatalf("token stored: %v %v", st, ps.HasPush)
	}
	if st, _ := ca.call("push.status", &pb.PushStatusRequest{}, &ps); st != pb.Status_STATUS_INVALID {
		t.Fatalf("empty user: %v", st)
	}
}
