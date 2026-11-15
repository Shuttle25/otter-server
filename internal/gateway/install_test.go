package gateway

import (
	"crypto/ed25519"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
)

// C14 + D56: the restored phone signs INSTALL over its own session; the old phone is cut off, the new one is not,
// and a later login hands out exactly that record. A forged INSTALL is refused.
func TestInstallPublishReplacesOldPhone(t *testing.T) {
	n := startNode(t)
	as, cs := members(t, n, "anna", "boris")
	anna, boris := as[0], as[1]
	oldPhone := cs[0]
	newPhone := dial(t, n)
	login(t, newPhone, anna)

	forged := sign(t, pb.RecordType_INSTALL, anna.id, &pb.Install{RegistrationId: 77, InstalledMs: time.Now().UnixMilli()}, boris.priv)
	if s, _ := newPhone.call("install.publish", &pb.RecordRequest{Record: forged}, nil); s != pb.Status_STATUS_INVALID {
		t.Fatalf("forged install: %v", s)
	}
	inst := sign(t, pb.RecordType_INSTALL, anna.id, &pb.Install{RegistrationId: 77, InstalledMs: time.Now().UnixMilli()}, anna.priv)
	if s, msg := newPhone.call("install.publish", &pb.RecordRequest{Record: inst}, nil); s != pb.Status_STATUS_OK {
		t.Fatalf("install: %v %s", s, msg)
	}
	ack := sign(t, pb.RecordType_ACK, anna.id, &pb.Ack{EnvelopeIds: [][]byte{make([]byte, 32)}, DeviceId: 1}, anna.priv)
	if s, ok := tryCall(oldPhone, "msg.ack", &pb.RecordRequest{Record: ack}); ok && s != pb.Status_STATUS_UNAUTHORIZED {
		t.Fatalf("ack from the replaced install: %v", s)
	}
	if s, msg := newPhone.call("msg.ack", &pb.RecordRequest{Record: ack}, nil); s != pb.Status_STATUS_OK {
		t.Fatalf("ack from the new install: %v %s", s, msg)
	}
	var resp pb.LoginResponse
	c := dial(t, n)
	ts := time.Now().UnixMilli()
	c.call("auth.login", &pb.LoginRequest{UserId: anna.id, DeviceId: 1, TsMs: ts,
		Signature: ed25519.Sign(anna.priv, keys.AuthMessage(c.hello.NodeId, c.hello.Nonce, ts))}, &resp)
	if resp.Install == nil || !proto.Equal(resp.Install, inst) || resp.RegistrationId != 77 {
		t.Fatalf("login response: %+v", &resp)
	}
}
