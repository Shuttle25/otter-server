package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/turnsrv"
)

// The owner follows revocations in journalctl: applying one, refused logins and refused TURN each leave an Info line
// with the short user tag (never the username), and a retrying phone does not flood the log.
func TestRevocationEffectsAreLogged(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	var logs bytes.Buffer
	f.svc.Log = slog.New(slog.NewTextHandler(&logs, nil))
	now := time.Now()
	f.svc.Now = func() time.Time { return now }
	f.notes.sessions = 2
	f.svc.LoadRevoked(ctx)
	anna := f.mustRegister(f.invite(nil, time.Hour), "anna")
	tag := userTag(anna.id)

	f.netRecord(pb.RecordType_REVOCATION, &pb.Revocation{UserId: anna.id, Reason: "lost phone"})
	f.svc.RefreshRevoked(ctx) // nothing new: no second line
	if n := strings.Count(logs.String(), `msg="revocation applied" user=`+tag+` reason="lost phone" sessions_closed=2`); n != 1 {
		t.Fatalf("revocation lines: %d\n%s", n, logs.String())
	}
	if strings.Contains(logs.String(), "anna") {
		t.Fatalf("username in the log:\n%s", logs.String())
	}

	login := func() {
		t.Helper()
		ts := now.UnixMilli()
		req := &pb.LoginRequest{UserId: anna.id, DeviceId: 1, TsMs: ts,
			Signature: ed25519.Sign(anna.priv, keys.AuthMessage(f.svc.NodeID, []byte("n"), ts))}
		if _, err := f.svc.VerifyLogin(ctx, []byte("n"), req); !errors.Is(err, ErrRevoked) {
			t.Fatalf("login: %v", err)
		}
	}
	refused := `msg="login refused" user=` + tag + ` reason=revoked`
	for range 5 {
		login()
	}
	if n := strings.Count(logs.String(), refused); n != 1 {
		t.Fatalf("login refused lines after 5 tries: %d\n%s", n, logs.String())
	}
	now = now.Add(61 * time.Second)
	login()
	if n := strings.Count(logs.String(), refused); n != 2 {
		t.Fatalf("login refused lines a minute later: %d", n)
	}

	for range 3 {
		if !f.svc.TurnTagRevoked(turnsrv.UserTag(anna.id)) {
			t.Fatal("turn not refused")
		}
	}
	if n := strings.Count(logs.String(), `msg="turn refused" user=`+tag+` reason=revoked`); n != 1 {
		t.Fatalf("turn refused lines: %d\n%s", n, logs.String())
	}
}

// A node restart loads the revoked accounts without a line per old revocation; a duplicate-invite disable is
// logged with its reason.
func TestDuplicateDisableLoggedNotOnLoad(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	var logs bytes.Buffer
	f.svc.Log = slog.New(slog.NewTextHandler(&logs, nil))
	tk := f.invite(nil, time.Hour)
	f.mustRegister(tk, "anna")
	_, rec := f.replicatedEntry(tk, "boris", nil) // the same invite redeemed again elsewhere
	if _, err := f.svc.ApplyReplicated(ctx, r16(), rec); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(logs.String(), `msg="revocation applied"`); n != 1 || !strings.Contains(logs.String(), `reason="duplicate invite"`) {
		t.Fatalf("duplicate disable lines: %d\n%s", n, logs.String())
	}
	logs.Reset()
	g := New(f.svc.Store, f.svc.NodeKeyPriv, f.svc.NetworkPub) // the node restarts
	g.Log = slog.New(slog.NewTextHandler(&logs, nil))
	g.LoadRevoked(ctx)
	if strings.Contains(logs.String(), "revocation applied") {
		t.Fatalf("old revocation logged on load:\n%s", logs.String())
	}
}
