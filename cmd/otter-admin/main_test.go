package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/admin"
	"ottermsg/server/internal/gateway"
	"ottermsg/server/internal/keys"
	"ottermsg/server/internal/netcode"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
	"ottermsg/server/internal/service"
	"ottermsg/server/internal/store"
)

// TestMain replaces the desktop keyring with an in-memory one: no test may touch the owner's real keyring.
func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

func TestCLIFlow(t *testing.T) {
	t.Setenv("OTTER_ADMIN_PASSPHRASE", "a very long passphrase")
	dir := t.TempDir()
	steps := [][]string{
		{"--dir", dir, "network", "init"},
		{"--dir", dir, "node", "add", "--label", "fi-1", "--wss-host", "chat.example.org"},
		{"--dir", dir, "manifest", "sign"},
		{"--dir", dir, "manifest", "show"},
		{"--dir", dir, "invite", "bootstrap", "--ttl", "1h"},
	}
	var out bytes.Buffer
	for _, s := range steps {
		if err := run(s, &out, strings.NewReader("")); err != nil {
			t.Fatalf("%v: %v", s, err)
		}
	}
	if !strings.Contains(out.String(), "signature OK") || !strings.Contains(out.String(), "chat.example.org") ||
		!strings.Contains(out.String(), "otter://join/") || !strings.Contains(out.String(), "otter-node import") {
		t.Fatalf("output: %s", out.String())
	}
}

func TestNetworkCode(t *testing.T) {
	t.Setenv("OTTER_ADMIN_PASSPHRASE", "a very long passphrase")
	dir := t.TempDir()
	var out bytes.Buffer
	if err := run([]string{"--dir", dir, "network", "init"}, &out, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	st, err := admin.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("OTTER_ADMIN_PASSPHRASE", "") // the code needs no passphrase
	out.Reset()
	if err := run([]string{"--dir", dir, "network", "code"}, &out, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	if want := "network code: " + netcode.Code(st.NetworkPub) + "\n"; out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}
}

func TestInteractivePassphrase(t *testing.T) {
	t.Setenv("OTTER_ADMIN_PASSPHRASE", "")
	dir := t.TempDir()
	var out bytes.Buffer
	if err := run([]string{"--dir", dir, "network", "init"}, &out, strings.NewReader("short\nshort\n")); err == nil {
		t.Fatal("short passphrase accepted")
	}
	if err := run([]string{"--dir", dir, "network", "init"}, &out, strings.NewReader("a very long passphrase\nanother long passphrase\n")); err == nil {
		t.Fatal("mismatched passphrases accepted")
	}
	if err := run([]string{"--dir", dir, "network", "init"}, &out, strings.NewReader("a very long passphrase\na very long passphrase\n")); err != nil {
		t.Fatal(err)
	}
}

func TestManifestPublish(t *testing.T) {
	t.Setenv("OTTER_ADMIN_PASSPHRASE", "a very long passphrase")
	dir := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	var out bytes.Buffer
	for _, s := range [][]string{
		{"--dir", dir, "network", "init"},
		{"--dir", dir, "node", "add", "--label", "dev", "--plain", "--wss-host", "127.0.0.1", "--wss-port", strconv.Itoa(port), "--wss-path", "/devpath"},
		{"--dir", dir, "manifest", "sign"},
	} {
		if err := run(s, &out, strings.NewReader("")); err != nil {
			t.Fatalf("%v: %v", s, err)
		}
	}
	// a node serving the client protocol, holding manifest v1
	st, _ := admin.LoadState(dir)
	nodeKey, err := keys.ReadPlainKey(filepath.Join(dir, "nodes", "dev", "node.key"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	svc := service.New(db, nodeKey, st.NetworkPub)
	raw, _ := os.ReadFile(filepath.Join(dir, "manifest.bin"))
	var v1 pb.Record
	proto.Unmarshal(raw, &v1)
	if _, err := svc.ImportRecord(context.Background(), &v1); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/devpath", gateway.New(svc, slog.New(slog.DiscardHandler)))
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	out.Reset()
	if err := run([]string{"--dir", dir, "manifest", "publish"}, &out, nil); err == nil {
		t.Fatal("plain endpoint used without --allow-plain")
	}
	if err := run([]string{"--dir", dir, "manifest", "sign"}, &out, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run([]string{"--dir", dir, "manifest", "publish", "--allow-plain"}, &out, nil); err != nil || !strings.Contains(out.String(), "dev          ok") {
		t.Fatalf("publish: %v\n%s", err, out.String())
	}
	if svc.CurrentManifest().Version != 2 {
		t.Fatalf("node has v%d", svc.CurrentManifest().Version)
	}
	out.Reset()
	if err := run([]string{"--dir", dir, "manifest", "publish", "--allow-plain", "--via", "dev"}, &out, nil); err != nil || !strings.Contains(out.String(), "already current") {
		t.Fatalf("republish: %v\n%s", err, out.String())
	}
	out.Reset()
	if err := run([]string{"--dir", dir, "manifest", "publish", "--allow-plain", "--via", "nope"}, &out, nil); err == nil || !strings.Contains(out.String(), "not in the manifest") {
		t.Fatalf("unknown label: %v\n%s", err, out.String())
	}
}

func TestVersion(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"version"}, &out, strings.NewReader("")); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != version {
		t.Fatalf("got %q", out.String())
	}
}

func TestNodeOpsCLI(t *testing.T) {
	t.Setenv("OTTER_ADMIN_PASSPHRASE", "a very long passphrase")
	dir := t.TempDir()
	var out bytes.Buffer
	for _, s := range [][]string{
		{"--dir", dir, "network", "init"},
		{"--dir", dir, "node", "add", "--label", "fi-1", "--wss-host", "chat.example.org"},
		{"--dir", dir, "node", "set-ip", "--label", "fi-1", "--ip", "203.0.113.10"},
		{"--dir", dir, "node", "env", "--label", "fi-1"},
		{"--dir", dir, "dns", "records"},
		{"--dir", dir, "node", "rotate-tls", "--label", "fi-1"},
		{"--dir", dir, "node", "drop-old-pins", "--label", "fi-1"},
		{"--dir", dir, "node", "set-push", "--label", "fi-1"},
	} {
		if err := run(s, &out, strings.NewReader("")); err != nil {
			t.Fatalf("%v: %v", s, err)
		}
	}
	for _, want := range []string{"OTTER_PORT='27443'", "IN  A     203.0.113.10", "pin unchanged", "only the new pin remains",
		"node fi-1: push_capable=true. Run 'manifest sign' and 'manifest publish'."} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in\n%s", want, out.String())
		}
	}
	if err := run([]string{"--dir", dir, "node", "set-ip", "--label", "fi-1"}, &out, strings.NewReader("")); err == nil {
		t.Fatal("set-ip without --ip accepted")
	}
	out.Reset()
	if err := run([]string{"--dir", dir, "node", "set-push", "--label", "fi-1", "--off"}, &out, strings.NewReader("")); err != nil ||
		!strings.Contains(out.String(), "push_capable=false") {
		t.Fatalf("set-push --off: %v %s", err, out.String())
	}
	if err := run([]string{"--dir", dir, "node", "set-push", "--label", "nope"}, &out, strings.NewReader("")); err == nil {
		t.Fatal("set-push accepted an unknown label")
	}
}

// devNode starts an in-process node for label "dev" of the admin dir, holding the current manifest.bin.
func devNode(t *testing.T, dir string, ln net.Listener) *service.Service {
	t.Helper()
	st, _ := admin.LoadState(dir)
	nodeKey, err := keys.ReadPlainKey(filepath.Join(dir, "nodes", "dev", "node.key"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	svc := service.New(db, nodeKey, st.NetworkPub)
	raw, _ := os.ReadFile(filepath.Join(dir, "manifest.bin"))
	var m pb.Record
	proto.Unmarshal(raw, &m)
	if _, err := svc.ImportRecord(context.Background(), &m); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/devpath", gateway.New(svc, slog.New(slog.DiscardHandler)))
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return svc
}

func TestNewsCLI(t *testing.T) {
	keyring.MockInit()
	t.Setenv("OTTER_ADMIN_PASSPHRASE", "a very long passphrase")
	dir := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	var out bytes.Buffer
	runOK := func(args ...string) string {
		t.Helper()
		out.Reset()
		if err := run(append([]string{"--dir", dir}, args...), &out, strings.NewReader("")); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out.String())
		}
		return out.String()
	}
	runOK("network", "init")
	runOK("node", "add", "--label", "dev", "--plain", "--wss-host", "127.0.0.1", "--wss-port", strconv.Itoa(port), "--wss-path", "/devpath")
	if err := run([]string{"--dir", dir, "announce", "--ru", "x"}, &out, nil); err == nil {
		t.Fatal("announce without a news key")
	}
	o := runOK("news", "init")
	if !strings.Contains(o, "news key ") || !strings.Contains(o, "Run 'manifest sign' and 'manifest publish'") {
		t.Fatalf("news init: %s", o)
	}
	pubHex := strings.Fields(o)[2]
	if err := run([]string{"--dir", dir, "news", "init"}, &out, nil); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second news init: %v", err)
	}
	if o := runOK("news", "show"); !strings.Contains(o, pubHex+" (this keyring)") {
		t.Fatalf("news show: %s", o)
	}
	runOK("manifest", "sign")
	if o := runOK("manifest", "show"); !strings.Contains(o, `"newsKeys"`) {
		t.Fatalf("manifest show: %s", o)
	}
	svc := devNode(t, dir, ln)

	ru := filepath.Join(t.TempDir(), "ru.txt")
	os.WriteFile(ru, []byte("  Вышла версия 0.6.0\n"), 0o644)
	apk := filepath.Join(t.TempDir(), "app.apk")
	os.WriteFile(apk, []byte("not really an apk"), 0o644)
	if err := run([]string{"--dir", dir, "announce", "--ru", ru}, &out, nil); err == nil {
		t.Fatal("plain endpoint used without --allow-plain")
	}
	if err := run([]string{"--dir", dir, "announce", "--ru", ru, "--apk", apk}, &out, nil); err == nil {
		t.Fatal("--apk without a version accepted")
	}
	if err := run([]string{"--dir", dir, "announce"}, &out, nil); err == nil {
		t.Fatal("announce without text accepted")
	}
	o = runOK("announce", "--ru", ru, "--apk", apk, "--version-name", "0.6.0", "--version-code", "6", "--allow-plain")
	if !strings.Contains(o, "announcement ") || !strings.Contains(o, "dev          ok") {
		t.Fatalf("announce: %s", o)
	}
	list, err := svc.News(context.Background())
	if err != nil || len(list) != 1 {
		t.Fatalf("node has %d news records: %v", len(list), err)
	}
	o = runOK("announce", "--list")
	if !strings.Contains(o, "Вышла версия 0.6.0 [APK 0.6.0]") {
		t.Fatalf("list: %s", o)
	}
	id := strings.Fields(o)[2]
	o = runOK("announce", "--delete", id[:8], "--allow-plain")
	if !strings.Contains(o, "dev          ok") {
		t.Fatalf("delete: %s", o)
	}
	if list, _ := svc.News(context.Background()); len(list) != 1 || bodyType(list[0]) != pb.RecordType_ANNOUNCEMENT_DELETED {
		t.Fatalf("node after delete: %d records", len(list))
	}
	if o := runOK("announce", "--list"); !strings.Contains(o, "[deleted]") {
		t.Fatalf("list after delete: %s", o)
	}
	if err := run([]string{"--dir", dir, "announce", "--ru", ru, "--allow-plain", "--via", "nope"}, &out, nil); err == nil ||
		!strings.Contains(err.Error(), "not published to any node") {
		t.Fatalf("unknown label: %v", err)
	}
	runOK("news", "revoke", "--pub", pubHex)
	if o := runOK("news", "show"); strings.Contains(o, pubHex) {
		t.Fatalf("still listed: %s", o)
	}
	if err := run([]string{"--dir", dir, "announce", "--ru", ru, "--allow-plain"}, &out, nil); err == nil {
		t.Fatal("announced with a revoked key")
	}
}

func TestAnnounceUnreachable(t *testing.T) {
	keyring.MockInit()
	t.Setenv("OTTER_ADMIN_PASSPHRASE", "a very long passphrase")
	dir := t.TempDir()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	var out bytes.Buffer
	for _, s := range [][]string{
		{"network", "init"},
		{"node", "add", "--label", "dev", "--plain", "--wss-host", "127.0.0.1", "--wss-port", strconv.Itoa(port), "--wss-path", "/devpath"},
		{"news", "init"},
		{"manifest", "sign"},
	} {
		if err := run(append([]string{"--dir", dir}, s...), &out, strings.NewReader("")); err != nil {
			t.Fatalf("%v: %v", s, err)
		}
	}
	ru := filepath.Join(t.TempDir(), "ru.txt")
	os.WriteFile(ru, []byte("Привет"), 0o644)
	out.Reset()
	err := run([]string{"--dir", dir, "announce", "--ru", ru, "--allow-plain"}, &out, nil)
	if err == nil || !strings.Contains(err.Error(), "not published to any node") || !strings.Contains(out.String(), "dev          error") {
		t.Fatalf("unreachable: %v\n%s", err, out.String())
	}
}

func bodyType(r *pb.Record) pb.RecordType {
	var b pb.RecordBody
	proto.Unmarshal(r.Body, &b)
	return b.Type
}

func TestDialOutOnlyAndRealityCLI(t *testing.T) {
	t.Setenv("OTTER_ADMIN_PASSPHRASE", "a very long passphrase")
	dir := t.TempDir()
	var out bytes.Buffer
	pub := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	for _, s := range [][]string{
		{"--dir", dir, "network", "init"},
		{"--dir", dir, "node", "add", "--label", "fi-1", "--wss-host", "chat.example.org"},
		{"--dir", dir, "node", "set-dial-out-only", "--label", "fi-1"},
		{"--dir", dir, "node", "set-no-backups", "--label", "fi-1"},
		{"--dir", dir, "node", "add-reality", "--label", "fi-1", "--host", "203.0.113.10", "--port", "443", "--pub", pub,
			"--server-name", "www.example.com", "--short-id", "abcd0123"},
		{"--dir", dir, "node", "list"},
	} {
		if err := run(s, &out, strings.NewReader("")); err != nil {
			t.Fatalf("%v: %v", s, err)
		}
	}
	for _, want := range []string{"node fi-1: dial_out_only=true. Run 'manifest sign' and 'manifest publish'.",
		"node fi-1: REALITY 203.0.113.10:443 server_name=www.example.com", `short_ids = ["abcd0123"]`,
		"node fi-1: no_backups=true. Run 'manifest sign' and 'manifest publish'.",
		"REALITY 203.0.113.10:443", "dial_out_only=true no_backups=true sni=www.example.com"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in\n%s", want, out.String())
		}
	}
	out.Reset()
	if err := run([]string{"--dir", dir, "node", "set-dial-out-only", "--label", "fi-1", "--off"}, &out, strings.NewReader("")); err != nil ||
		!strings.Contains(out.String(), "dial_out_only=false") {
		t.Fatalf("set-dial-out-only --off: %v %s", err, out.String())
	}
	if err := run([]string{"--dir", dir, "node", "set-dial-out-only", "--label", "nope"}, &out, strings.NewReader("")); err == nil {
		t.Fatal("set-dial-out-only accepted an unknown label")
	}
	if err := run([]string{"--dir", dir, "node", "set-no-backups", "--label", "fi-1", "--off"}, &out, strings.NewReader("")); err != nil ||
		!strings.Contains(out.String(), "no_backups=false") {
		t.Fatalf("set-no-backups --off: %v %s", err, out.String())
	}
	if err := run([]string{"--dir", dir, "node", "set-no-backups", "--label", "nope"}, &out, strings.NewReader("")); err == nil {
		t.Fatal("set-no-backups accepted an unknown label")
	}
	if err := run([]string{"--dir", dir, "node", "add-reality", "--label", "fi-1", "--host", "h", "--pub", "short", "--server-name", "s"}, &out, strings.NewReader("")); err == nil {
		t.Fatal("add-reality accepted a bad public key")
	}
}

func TestAddWSSCLI(t *testing.T) {
	t.Setenv("OTTER_ADMIN_PASSPHRASE", "a very long passphrase")
	dir := t.TempDir()
	var out bytes.Buffer
	for _, s := range [][]string{
		{"--dir", dir, "network", "init"},
		{"--dir", dir, "node", "add", "--label", "fi-1", "--wss-host", "chat.example.org"},
	} {
		if err := run(s, &out, strings.NewReader("")); err != nil {
			t.Fatalf("%v: %v", s, err)
		}
	}
	out.Reset()
	if err := run([]string{"--dir", dir, "node", "add-wss", "--label", "fi-1", "--host", "n2.example.net", "--cdn"}, &out, nil); err != nil ||
		!strings.Contains(out.String(), "WSS n2.example.net:443 cdn=true priority=10 pins=0") {
		t.Fatalf("add-wss: %v %s", err, out.String())
	}
	out.Reset()
	if err := run([]string{"--dir", dir, "node", "list"}, &out, nil); err != nil || strings.Count(out.String(), "fi-1") != 2 {
		t.Fatalf("node list: %v %s", err, out.String())
	}
	out.Reset()
	if err := run([]string{"--dir", dir, "node", "remove-endpoint", "--label", "fi-1", "--host", "n2.example.net", "--port", "443"}, &out, nil); err != nil {
		t.Fatalf("remove-endpoint: %v %s", err, out.String())
	}
	if err := run([]string{"--dir", dir, "node", "remove-endpoint", "--label", "fi-1", "--host", "chat.example.org", "--port", "27443"}, &out, nil); err == nil {
		t.Fatal("removed the node's own endpoint")
	}
}

func signRec(t *testing.T, typ pb.RecordType, author []byte, m proto.Message, k ed25519.PrivateKey) *pb.Record {
	t.Helper()
	p, _ := proto.Marshal(m)
	id := make([]byte, 16)
	rand.Read(id)
	r, err := records.Sign(&pb.RecordBody{Id: id, Type: typ, Author: author, CreatedMs: time.Now().UnixMilli(), Payload: p}, k)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// joinWithLink registers an account on svc the way the app does with a link from 'invite bootstrap' (D100): the
// INVITE comes from the link, nothing was imported on the node.
func joinWithLink(t *testing.T, svc *service.Service, link, name string) []byte {
	t.Helper()
	b, err := admin.DecodeInviteLink(link)
	if err != nil || b.Invite == nil {
		t.Fatalf("link without INVITE: %v", err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	id := keys.ID16(pub)
	e := &pb.DirectoryEntry{UserId: id, Username: name, DisplayName: name, AccountPub: pub, IdentityPub: make([]byte, 33),
		IdentitySig: make([]byte, 64), Version: 1, RegisteredMs: time.Now().UnixMilli()}
	if err := records.Redeem(e, b.Invite, b.Secret); err != nil {
		t.Fatal(err)
	}
	pk := &pb.PreKeys{DeviceId: 1, RegistrationId: 9,
		SignedPrekey: &pb.SignedPreKey{Id: 1, PublicKey: make([]byte, 33), Signature: make([]byte, 64)},
		KyberPrekey:  &pb.SignedPreKey{Id: 1, PublicKey: make([]byte, 1569), Signature: make([]byte, 64)}}
	sum := sha256.Sum256(b.Secret)
	if _, err := svc.Register(context.Background(), &pb.RegisterRequest{
		DirectoryEntry: signRec(t, pb.RecordType_DIRECTORY_ENTRY, id, e, priv),
		Prekeys:        signRec(t, pb.RecordType_PREKEYS, id, pk, priv),
		InviteUsed:     signRec(t, pb.RecordType_INVITE_USED, id, &pb.InviteUsed{InviteId: sum[:], UserId: id}, priv)}); err != nil {
		t.Fatalf("register %s: %v", name, err)
	}
	return id
}

func TestUserCommands(t *testing.T) {
	t.Setenv("OTTER_ADMIN_PASSPHRASE", "a very long passphrase")
	dir := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	var out bytes.Buffer
	runIn := func(in string, args ...string) (string, error) {
		out.Reset()
		err := run(append([]string{"--dir", dir}, args...), &out, strings.NewReader(in))
		return out.String(), err
	}
	runOK := func(args ...string) string {
		t.Helper()
		o, err := runIn("", args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, o)
		}
		return o
	}
	runOK("network", "init")
	runOK("node", "add", "--label", "dev", "--plain", "--wss-host", "127.0.0.1", "--wss-port", strconv.Itoa(port), "--wss-path", "/devpath")
	runOK("manifest", "sign")
	link := func() string {
		for _, l := range strings.Split(runOK("invite", "bootstrap", "--ttl", "1h"), "\n") {
			if strings.HasPrefix(l, admin.InvitePrefix) {
				return l
			}
		}
		t.Fatal("no link")
		return ""
	}
	svc := devNode(t, dir, ln)
	ctx := context.Background()
	anna := joinWithLink(t, svc, link(), "anna")
	boris := joinWithLink(t, svc, link(), "boris")

	if _, err := runIn("", "user", "list"); err == nil {
		t.Fatal("plain endpoint used without --allow-plain")
	}
	o := runOK("user", "list", "--allow-plain")
	if !strings.Contains(o, fmt.Sprintf("anna#%x", anna[:4])) || !strings.Contains(o, fmt.Sprintf("%x", boris)) ||
		strings.Count(o, "invite=true") != 2 || strings.Contains(o, "not admitted") {
		t.Fatalf("list: %s", o)
	}

	// revoke: asks first; "n" cancels
	if _, err := runIn("n\n", "user", "revoke", "anna", "--allow-plain"); err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("revoke without confirmation: %v", err)
	}
	if u, _ := svc.Store.UserByID(ctx, anna); u.Revoked {
		t.Fatal("revoked without confirmation")
	}
	if _, err := runIn("", "user", "revoke", "nobody", "--yes", "--allow-plain"); err == nil {
		t.Fatal("unknown member revoked")
	}
	if o, err := runIn("y\n", "user", "revoke", "anna", "--reason", "lost phone", "--allow-plain"); err != nil || !strings.Contains(o, "dev          ok") {
		t.Fatalf("revoke: %v\n%s", err, o)
	}
	if u, _ := svc.Store.UserByID(ctx, anna); !u.Revoked {
		t.Fatal("anna not revoked on the node")
	}
	if _, err := os.Stat(filepath.Join(dir, "revocations", fmt.Sprintf("%x.bin", anna))); err != nil {
		t.Fatal(err)
	}
	if o := runOK("user", "list", "--allow-plain"); !strings.Contains(o, "revoked: lost phone") {
		t.Fatalf("list after revoke: %s", o)
	}

	// invite rights: version = highest known + 1
	if _, err := runIn("", "user", "invite-rights", "boris", "--allow-plain"); err == nil {
		t.Fatal("invite-rights without --on/--off")
	}
	runOK("user", "invite-rights", fmt.Sprintf("boris#%x", boris[:4]), "--off", "--allow-plain")
	if ok, _ := svc.Store.CanInviteAt(ctx, boris, time.Now().Add(time.Minute).UnixMilli()); ok {
		t.Fatal("boris still may invite")
	}
	runOK("user", "invite-rights", fmt.Sprintf("%x", boris), "--on", "--allow-plain")
	if ok, _ := svc.Store.CanInviteAt(ctx, boris, time.Now().Add(time.Minute).UnixMilli()); !ok {
		t.Fatal("boris's rights not restored (version 2 must beat version 1)")
	}
	if o := runOK("user", "list", "--allow-plain"); !strings.Contains(o, "invite=true  founding=false v2") {
		t.Fatalf("list after rights: %s", o)
	}

	// founding members end up in the next signed manifest
	if _, err := runIn("", "user", "found", "zz"); err == nil {
		t.Fatal("bad user id accepted")
	}
	if _, err := runIn("", "user", "found"); err == nil {
		t.Fatal("no user id accepted")
	}
	runOK("user", "found", fmt.Sprintf("%x", boris))
	if o := runOK("manifest", "sign"); !strings.Contains(o, `"foundingMembers"`) || !strings.Contains(o, base64.StdEncoding.EncodeToString(boris)) {
		t.Fatalf("manifest: %s", o)
	}

	// typed passphrase and confirmation share one input
	t.Setenv("OTTER_ADMIN_PASSPHRASE", "")
	if o, err := runIn("a very long passphrase\ny\n", "user", "revoke", "boris", "--allow-plain"); err != nil {
		t.Fatalf("interactive revoke: %v\n%s", err, o)
	}
	if u, _ := svc.Store.UserByID(ctx, boris); !u.Revoked {
		t.Fatal("boris not revoked")
	}
}

// D111 end to end on an in-process node: step 1 revokes the lost account and prints the invite, the new install
// registers with it under the same name, step 2 signs REKEY with the code read aloud and the name moves.
func TestUserRekey(t *testing.T) {
	t.Setenv("OTTER_ADMIN_PASSPHRASE", "a very long passphrase")
	dir := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	var out bytes.Buffer
	runIn := func(in string, args ...string) (string, error) {
		out.Reset()
		err := run(append([]string{"--dir", dir}, args...), &out, strings.NewReader(in))
		return out.String(), err
	}
	runOK := func(args ...string) string {
		t.Helper()
		o, err := runIn("", args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, o)
		}
		return o
	}
	linkIn := func(o string) string {
		t.Helper()
		for _, l := range strings.Split(o, "\n") {
			if strings.HasPrefix(l, admin.InvitePrefix) {
				return l
			}
		}
		t.Fatalf("no link in %s", o)
		return ""
	}
	runOK("network", "init")
	runOK("node", "add", "--label", "dev", "--plain", "--wss-host", "127.0.0.1", "--wss-port", strconv.Itoa(port), "--wss-path", "/devpath")
	runOK("manifest", "sign")
	svc := devNode(t, dir, ln)
	ctx := context.Background()
	old := joinWithLink(t, svc, linkIn(runOK("invite", "bootstrap", "--ttl", "1h")), "anna")
	boris := joinWithLink(t, svc, linkIn(runOK("invite", "bootstrap", "--ttl", "1h")), "boris")
	oldHex, newCode := fmt.Sprintf("%x", old), strings.Repeat("ab", 16)

	// usage and code errors come before the passphrase
	for _, args := range [][]string{
		{"user", "rekey", "anna", "--allow-plain"},
		{"user", "rekey", "anna", "--old", oldHex, "--new", newCode, "--allow-plain"},
		{"user", "rekey", "anna", "--old", oldHex[:30], "--yes", "--allow-plain"},
		{"user", "rekey", "anna", "--new", newCode, "--allow-plain"},          // step 2 before step 1
		{"user", "rekey", "boris", "--old", oldHex, "--yes", "--allow-plain"}, // the code is anna's
		{"user", "revoke", "anna", "--old", oldHex, "--allow-plain"},
	} {
		if o, err := runIn("", args...); err == nil {
			t.Fatalf("%v accepted:\n%s", args, o)
		}
	}
	if _, err := runIn("n\n", "user", "rekey", "anna", "--old", oldHex, "--allow-plain"); err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("rekey without confirmation: %v", err)
	}
	if u, _ := svc.Store.UserByID(ctx, old); u.Revoked {
		t.Fatal("revoked without confirmation")
	}

	// step 1
	o, err := runIn("y\n", "user", "rekey", "anna", "--old", strings.ToUpper(oldHex), "--allow-plain")
	if err != nil || strings.Count(o, "dev          ok") != 2 || !strings.Contains(o, "--new CODE") || !strings.Contains(o, "Код аккаунта") {
		t.Fatalf("step 1: %v\n%s", err, o)
	}
	if u, _ := svc.Store.UserByID(ctx, old); !u.Revoked {
		t.Fatal("old account not revoked on the node")
	}
	if fi, err := os.Stat(filepath.Join(dir, "rekeys", "anna.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v", err)
	}
	link := linkIn(o)
	if b, _ := admin.DecodeInviteLink(link); b.Invite == nil {
		t.Fatal("re-key link without INVITE")
	}

	// a misheard code, a code of someone else, the lost account's code: refused, nothing done
	if _, err := runIn("", "user", "rekey", "anna", "--new", newCode, "--allow-plain"); err == nil || !strings.Contains(err.Error(), "no account") {
		t.Fatalf("unknown new account: %v", err)
	}
	if _, err := runIn("", "user", "rekey", "anna", "--new", fmt.Sprintf("%x", boris), "--allow-plain"); err == nil {
		t.Fatal("boris's account accepted as anna's new install")
	}
	if _, err := runIn("", "user", "rekey", "anna", "--new", oldHex, "--allow-plain"); err == nil {
		t.Fatal("new == old accepted")
	}

	// the new install registers with the re-key invite under the same name (anna#tag until step 2)
	nw := joinWithLink(t, svc, link, "anna")
	if owner, _ := svc.Store.UsernameOwner(ctx, "anna"); !bytes.Equal(owner, old) {
		t.Fatalf("name moved before the REKEY: %x", owner)
	}
	code := fmt.Sprintf("%x", nw)
	spaced := strings.Join([]string{code[:4], code[4:8], code[8:12], code[12:16], code[16:20], code[20:24], code[24:28], code[28:]}, " ")
	o = runOK("user", "rekey", "anna", "--new", spaced, "--allow-plain")
	if !strings.Contains(o, "dev          ok") || !strings.Contains(o, "anna now belongs to "+code) {
		t.Fatalf("step 2: %s", o)
	}
	if owner, _ := svc.Store.UsernameOwner(ctx, "anna"); !bytes.Equal(owner, nw) {
		t.Fatalf("anna owned by %x after the REKEY, want %x", owner, nw)
	}
	if ok, _ := svc.Store.IsRekeyTarget(ctx, nw); !ok {
		t.Fatal("no REKEY stored on the node")
	}
	if _, err := os.Stat(filepath.Join(dir, "rekeys", "anna.done.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "rekeys", "anna.json")); !os.IsNotExist(err) {
		t.Fatalf("pending file left: %v", err)
	}
	if _, err := runIn("", "user", "rekey", "anna", "--new", code, "--allow-plain"); err == nil {
		t.Fatal("step 2 ran twice")
	}

	// user list understands the REKEY
	o = runOK("user", "list", "--allow-plain")
	oldTag, newTag := fmt.Sprintf("anna#%x", old[:4]), fmt.Sprintf("anna#%x", nw[:4])
	if !strings.Contains(o, "revoked: rekey, re-keyed → "+newTag) || !strings.Contains(o, "active (admitted by REKEY of "+oldTag+")") ||
		strings.Contains(o, "not admitted") {
		t.Fatalf("list: %s", o)
	}
}

// Step 1 fails without a reachable node and leaves nothing marked as started.
func TestUserRekeyUnreachable(t *testing.T) {
	t.Setenv("OTTER_ADMIN_PASSPHRASE", "a very long passphrase")
	dir := t.TempDir()
	var out bytes.Buffer
	for _, s := range [][]string{{"network", "init"}, {"node", "add", "--label", "dev", "--plain", "--wss-host", "127.0.0.1",
		"--wss-port", "1", "--wss-path", "/devpath"}, {"manifest", "sign"}} {
		if err := run(append([]string{"--dir", dir}, s...), &out, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := run([]string{"--dir", dir, "user", "rekey", "anna", "--old", strings.Repeat("01", 16), "--yes", "--allow-plain"}, &out, nil); err == nil {
		t.Fatal("rekey without a node succeeded")
	}
	if _, err := os.Stat(filepath.Join(dir, "rekeys", "anna.json")); !os.IsNotExist(err) {
		t.Fatalf("marked started: %v", err)
	}
}
