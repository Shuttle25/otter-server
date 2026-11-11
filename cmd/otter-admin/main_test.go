package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/admin"
	"ottermsg/server/internal/gateway"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/service"
	"ottermsg/server/internal/store"
)

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
