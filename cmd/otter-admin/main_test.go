package main

import (
	"bytes"
	"strings"
	"testing"
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
