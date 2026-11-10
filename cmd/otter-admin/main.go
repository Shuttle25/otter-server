// Command otter-admin manages an OtterMSG network: keys, nodes and the signed manifest.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mdp/qrterminal/v3"
	"golang.org/x/term"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/admin"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

const usage = `usage: otter-admin [--dir DIR] <command>
  network init
  node add --label L --wss-host H [--wss-port 443] [--wss-path /p] [--cdn] [--push] [--plain]
  node list
  node remove --label L
  manifest sign
  manifest show [--file F]
  invite bootstrap [--ttl 168h]`

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func passphrase(in io.Reader, confirm bool) ([]byte, error) {
	if p := os.Getenv("OTTER_ADMIN_PASSPHRASE"); p != "" {
		if confirm && len(p) < 12 {
			return nil, errors.New("passphrase must be at least 12 characters")
		}
		return []byte(p), nil
	}
	br := bufio.NewReader(in)
	read := func(prompt string) ([]byte, error) {
		fmt.Fprint(os.Stderr, prompt)
		if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
			b, err := term.ReadPassword(int(f.Fd()))
			fmt.Fprintln(os.Stderr)
			return b, err
		}
		line, err := br.ReadString('\n')
		if err == io.EOF && line != "" {
			err = nil
		}
		return []byte(strings.TrimRight(line, "\r\n")), err
	}
	p, err := read("Admin key passphrase: ")
	if err != nil {
		return nil, err
	}
	if confirm {
		if len(p) < 12 {
			return nil, errors.New("passphrase must be at least 12 characters")
		}
		p2, err := read("Repeat passphrase: ")
		if err != nil {
			return nil, err
		}
		if string(p) != string(p2) {
			return nil, errors.New("passphrases differ")
		}
	}
	return p, nil
}

func run(args []string, out io.Writer, in io.Reader) error {
	root := flag.NewFlagSet("otter-admin", flag.ContinueOnError)
	dir := root.String("dir", defaultDir(), "admin state directory")
	if err := root.Parse(args); err != nil {
		return err
	}
	a := root.Args()
	if len(a) < 2 {
		return errors.New(usage)
	}
	switch a[0] + " " + a[1] {
	case "network init":
		p, err := passphrase(in, true)
		if err != nil {
			return err
		}
		if err := admin.InitNetwork(*dir, p); err != nil {
			return err
		}
		st, _ := admin.LoadState(*dir)
		fmt.Fprintf(out, "network created in %s\nnetwork_pub %x\nKeep a backup of network.key.enc and its passphrase.\n", *dir, st.NetworkPub)
	case "node add":
		fs := flag.NewFlagSet("node add", flag.ContinueOnError)
		var s admin.NodeSpec
		var port uint
		fs.StringVar(&s.Label, "label", "", "node label")
		fs.StringVar(&s.WSSHost, "wss-host", "", "WSS host")
		fs.UintVar(&port, "wss-port", 443, "WSS port")
		fs.StringVar(&s.WSSPath, "wss-path", "", "secret WebSocket path (random if empty)")
		fs.BoolVar(&s.CDN, "cdn", false, "endpoint is behind a CDN")
		fs.BoolVar(&s.Push, "push", false, "node can send FCM pushes")
		fs.BoolVar(&s.Plain, "plain", false, "development only: unencrypted ws:// endpoint")
		if err := fs.Parse(a[2:]); err != nil {
			return err
		}
		if port == 0 || port > 65535 {
			return fmt.Errorf("invalid --wss-port %d", port)
		}
		s.WSSPort = uint32(port)
		n, err := admin.AddNode(*dir, s)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "node %s added, node_id %x\nkey: %s\nRun 'manifest sign' to publish.\n", n.Label, n.NodeId, filepath.Join(*dir, "nodes", n.Label, "node.key"))
	case "node list":
		st, err := admin.LoadState(*dir)
		if err != nil {
			return err
		}
		for _, n := range st.Nodes {
			for _, e := range n.Endpoints {
				fmt.Fprintf(out, "%-12s %x  %s %s:%d%s cdn=%v\n", n.Label, n.NodeId, e.Kind, e.Host, e.Port, e.Path, e.ViaCdn)
			}
		}
	case "node remove":
		fs := flag.NewFlagSet("node remove", flag.ContinueOnError)
		label := fs.String("label", "", "node label")
		if err := fs.Parse(a[2:]); err != nil {
			return err
		}
		if err := admin.RemoveNode(*dir, *label); err != nil {
			return err
		}
		fmt.Fprintf(out, "node %s removed. Run 'manifest sign' to publish.\n", *label)
	case "manifest sign":
		p, err := passphrase(in, false)
		if err != nil {
			return err
		}
		rec, err := admin.SignManifest(*dir, p, time.Now())
		if err != nil {
			return err
		}
		return show(out, *dir, rec)
	case "manifest show":
		fs := flag.NewFlagSet("manifest show", flag.ContinueOnError)
		file := fs.String("file", "", "manifest file (default DIR/manifest.bin)")
		if err := fs.Parse(a[2:]); err != nil {
			return err
		}
		if *file == "" {
			*file = filepath.Join(*dir, "manifest.bin")
		}
		raw, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		var rec pb.Record
		if err := proto.Unmarshal(raw, &rec); err != nil {
			return err
		}
		return show(out, *dir, &rec)
	case "invite bootstrap":
		fs := flag.NewFlagSet("invite bootstrap", flag.ContinueOnError)
		ttl := fs.Duration("ttl", 7*24*time.Hour, "invite validity")
		if err := fs.Parse(a[2:]); err != nil {
			return err
		}
		p, err := passphrase(in, false)
		if err != nil {
			return err
		}
		res, err := admin.BootstrapInvite(*dir, p, time.Now(), *ttl)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Invite for the first member (valid %s):\n%s\n\n", *ttl, res.Link)
		qrterminal.GenerateHalfBlock(res.Link, qrterminal.L, out)
		fmt.Fprintf(out, "\nRecord: %s\nCopy it to the node and run:\n  otter-node import --config /etc/otter/node.toml %s\n", res.File, filepath.Base(res.File))
	default:
		return errors.New(usage)
	}
	return nil
}

func show(out io.Writer, dir string, rec *pb.Record) error {
	st, err := admin.LoadState(dir)
	if err != nil {
		return err
	}
	v := &records.Validator{NetworkPub: st.NetworkPub, Users: noUsers{}, Now: time.Now}
	body, err := v.Validate(rec)
	if err != nil {
		return fmt.Errorf("manifest does not verify: %w", err)
	}
	var m pb.Manifest
	if err := proto.Unmarshal(body.Payload, &m); err != nil {
		return err
	}
	b, _ := protojson.MarshalOptions{Multiline: true}.Marshal(&m)
	fmt.Fprintf(out, "signature OK\n%s\n", b)
	return nil
}

type noUsers struct{}

func (noUsers) UserKey([]byte) (records.UserKey, bool) { return records.UserKey{}, false }

func defaultDir() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".otter-admin")
}
