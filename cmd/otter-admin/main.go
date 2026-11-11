// Command otter-admin manages an OtterMSG network: keys, nodes and the signed manifest.
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mdp/qrterminal/v3"
	"golang.org/x/term"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/admin"
	"ottermsg/server/internal/client"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

const usage = `usage: otter-admin [--dir DIR] <command>
  network init
  node add --label L --wss-host H [--ip A]... [--wss-port 27443] [--wss-path /p] [--cdn] [--push] [--plain]
  node list
  node remove --label L
  manifest sign
  manifest show [--file F]
  manifest publish [--via LABEL]... [--allow-plain]
  invite bootstrap [--ttl 168h]
  node set-ip --label L --ip A [--ip B]...
  node rotate-tls --label L
  node drop-old-pins --label L
  node env --label L
  dns records
  dns check [--label L]
  version`

var version = "dev"

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
	if len(a) == 1 && a[0] == "version" {
		fmt.Fprintln(out, version)
		return nil
	}
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
		fs.UintVar(&port, "wss-port", admin.DefaultPort, "WSS port")
		fs.Var((*multi)(&s.IPs), "ip", "additional IP address in the certificate (repeatable)")
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
				pin := "-"
				if len(e.TlsSpkiPins) > 0 {
					pin = base64.StdEncoding.EncodeToString(e.TlsSpkiPins[0])
				}
				fmt.Fprintf(out, "%-12s %x  %s %s:%d%s cdn=%v pin=%s\n", n.Label, n.NodeId, e.Kind, e.Host, e.Port, e.Path, e.ViaCdn, pin)
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
	case "node set-ip":
		fs := flag.NewFlagSet("node set-ip", flag.ContinueOnError)
		label := fs.String("label", "", "node label")
		var ips multi
		fs.Var(&ips, "ip", "IP address (repeatable)")
		if err := fs.Parse(a[2:]); err != nil {
			return err
		}
		if len(ips) == 0 {
			return errors.New("node set-ip: at least one --ip")
		}
		if err := admin.SetIPs(*dir, *label, ips); err != nil {
			return err
		}
		recs, _ := admin.DNSRecords(*dir)
		fmt.Fprintf(out, "node %s: IPs %v recorded, certificate re-issued (pin unchanged).\nUpdate DNS:\n%s", *label, []string(ips), recs)
	case "node rotate-tls", "node drop-old-pins":
		fs := flag.NewFlagSet(a[0]+" "+a[1], flag.ContinueOnError)
		label := fs.String("label", "", "node label")
		if err := fs.Parse(a[2:]); err != nil {
			return err
		}
		if a[1] == "rotate-tls" {
			pin, err := admin.RotateTLS(*dir, *label)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "node %s: new certificate staged, pin %s added.\nRun 'manifest sign' and 'manifest publish', wait for apps to update, deploy (push.sh), then 'node drop-old-pins'.\n",
				*label, base64.StdEncoding.EncodeToString(pin))
		} else {
			if err := admin.DropOldPins(*dir, *label); err != nil {
				return err
			}
			fmt.Fprintf(out, "node %s: only the new pin remains. Run 'manifest sign' and 'manifest publish'.\n", *label)
		}
	case "node env":
		fs := flag.NewFlagSet("node env", flag.ContinueOnError)
		label := fs.String("label", "", "node label")
		if err := fs.Parse(a[2:]); err != nil {
			return err
		}
		env, err := admin.NodeEnv(*dir, *label)
		if err != nil {
			return err
		}
		keys := make([]string, 0, len(env))
		for k := range env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(out, "%s=%s\n", k, admin.ShellQuote(env[k]))
		}
	case "dns records":
		s, err := admin.DNSRecords(*dir)
		if err != nil {
			return err
		}
		fmt.Fprint(out, s)
	case "dns check":
		fs := flag.NewFlagSet("dns check", flag.ContinueOnError)
		label := fs.String("label", "", "only this node")
		if err := fs.Parse(a[2:]); err != nil {
			return err
		}
		res, err := admin.CheckDNS(context.Background(), *dir, *label, net.DefaultResolver)
		if err != nil {
			return err
		}
		bad := false
		for _, r := range res {
			switch {
			case r.Skipped:
				fmt.Fprintf(out, "%-12s %s skip (IP endpoint)\n", r.Label, r.Host)
			case r.Err != "":
				bad = true
				fmt.Fprintf(out, "%-12s %s ERROR %s\n", r.Label, r.Host, r.Err)
			case r.OK:
				fmt.Fprintf(out, "%-12s %s ok\n", r.Label, r.Host)
			default:
				bad = true
				fmt.Fprintf(out, "%-12s %s MISSING %v UNEXPECTED %v\n", r.Label, r.Host, r.Missing, r.Unexpected)
			}
		}
		if bad {
			return errors.New("DNS does not match (records may still be propagating; TTL 300)")
		}
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
	case "manifest publish":
		fs := flag.NewFlagSet("manifest publish", flag.ContinueOnError)
		var via multi
		fs.Var(&via, "via", "node label to publish through (repeatable; default: every node in the manifest)")
		allowPlain := fs.Bool("allow-plain", false, "allow plain ws:// endpoints (development only)")
		if err := fs.Parse(a[2:]); err != nil {
			return err
		}
		return publishManifest(out, *dir, via, *allowPlain)
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

// multi is a repeatable string flag.
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// publishManifest sends manifest.bin to the selected nodes; succeeds if at least one node took it or already had it.
func publishManifest(out io.Writer, dir string, via []string, allowPlain bool) error {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.bin"))
	if err != nil {
		return fmt.Errorf("no signed manifest (run 'manifest sign' first): %w", err)
	}
	var rec pb.Record
	if err := proto.Unmarshal(raw, &rec); err != nil {
		return err
	}
	var body pb.RecordBody
	var m pb.Manifest
	if err := proto.Unmarshal(rec.Body, &body); err != nil {
		return err
	}
	if err := proto.Unmarshal(body.Payload, &m); err != nil {
		return err
	}
	selected := map[string]bool{}
	for _, l := range via {
		selected[l] = true
	}
	good := 0
	for _, n := range m.Nodes {
		if len(selected) > 0 && !selected[n.Label] {
			continue
		}
		delete(selected, n.Label)
		res := publishTo(n, &rec, allowPlain)
		if res == "ok" || res == "already current" {
			good++
		}
		fmt.Fprintf(out, "%-12s %s\n", n.Label, res)
	}
	for l := range selected {
		fmt.Fprintf(out, "%-12s error: not in the manifest\n", l)
	}
	if good == 0 {
		return errors.New("the manifest was not published to any node")
	}
	return nil
}

func publishTo(n *pb.NodeInfo, rec *pb.Record, allowPlain bool) string {
	lastErr := "error: no usable endpoint"
	for _, ep := range n.Endpoints {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		c, err := client.Dial(ctx, ep, allowPlain)
		if err != nil {
			cancel()
			lastErr = "error: " + err.Error()
			continue
		}
		err = c.Call(ctx, "manifest.publish", &pb.RecordRequest{Record: rec}, nil)
		c.Close()
		cancel()
		var se *client.StatusError
		switch {
		case err == nil:
			return "ok"
		case errors.As(err, &se) && se.Status == pb.Status_STATUS_CONFLICT:
			return "already current"
		default:
			lastErr = "error: " + err.Error()
		}
	}
	return lastErr
}
