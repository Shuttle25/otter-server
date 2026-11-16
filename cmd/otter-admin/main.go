// Command otter-admin manages an OtterMSG network: keys, nodes and the signed manifest.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/records"
)

const usage = `usage: otter-admin [--dir DIR] <command>
  network init
  node add --label L --wss-host H [--ip A]... [--wss-port 27443] [--wss-path /p] [--cdn] [--push] [--plain]
  node list
  node remove --label L
  manifest sign [--sig-v1-until RFC3339]   (once, after every node and phone runs 0.10.0: publish time + 48h)
  manifest show [--file F]
  manifest publish [--via LABEL]... [--allow-plain]
  invite bootstrap [--ttl 168h]    (at most 720h)
  user list [--via LABEL] [--allow-plain]
  user revoke NAME|NAME#TAG|USER_ID [--reason TEXT] [--yes] [--via LABEL]... [--allow-plain]
  user invite-rights NAME|NAME#TAG|USER_ID --on|--off [--via LABEL]... [--allow-plain]
  user found USER_ID...            (then 'manifest sign' and 'manifest publish')
  node set-ip --label L --ip A [--ip B]...
  node rotate-tls --label L
  node drop-old-pins --label L
  node set-push --label L [--off]
  node set-dial-out-only --label L [--off]
  node add-reality --label L --host H --port 443 --pub B64URL --server-name S [--short-id HEX] [--uuid UUID]
  node add-wss --label L --host H [--port 443] [--cdn] [--priority 10]
  node remove-endpoint --label L --host H --port P
  node env --label L
  dns records
  dns check [--label L]
  news init
  news show
  news revoke --pub HEX
  announce [--ru FILE] [--en FILE] [--apk FILE --version-name V --version-code N] [--via LABEL]... [--allow-plain]
  announce --delete ID [--via LABEL]... [--allow-plain]
  announce --list
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
	if len(a) >= 1 && a[0] == "announce" {
		return announce(out, *dir, a[1:])
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
				extra := ""
				if e.Kind == pb.Endpoint_REALITY && len(e.ServerNames) > 0 {
					extra = " sni=" + e.ServerNames[0]
				}
				fmt.Fprintf(out, "%-12s %x  %s %s:%d%s cdn=%v pin=%s dial_out_only=%v%s\n", n.Label, n.NodeId, e.Kind, e.Host, e.Port, e.Path, e.ViaCdn, pin, n.DialOutOnly, extra)
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
	case "node set-push":
		fs := flag.NewFlagSet("node set-push", flag.ContinueOnError)
		label := fs.String("label", "", "node label")
		off := fs.Bool("off", false, "the node can no longer push")
		if err := fs.Parse(a[2:]); err != nil {
			return err
		}
		if err := admin.SetPush(*dir, *label, !*off); err != nil {
			return err
		}
		fmt.Fprintf(out, "node %s: push_capable=%v. Run 'manifest sign' and 'manifest publish'.\n", *label, !*off)
	case "node set-dial-out-only":
		fs := flag.NewFlagSet("node set-dial-out-only", flag.ContinueOnError)
		label := fs.String("label", "", "node label")
		off := fs.Bool("off", false, "the node may be dialed again")
		if err := fs.Parse(a[2:]); err != nil {
			return err
		}
		if err := admin.SetDialOutOnly(*dir, *label, !*off); err != nil {
			return err
		}
		fmt.Fprintf(out, "node %s: dial_out_only=%v. Run 'manifest sign' and 'manifest publish'.\n", *label, !*off)
	case "node add-reality":
		fs := flag.NewFlagSet("node add-reality", flag.ContinueOnError)
		var s admin.RealitySpec
		var port uint
		fs.StringVar(&s.Label, "label", "", "node label")
		fs.StringVar(&s.Host, "host", "", "public IP or name of the node")
		fs.UintVar(&port, "port", 443, "REALITY port")
		fs.StringVar(&s.Pub, "pub", "", "X25519 public key (otter-node reality keygen)")
		fs.StringVar(&s.ServerName, "server-name", "", "camouflage site name, e.g. dl.google.com")
		fs.StringVar(&s.ShortID, "short-id", "", "REALITY short id (hex; random if empty)")
		fs.StringVar(&s.UUID, "uuid", "", "VLESS UUID used in the node's [reality] (random if empty)")
		if err := fs.Parse(a[2:]); err != nil {
			return err
		}
		s.Port = uint32(port)
		ep, err := admin.AddReality(*dir, s)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "node %s: REALITY %s:%d server_name=%s\n[reality] for its node.toml:\n  vless_uuid = %q\n  short_ids = [%q]\n  server_names = [%q]\nRun 'manifest sign' and 'manifest publish'.\n",
			s.Label, ep.Host, ep.Port, s.ServerName, ep.VlessUuid, ep.ShortIds[0], s.ServerName)
	case "node add-wss":
		fs := flag.NewFlagSet("node add-wss", flag.ContinueOnError)
		var s admin.WSSSpec
		var port, prio uint
		fs.StringVar(&s.Label, "label", "", "node label")
		fs.StringVar(&s.Host, "host", "", "name clients dial (the CDN-proxied name with --cdn)")
		fs.UintVar(&port, "port", 443, "port clients dial")
		fs.BoolVar(&s.CDN, "cdn", false, "behind a CDN: no pins, CA-checked certificate (D131)")
		fs.UintVar(&prio, "priority", 10, "higher = tried later; the node's own endpoint has 0")
		if err := fs.Parse(a[2:]); err != nil {
			return err
		}
		if port > 65535 || prio > 1000 {
			return errors.New("--port must be 1-65535 and --priority 0-1000")
		}
		s.Port, s.Priority = uint32(port), uint32(prio)
		ep, err := admin.AddWSS(*dir, s)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "node %s: WSS %s:%d cdn=%v priority=%d pins=%d\nRun 'manifest sign' and 'manifest publish'.\n",
			s.Label, ep.Host, ep.Port, ep.ViaCdn, ep.Priority, len(ep.TlsSpkiPins))
	case "node remove-endpoint":
		fs := flag.NewFlagSet("node remove-endpoint", flag.ContinueOnError)
		label := fs.String("label", "", "node label")
		host := fs.String("host", "", "endpoint host")
		port := fs.Uint("port", 0, "endpoint port")
		if err := fs.Parse(a[2:]); err != nil {
			return err
		}
		if *port == 0 || *port > 65535 {
			return errors.New("--port must be 1-65535")
		}
		if err := admin.RemoveEndpoint(*dir, *label, *host, uint32(*port)); err != nil {
			return err
		}
		fmt.Fprintf(out, "node %s: endpoint %s:%d removed. Run 'manifest sign' and 'manifest publish'.\n", *label, *host, *port)
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
	case "news init":
		pub, err := admin.NewsInit(*dir)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "news key %x\nRun 'manifest sign' and 'manifest publish' so nodes and phones accept it.\n", pub)
	case "news show":
		ks, err := admin.LoadNewsKeys(*dir)
		if err != nil {
			return err
		}
		local := admin.LocalNewsKey(*dir)
		if len(ks) == 0 {
			fmt.Fprintln(out, "no news keys (run 'news init')")
		}
		for _, k := range ks {
			mark := ""
			if local != nil && string(k) == string(local) {
				mark = " (this keyring)"
			}
			fmt.Fprintf(out, "%x%s\n", k, mark)
		}
	case "news revoke":
		fs := flag.NewFlagSet("news revoke", flag.ContinueOnError)
		pub := fs.String("pub", "", "public key (hex) from 'news show'")
		if err := fs.Parse(a[2:]); err != nil {
			return err
		}
		if *pub == "" {
			return errors.New("news revoke: --pub HEX")
		}
		if err := admin.NewsRevoke(*dir, *pub); err != nil {
			return err
		}
		fmt.Fprintf(out, "news key %s removed. Run 'manifest sign' and 'manifest publish': nodes and phones then drop everything it signed.\n", strings.ToLower(*pub))
	case "manifest sign":
		fs := flag.NewFlagSet("manifest sign", flag.ContinueOnError)
		cut := fs.String("sig-v1-until", "", "RFC 3339 time: v1 record signatures stop being valid for records created after it (D110, once)")
		if err := fs.Parse(a[2:]); err != nil {
			return err
		}
		var cutAt time.Time
		if *cut != "" {
			t, err := time.Parse(time.RFC3339, *cut)
			if err != nil {
				return fmt.Errorf("--sig-v1-until: %w", err)
			}
			if !t.After(time.Now()) {
				return errors.New("--sig-v1-until must be in the future (publish time + 48h): queued v1 messages need it")
			}
			cutAt = t
		}
		p, err := passphrase(in, false)
		if err != nil {
			return err
		}
		if !cutAt.IsZero() {
			// check the passphrase before the one-time cut-over is stored
			if _, err := keys.ReadEncryptedKey(filepath.Join(*dir, "network.key.enc"), p); err != nil {
				return err
			}
			if err := admin.SetSigV1Until(*dir, cutAt.UnixMilli()); err != nil {
				return err
			}
			fmt.Fprintf(out, "v1 signatures end at %s; this and every later manifest, invite, network record and announcement is signed v2.\n",
				cutAt.UTC().Format(time.RFC3339))
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
		ttl := fs.Duration("ttl", 7*24*time.Hour, "invite validity (at most 720h)")
		if err := fs.Parse(a[2:]); err != nil {
			return err
		}
		if *ttl <= 0 || *ttl > records.MaxInviteTTL { // checked before the passphrase is asked (C8)
			return fmt.Errorf("--ttl must be between 1s and %s", records.MaxInviteTTL)
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
		fmt.Fprintf(out, "\nRecord: %s\nThe link carries it; optionally copy it to a node and run:\n  otter-node import --config /etc/otter/node.toml %s\n", res.File, filepath.Base(res.File))
	case "user list", "user revoke", "user invite-rights":
		return userCmd(out, in, *dir, a[1], a[2:])
	case "user found":
		var ids [][]byte
		for _, h := range a[2:] {
			id, err := hex.DecodeString(h)
			if err != nil || len(id) != 16 {
				return fmt.Errorf("user found: %q is not a 32-hex user id", h)
			}
			ids = append(ids, id)
		}
		if len(ids) == 0 {
			return errors.New("user found USER_ID...")
		}
		if err := admin.AddFounding(*dir, ids); err != nil {
			return err
		}
		fmt.Fprintln(out, "Stored. Run 'manifest sign' and 'manifest publish' so every node and phone accepts these accounts without an invite.")
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
	v := &records.Validator{NetworkPub: st.NetworkPub, Users: noUsers{}, Now: time.Now,
		V1Until: func() int64 { return admin.SigV1Until(dir) }}
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
	if m.SigV1UntilMs != 0 {
		fmt.Fprintf(out, "sig_v1_until: %s (records created after it need a v2 signature)\n",
			time.UnixMilli(m.SigV1UntilMs).UTC().Format(time.RFC3339))
	}
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
		res := publishTo(n, "manifest.publish", &rec, allowPlain)
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

func publishTo(n *pb.NodeInfo, method string, rec *pb.Record, allowPlain bool) string {
	lastErr := "error: no usable endpoint"
	for _, ep := range n.Endpoints {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		c, err := client.Dial(ctx, ep, allowPlain)
		if err != nil {
			cancel()
			lastErr = "error: " + err.Error()
			continue
		}
		err = c.Call(ctx, method, &pb.RecordRequest{Record: rec}, nil)
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

// manifestNodes returns the nodes of the current manifest.bin, only those named by via if any (each must exist).
func manifestNodes(dir string, via []string) ([]*pb.NodeInfo, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.bin"))
	if err != nil {
		return nil, fmt.Errorf("no signed manifest (run 'manifest sign' first): %w", err)
	}
	var mrec pb.Record
	var body pb.RecordBody
	var m pb.Manifest
	if proto.Unmarshal(raw, &mrec) != nil || proto.Unmarshal(mrec.Body, &body) != nil || proto.Unmarshal(body.Payload, &m) != nil {
		return nil, errors.New("manifest.bin is corrupt")
	}
	selected := map[string]bool{}
	for _, l := range via {
		selected[l] = true
	}
	var out []*pb.NodeInfo
	for _, n := range m.Nodes {
		if len(selected) > 0 && !selected[n.Label] {
			continue
		}
		delete(selected, n.Label)
		out = append(out, n)
	}
	for l := range selected {
		return nil, fmt.Errorf("%s: not in the manifest", l)
	}
	return out, nil
}

// publishNews sends rec to every selected node of the current manifest.bin with news.publish (idempotent);
// succeeds if at least one node accepted it.
func publishNews(out io.Writer, dir string, rec *pb.Record, via []string, allowPlain bool) error {
	nodes, err := manifestNodes(dir, via)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return fmt.Errorf("not published to any node: %w", err)
	}
	return publishAll(out, nodes, "news.publish", rec, allowPlain)
}

// publishAll sends rec with method to every node; succeeds if at least one accepted it.
func publishAll(out io.Writer, nodes []*pb.NodeInfo, method string, rec *pb.Record, allowPlain bool) error {
	good := 0
	for _, n := range nodes {
		res := publishTo(n, method, rec, allowPlain)
		if res == "ok" {
			good++
		}
		fmt.Fprintf(out, "%-12s %s\n", n.Label, res)
	}
	if good == 0 {
		return errors.New("not published to any node")
	}
	return nil
}

// userCmd fetches the member list from one node (signed request, verified here), then lists, revokes or sets rights.
func userCmd(out io.Writer, in io.Reader, dir, sub string, args []string) error {
	fs := flag.NewFlagSet("user "+sub, flag.ContinueOnError)
	var via multi
	fs.Var(&via, "via", "node label (repeatable; list asks the first that answers)")
	allowPlain := fs.Bool("allow-plain", false, "allow plain ws:// endpoints (development only)")
	reason := fs.String("reason", "", "revocation reason (seen by the admin only)")
	yes := fs.Bool("yes", false, "do not ask")
	on := fs.Bool("on", false, "allow inviting")
	off := fs.Bool("off", false, "withdraw the right to invite")
	who := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		who, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("user %s: unexpected %q", sub, fs.Arg(0))
	}
	switch {
	case sub == "list" && who != "":
		return fmt.Errorf("user list: unexpected %q", who)
	case sub != "list" && who == "":
		return fmt.Errorf("user %s: NAME, NAME#TAG or USER_ID", sub)
	case sub == "invite-rights" && *on == *off:
		return errors.New("user invite-rights: exactly one of --on, --off")
	}
	st, err := admin.LoadState(dir)
	if err != nil {
		return err
	}
	nodes, err := manifestNodes(dir, via)
	if err != nil {
		return err
	}
	founding, err := admin.LoadFounding(dir)
	if err != nil {
		return err
	}
	// one buffered reader for the passphrase and the confirmation; a terminal keeps its no-echo passphrase prompt
	br := bufio.NewReader(orEmpty(in))
	pin := io.Reader(br)
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		pin = f
	}
	p, err := passphrase(pin, false)
	if err != nil {
		return err
	}
	priv, err := keys.ReadEncryptedKey(filepath.Join(dir, "network.key.enc"), p)
	if err != nil {
		return err
	}
	var ms []admin.Member
	lastErr := errors.New("no node selected")
	for _, n := range nodes {
		if ms, lastErr = fetchMembers(n, priv, st.NetworkPub, founding, admin.SigV1Until(dir), allowPlain); lastErr == nil {
			break
		}
	}
	if lastErr != nil {
		return lastErr
	}
	if sub == "list" {
		for _, m := range ms {
			state := "active"
			if m.Revoked {
				state = "revoked: " + m.Reason
			}
			if !m.Admitted {
				state += " (not admitted: no invite chain; 'user found' if it predates 0.9.3)"
			}
			fmt.Fprintf(out, "%-24s %x  invite=%-5v founding=%-5v v%d  %s  «%s»\n", m.Tag(), m.UserID, m.CanInvite, m.Founding,
				m.RightsVersion, state, m.Display)
		}
		return nil
	}
	m, err := admin.Find(ms, who)
	if err != nil {
		return err
	}
	var rec *pb.Record
	switch sub {
	case "revoke":
		if !*yes && !confirm(br, fmt.Sprintf("Revoke %s «%s» (%x)? This cannot be undone. [y/N] ", m.Tag(), m.Display, m.UserID)) {
			return errors.New("cancelled")
		}
		rec, err = admin.SignRevocation(dir, priv, m.UserID, *reason, time.Now())
	case "invite-rights":
		v := max(m.RightsVersion, admin.SavedRightsVersion(dir, m.UserID)) + 1
		rec, err = admin.SignInviteRights(dir, priv, m.UserID, *on, v, time.Now())
		if err == nil {
			fmt.Fprintf(out, "%s: invite=%v (version %d)\n", m.Tag(), *on, v)
		}
	}
	if err != nil {
		return err
	}
	if err := publishAll(out, nodes, "network.publish", rec, *allowPlain); err != nil {
		return fmt.Errorf("%w (the record is saved in %s; retry later)", err, dir)
	}
	return nil
}

func fetchMembers(n *pb.NodeInfo, priv ed25519.PrivateKey, netPub ed25519.PublicKey, founding [][]byte, v1Until int64, allowPlain *bool) ([]admin.Member, error) {
	var lastErr error = errors.New("no usable endpoint")
	for _, ep := range n.Endpoints {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		c, err := client.Dial(ctx, ep, *allowPlain)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		ts := time.Now().UnixMilli()
		var batch pb.RecordBatch
		err = c.Call(ctx, "admin.users", &pb.AdminRequest{TsMs: ts,
			Signature: ed25519.Sign(priv, keys.AdminAuthMessage(c.Hello().NodeId, c.Hello().Nonce, ts))}, &batch)
		c.Close()
		cancel()
		if err == nil {
			return admin.Members(batch.Records, netPub, founding, v1Until), nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("%s: %w", n.Label, lastErr)
}

func confirm(in *bufio.Reader, prompt string) bool {
	fmt.Fprint(os.Stderr, prompt)
	line, _ := in.ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "y")
}

func orEmpty(in io.Reader) io.Reader {
	if in == nil {
		return strings.NewReader("")
	}
	return in
}

func announce(out io.Writer, dir string, args []string) error {
	fs := flag.NewFlagSet("announce", flag.ContinueOnError)
	ru := fs.String("ru", "", "file with the Russian text")
	en := fs.String("en", "", "file with the English text")
	apkFile := fs.String("apk", "", "APK already copied to the nodes (release-apk.sh)")
	vName := fs.String("version-name", "", "versionName of the APK")
	vCode := fs.Uint("version-code", 0, "versionCode of the APK")
	del := fs.String("delete", "", "delete the announcement with this id prefix")
	list := fs.Bool("list", false, "list sent announcements")
	allowPlain := fs.Bool("allow-plain", false, "allow plain ws:// endpoints (development only)")
	var via multi
	fs.Var(&via, "via", "node label (repeatable; default: every node)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("announce: unexpected %q\n%s", fs.Arg(0), usage)
	}
	switch {
	case *list:
		sent, err := admin.ListAnnouncements(dir)
		if err != nil {
			return err
		}
		for _, s := range sent {
			text := s.A.TextRu
			if text == "" {
				text = s.A.TextEn
			}
			text = strings.Join(strings.Fields(text), " ")
			if r := []rune(text); len(r) > 60 {
				text = string(r[:60]) + "…"
			}
			extra := ""
			if s.A.Update != nil {
				extra += " [APK " + s.A.Update.VersionName + "]"
			}
			if s.Deleted {
				extra += " [deleted]"
			}
			fmt.Fprintf(out, "%s  %s  %s%s\n", time.UnixMilli(s.CreatedMs).Format("2006-01-02 15:04"), s.ID[:12], text, extra)
		}
		return nil
	case *del != "":
		rec, err := admin.SignAnnouncementDeleted(dir, *del, time.Now())
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "deletion of %s\n", *del)
		return publishSent(out, dir, rec, via, *allowPlain)
	}
	a := &pb.Announcement{}
	for _, x := range []struct {
		path string
		dst  *string
	}{{*ru, &a.TextRu}, {*en, &a.TextEn}} {
		if x.path == "" {
			continue
		}
		b, err := os.ReadFile(x.path)
		if err != nil {
			return err
		}
		*x.dst = strings.TrimSpace(string(b))
	}
	if *apkFile != "" {
		if *vName == "" || *vCode == 0 || *vCode > 1<<31-1 {
			return errors.New("--apk needs --version-name and --version-code")
		}
		b, err := os.ReadFile(*apkFile)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		a.Update = &pb.AppUpdate{VersionName: *vName, VersionCode: uint32(*vCode), Sha256: sum[:], Size: uint64(len(b))}
	}
	if a.TextRu == "" && a.TextEn == "" {
		return errors.New("announce: --ru and/or --en with text")
	}
	rec, err := admin.SignAnnouncement(dir, a, time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "announcement %s\n", admin.NewsID(rec)[:12])
	return publishSent(out, dir, rec, via, *allowPlain)
}

// publishSent publishes a just-signed news record; if no node took it, the saved copy is removed so
// 'announce --list' shows only what was sent.
func publishSent(out io.Writer, dir string, rec *pb.Record, via []string, allowPlain bool) error {
	err := publishNews(out, dir, rec, via, allowPlain)
	if err != nil {
		if ferr := admin.ForgetSent(dir, rec); ferr != nil {
			fmt.Fprintln(out, "warning:", ferr)
		}
	}
	return err
}
