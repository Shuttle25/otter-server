// Command otter-node runs an OtterMSG relay node.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"
	"ottermsg/server/internal/apk"
	"ottermsg/server/internal/blobs"
	"ottermsg/server/internal/config"
	"ottermsg/server/internal/gateway"
	"ottermsg/server/internal/keys"
	"ottermsg/server/internal/netlog"
	"ottermsg/server/internal/nodecheck"
	"ottermsg/server/internal/probe"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/push"
	"ottermsg/server/internal/reality"
	"ottermsg/server/internal/replication"
	"ottermsg/server/internal/service"
	"ottermsg/server/internal/store"
	"ottermsg/server/internal/transport/wss"
	"ottermsg/server/internal/turnsrv"
)

var version = "dev"

// geteuid and stdin are variables so tests can play root and feed stdin.
var (
	geteuid           = os.Geteuid
	stdin   io.Reader = os.Stdin
)

const usage = `usage: otter-node <command>
  run --config FILE            serve clients
  import --config FILE FILE...|-   apply signed record files (manifest, bootstrap invite); - = stdin
  check --config FILE          verify config, keys, manifest and TLS before starting
  backup --config FILE --out F consistent database copy (safe while running)
  stats --config FILE          database counts (safe while running)
  apk import --config FILE APK...|-   store app update files served by apk.get (keeps the newest 2); - = stdin; never as root
  reality keygen --config FILE write the REALITY private key file (once) and print the public key
  turn keygen --config FILE [--force]  write the TURN secret file (once; never printed)
  reality-check HOST...        test camouflage candidates from this machine (TLS 1.3, h2, valid certificate)
  netlog --config FILE [--limit 50] [--json]   connectivity log (safe while running)
  probe --url URL --pin B64 [--pin B64]... [--addr HOST:PORT] [--insecure] [--expect-node HEX] [--timeout 10s]
  version`

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type app struct {
	cfg   *config.Config
	st    *store.Store
	svc   *service.Service
	log   *slog.Logger
	close func()
}

func open(cfgPath string, out io.Writer) (*app, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	var lvl slog.Level
	_ = lvl.UnmarshalText([]byte(cfg.LogLevel))
	log := slog.New(slog.NewJSONHandler(out, &slog.HandlerOptions{Level: lvl}))
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	nodeKey, err := keys.ReadPlainKey(cfg.NodeKey)
	if err != nil {
		return nil, err
	}
	netPub, _ := cfg.NetworkPubKey()
	st, err := store.Open(filepath.Join(cfg.DataDir, "node.db"))
	if err != nil {
		return nil, err
	}
	svc := service.New(st, nodeKey, netPub)
	bd, err := blobs.New(filepath.Join(cfg.DataDir, "blobs"))
	if err != nil {
		st.Close()
		return nil, err
	}
	svc.Blobs = bd
	apks, err := apk.New(filepath.Join(cfg.DataDir, "apk"))
	if err != nil {
		st.Close()
		return nil, err
	}
	svc.Apks = apks
	svc.Limits = service.Limits{UserQuota: cfg.UserQuotaBytes, MaxBlob: cfg.MaxBlobBytes}
	return &app{cfg: cfg, st: st, svc: svc, log: log, close: func() { st.Close() }}, nil
}

func importFile(ctx context.Context, svc *service.Service, path string) (bool, error) {
	var raw []byte
	var err error
	if path == "-" { // deploy hands a root-held file to the otter user as an open descriptor (D82)
		raw, err = io.ReadAll(stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return false, err
	}
	var rec pb.Record
	if err := proto.Unmarshal(raw, &rec); err != nil {
		return false, fmt.Errorf("%s: not a record: %w", path, err)
	}
	return svc.ImportRecord(ctx, &rec)
}

// importApks stores APK files in <data_dir>/apk (D68). It does not open the database, so it runs while the node
// runs. Never as root (C3, D82): deploy runs `runuser -u otter -- otter-node apk import --config F - < file`.
func importApks(cfgPath string, files []string, out io.Writer) error {
	if len(files) == 0 {
		return errors.New("usage: otter-node apk import --config FILE APK...|-")
	}
	if geteuid() == 0 {
		return errors.New("apk import: run it as the node user (runuser -u otter -- otter-node apk import ...), never as root")
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	d, err := apk.New(filepath.Join(cfg.DataDir, "apk"))
	if err != nil {
		return err
	}
	for _, f := range files {
		var sum []byte
		if f == "-" {
			sum, err = d.ImportReader(stdin)
		} else {
			sum, err = d.Import(f)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		fmt.Fprintf(out, "%s: stored %x\n", f, sum)
	}
	return nil
}

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	cmd := args[0]
	if cmd == "version" {
		fmt.Fprintln(out, version)
		return nil
	}
	if cmd == "probe" {
		return runProbe(ctx, args[1:], out)
	}
	if cmd == "reality-check" {
		return runRealityCheck(ctx, args[1:], out)
	}
	rest := args[1:]
	if cmd == "reality" {
		if len(rest) == 0 || rest[0] != "keygen" {
			return errors.New("usage: otter-node reality keygen --config FILE")
		}
		rest = rest[1:]
	}
	if cmd == "turn" {
		if len(rest) == 0 || rest[0] != "keygen" {
			return errors.New("usage: otter-node turn keygen --config FILE [--force]")
		}
		rest = rest[1:]
	}
	if cmd == "apk" {
		if len(rest) == 0 || rest[0] != "import" {
			return errors.New("usage: otter-node apk import --config FILE APK...|-")
		}
		rest = rest[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/otter/node.toml", "config file")
	outPath := fs.String("out", "", "backup file (backup)")
	limit := fs.Int("limit", 50, "lines (netlog)")
	asJSON := fs.Bool("json", false, "JSON output (netlog)")
	force := fs.Bool("force", false, "replace an existing secret (turn keygen)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if cmd == "apk" {
		return importApks(*cfgPath, fs.Args(), out)
	}
	if cmd == "check" { // must not touch the database
		lines, err := nodecheck.Run(*cfgPath)
		for _, l := range lines {
			fmt.Fprintln(out, l)
		}
		return err
	}
	if cmd == "reality" { // must not touch the database
		return realityKeygen(*cfgPath, out)
	}
	if cmd == "turn" { // must not touch the database
		return turnKeygen(*cfgPath, *force, out)
	}
	if cmd != "run" && cmd != "import" && cmd != "backup" && cmd != "stats" && cmd != "netlog" {
		return errors.New(usage)
	}
	if cmd == "backup" && *outPath == "" {
		return errors.New("backup: --out is required")
	}
	a, err := open(*cfgPath, out)
	if err != nil {
		return err
	}
	defer a.close()

	switch cmd {
	case "import":
		if fs.NArg() == 0 {
			return errors.New("import: no files")
		}
		for _, f := range fs.Args() {
			applied, err := importFile(ctx, a.svc, f)
			if err != nil {
				return fmt.Errorf("%s: %w", f, err)
			}
			state := "already present"
			if applied {
				state = "applied"
			}
			fmt.Fprintf(out, "%s: %s\n", f, state)
		}
		return nil
	case "backup":
		if err := a.st.Backup(ctx, *outPath); err != nil {
			return err
		}
		fmt.Fprintf(out, "backup written to %s\n", *outPath)
		return nil
	case "stats":
		st, err := a.st.Stats(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "users=%d records=%d oplog_seq=%d blobs=%d blob_bytes=%d peers=%d",
			st.Users, st.Records, st.OplogSeq, st.Blobs, st.BlobBytes, st.Peers)
		if ts, ok := turnsrv.ReadSnapshot(turnStatsPath(a.cfg), time.Now(), time.Minute); ok {
			fmt.Fprintf(out, " turn_allocs=%d turn_relayed_bytes=%d", ts.Allocations, ts.Relayed)
		}
		fmt.Fprintln(out)
		return nil
	case "netlog":
		return printNetlog(ctx, a.st, *limit, *asJSON, out)
	case "run":
		return serve(ctx, a)
	default:
		return errors.New(usage)
	}
}

func serve(ctx context.Context, a *app) error {
	if a.cfg.ManifestFile != "" {
		if _, err := importFile(ctx, a.svc, a.cfg.ManifestFile); err != nil {
			return fmt.Errorf("manifest_file: %w", err)
		}
	}
	if rec, v, err := a.svc.Manifest(ctx); err != nil {
		a.log.Warn("no manifest imported; clients cannot verify this network yet")
	} else {
		var body pb.RecordBody
		var m pb.Manifest
		_ = proto.Unmarshal(rec.Body, &body)
		_ = proto.Unmarshal(body.Payload, &m)
		found := false
		for _, n := range m.Nodes {
			found = found || bytes.Equal(n.NodeId, a.svc.NodeID)
		}
		if !found {
			a.log.Warn("this node is not listed in the manifest", "manifest_version", v, "node_id", fmt.Sprintf("%x", a.svc.NodeID))
		}
	}
	a.svc.Log = a.log
	if _, err := a.svc.LoadManifest(ctx); err != nil {
		return fmt.Errorf("load manifest: %w", err)
	}
	a.svc.LoadRevoked(ctx) // TURN refuses revoked accounts from the first request (C2)
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	gw := gateway.New(a.svc, a.log)
	if a.cfg.PushEnabled() {
		raw, err := os.ReadFile(a.cfg.Push.FCMCredentials)
		if err != nil {
			return fmt.Errorf("push key: %w", err)
		}
		fcm, err := push.NewFCM(raw)
		if err != nil {
			return err
		}
		a.svc.Waker = push.New(fcm, a.st, a.log)
		a.log.Info("push on", "project", fcm.ProjectID())
	} else {
		a.log.Info("push off (no fcm_credentials file)")
		if service.Capable(a.svc.CurrentManifest(), a.svc.NodeID) {
			a.log.Warn("manifest says push_capable but no FCM key is installed")
		}
	}
	reality.SetLogger(a.log)
	rc := reality.NewClient() // dials peers' REALITY endpoints in-process (D72)
	defer rc.Close()
	rank, nl := replication.NewRanker(time.Now), netlog.StoreLogger{S: a.st}
	dialer := &replication.MultiDialer{EP: replication.NetDialer{AllowPlain: a.cfg.Mesh.AllowPlain, Reality: rc}, Rank: rank, Log: nl}
	repl := replication.New(a.svc, dialer, a.log, replication.WithNetlog(nl, rank))
	go repl.Run(ctx)     // before serving, so accepted peer sessions use the run context
	a.svc.Fetcher = repl // readers asking for a chunk this node lacks are served from a peer (D45)
	go repl.RunPuller(ctx, a.cfg.BlobBytesPerSec)
	go repl.RunBackupHandoff(ctx) // D113: only acts while this node is marked no_backups
	go a.svc.RunJanitor(ctx, 10*time.Minute)
	// before serving: sessions read svc.Turn without a lock
	if a.cfg.TurnEnabled() {
		if ts, iss, err := startTurn(a); err != nil {
			a.log.Error("turn off: could not start", "err", err)
			nl.Add(ctx, netlog.Entry{Peer: "turn", Endpoint: "turn", Direction: "in",
				Result: netlog.Result(netlog.Listen), Class: netlog.Listen, Detail: err.Error()})
		} else {
			defer ts.Close()
			a.svc.Turn = iss
		}
	}
	wcfg := wss.Config{Listen: a.cfg.WSS.Listen, Path: a.cfg.WSS.Path, TLSCert: a.cfg.WSS.TLSCert, TLSKey: a.cfg.WSS.TLSKey, SiteDir: a.cfg.WSS.SiteDir}
	srv := wss.NewServer(wcfg, gw, replication.WithListener(repl, "wss"), http.HandlerFunc(repl.ServeTunnel))
	errc := make(chan error, 2)
	go func() { errc <- wss.Serve(srv, wcfg) }()
	if a.cfg.WSS.TLSCert != "" { // D114: restore streams relayed by a node marked no_backups end here, under our WSS certificate
		cert, err := tls.LoadX509KeyPair(a.cfg.WSS.TLSCert, a.cfg.WSS.TLSKey)
		if err != nil {
			srv.Close()
			return fmt.Errorf("tunnel tls: %w", err)
		}
		tsrv := wss.NewServer(wss.Config{Path: a.cfg.WSS.Path}, gw, nil, nil)
		tsrv.ErrorLog = log.New(io.Discard, "", 0) // handshake errors of abandoned restores
		go tsrv.Serve(tls.NewListener(repl.TunnelListener(), &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}))
		defer tsrv.Close()
	}
	if a.cfg.RealityEnabled() {
		stopReality, err := startReality(a, gw, repl, errc)
		if err != nil {
			srv.Close()
			return err
		}
		defer stopReality()
	}
	a.log.Info("otter-node started", "listen", a.cfg.WSS.Listen, "node_id", fmt.Sprintf("%x", a.svc.NodeID), "version", version)
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	}
}

// startTurn runs the embedded relay (D77). A failure leaves the node running without calls.
func startTurn(a *app) (*turnsrv.Server, turnsrv.Issuer, error) {
	t := a.cfg.Turn
	secret, err := turnsrv.ReadSecret(t.SecretFile)
	if err != nil {
		return nil, turnsrv.Issuer{}, fmt.Errorf("turn secret: %w", err)
	}
	var tc *tls.Config
	if t.TLSListen != "" {
		cert, err := tls.LoadX509KeyPair(a.cfg.WSS.TLSCert, a.cfg.WSS.TLSKey)
		if err != nil {
			return nil, turnsrv.Issuer{}, fmt.Errorf("turn tls: %w", err)
		}
		tc = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	}
	srv, err := turnsrv.Start(turnsrv.Config{UDPListen: t.UDPListen, TCPListen: t.TCPListen, TLSListen: t.TLSListen,
		TLS: tc, RelayIP: net.ParseIP(t.RelayIP).To4(), PortMin: t.RelayPortMin, PortMax: t.RelayPortMax, Secret: secret,
		Realm: t.Realm, MaxPerUser: t.MaxAllocationsPerUser, MaxTotal: t.MaxAllocations, RelayKbps: t.RelayKbps,
		AllowPrivatePeers: t.AllowPrivatePeers, Netlog: netlog.StoreLogger{S: a.st}, StatsFile: turnStatsPath(a.cfg),
		Refuse: a.svc.TurnTagRevoked, Log: a.log})
	if err != nil {
		return nil, turnsrv.Issuer{}, err
	}
	return srv, turnsrv.Issuer{Secret: secret, RelayIP: t.RelayIP, TLS: tc != nil,
		UDPPort: portOf(t.UDPListen), TCPPort: portOf(t.TCPListen), TLSPort: portOf(t.TLSListen)}, nil
}

func portOf(listen string) int {
	_, p, _ := net.SplitHostPort(listen)
	n, _ := strconv.Atoi(p)
	return n
}

// turnStatsPath sits next to the database (the unit may write only there).
func turnStatsPath(c *config.Config) string { return filepath.Join(c.DataDir, "turn.stats.json") }

// startReality serves the client/peer mux on an internal listener and puts the REALITY inbound in front (D72).
func startReality(a *app, gw http.Handler, repl *replication.Replicator, errc chan<- error) (func(), error) {
	priv, err := reality.ReadKeyFile(a.cfg.Reality.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("reality key: %w", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	icfg := wss.Config{Path: a.cfg.WSS.Path, SiteDir: a.cfg.WSS.SiteDir}
	isrv := wss.NewServer(icfg, gw, replication.WithListener(repl, "reality"), http.HandlerFunc(repl.ServeTunnel))
	go func() { errc <- isrv.Serve(ln) }()
	r := a.cfg.Reality
	rs, err := reality.StartServer(reality.ServerConfig{Listen: r.Listen, PrivateKey: priv, Dest: r.Dest,
		ServerNames: r.ServerNames, ShortIDs: r.ShortIDs, VlessUUID: r.VlessUUID, Forward: ln.Addr().String()})
	if err != nil {
		isrv.Close()
		return nil, err
	}
	a.log.Info("reality on", "listen", r.Listen, "dest", r.Dest)
	return func() { rs.Close(); isrv.Close() }, nil
}

// realityKeygen writes [reality].private_key_file once and prints the public key; with an existing file it
// re-prints that key's public key (idempotent for deploy scripts).
func realityKeygen(cfgPath string, out io.Writer) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if !cfg.RealityEnabled() {
		return errors.New("reality keygen: add a [reality] section with private_key_file first (deploy/reality-setup.sh does this)")
	}
	priv, pub, err := reality.GenerateKey()
	if err != nil {
		return err
	}
	if err := reality.WriteKeyFile(cfg.Reality.PrivateKeyFile, priv); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		if priv, err = reality.ReadKeyFile(cfg.Reality.PrivateKeyFile); err != nil {
			return err
		}
		if pub, err = reality.PublicFromPrivate(priv); err != nil {
			return err
		}
		fmt.Fprintf(out, "key file exists; public key: %s\n", pub)
		return nil
	}
	fmt.Fprintf(out, "public key: %s\n", pub)
	return nil
}

// turnKeygen writes the TURN-REST shared secret ([turn] secret_file, default /etc/otter/turn.secret) once; with
// --force it replaces it (active credentials stop working). The secret is never printed.
func turnKeygen(cfgPath string, force bool, out io.Writer) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	path := cfg.Turn.SecretFile
	if path == "" {
		path = config.DefaultTurnSecretFile
	}
	if err := turnsrv.WriteSecret(path, force); err != nil {
		return fmt.Errorf("turn keygen: %w", err)
	}
	fmt.Fprintf(out, "turn secret written %s\n", path)
	return nil
}

func runRealityCheck(ctx context.Context, hosts []string, out io.Writer) error {
	if len(hosts) == 0 {
		return errors.New("usage: otter-node reality-check HOST...")
	}
	good := 0
	for _, h := range hosts {
		r, err := reality.Check(ctx, h)
		switch {
		case err != nil:
			fmt.Fprintf(out, "FAIL %s: %v\n", h, err)
		case !r.OK():
			fmt.Fprintf(out, "FAIL %s: tls1.3=%v h2=%v cert=%v reality=%v\n", h, r.TLS13, r.H2, r.CertOK, r.Handshake)
		default:
			good++
			fmt.Fprintf(out, "ok   %s: tls1.3 h2 cert reality %dms\n", h, r.Latency.Milliseconds())
		}
	}
	if good == 0 {
		return errors.New("no candidate passed")
	}
	return nil
}

// printNetlog prints the connectivity log newest first (D74), e.g.
// "2026-11-20 10:02–14:55  eeee  reality:203.0.113.5:443  out  ok  ×143".
func printNetlog(ctx context.Context, st *store.Store, limit int, asJSON bool, out io.Writer) error {
	es, err := st.Netlog(ctx, limit)
	if err != nil {
		return err
	}
	if asJSON {
		return json.NewEncoder(out).Encode(es)
	}
	for _, e := range es {
		first, last := time.UnixMilli(e.FirstMs).Local(), time.UnixMilli(e.LastMs).Local()
		span := last.Format("2006-01-02 15:04")
		if e.Count > 1 {
			span = first.Format("2006-01-02 15:04") + "–" + last.Format("15:04")
		}
		line := fmt.Sprintf("%s  %s  %s  %s  %s", span, e.Peer, e.Endpoint, e.Direction, e.Result)
		if e.Class != string(netlog.OK) {
			line += " " + e.Class
		}
		line += fmt.Sprintf("  ×%d", e.Count)
		if e.Detail != "" && e.Class != string(netlog.OK) {
			line += "  (" + e.Detail + ")"
		}
		fmt.Fprintln(out, line)
	}
	return nil
}

func runProbe(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	var o probe.Options
	var pins pinList
	var expect string
	fs.StringVar(&o.URL, "url", "", "wss://host:port/path")
	fs.Var(&pins, "pin", "base64 SHA-256 SPKI pin (repeatable)")
	fs.StringVar(&o.Addr, "addr", "", "connect to HOST:PORT instead of the URL host")
	fs.BoolVar(&o.Insecure, "insecure", false, "no pin: skip certificate verification")
	fs.StringVar(&expect, "expect-node", "", "expected node id (hex)")
	fs.DurationVar(&o.Timeout, "timeout", 10*time.Second, "overall timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	o.Pins = pins
	if expect != "" {
		id, err := hex.DecodeString(expect)
		if err != nil {
			return fmt.Errorf("--expect-node: %w", err)
		}
		o.ExpectNode = id
	}
	r, err := probe.Run(ctx, o)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "ok node_id=%x protocol=%d rtt=%dms\n", r.NodeID, r.Protocol, r.RTT.Milliseconds())
	return nil
}

type pinList [][]byte

func (p *pinList) String() string { return fmt.Sprint(len(*p)) }
func (p *pinList) Set(v string) error {
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(b) != 32 {
		return fmt.Errorf("pin must be base64 of 32 bytes")
	}
	*p = append(*p, b)
	return nil
}
