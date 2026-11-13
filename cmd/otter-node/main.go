// Command otter-node runs an OtterMSG relay node.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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
	"ottermsg/server/internal/replication"
	"ottermsg/server/internal/service"
	"ottermsg/server/internal/store"
	"ottermsg/server/internal/transport/wss"
)

var version = "dev"

const usage = `usage: otter-node <command>
  run --config FILE            serve clients
  import --config FILE FILE... apply signed record files (manifest, bootstrap invite)
  check --config FILE          verify config, keys, manifest and TLS before starting
  backup --config FILE --out F consistent database copy (safe while running)
  stats --config FILE          database counts (safe while running)
  apk import --config FILE APK... store app update files served by apk.get (keeps the newest 2)
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
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var rec pb.Record
	if err := proto.Unmarshal(raw, &rec); err != nil {
		return false, fmt.Errorf("%s: not a record: %w", path, err)
	}
	return svc.ImportRecord(ctx, &rec)
}

// importApks stores APK files in <data_dir>/apk (D68). It does not open the database: deploy runs it as root
// while the node is running.
func importApks(cfgPath string, files []string, out io.Writer) error {
	if len(files) == 0 {
		return errors.New("usage: otter-node apk import --config FILE APK...")
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
		sum, err := d.Import(f)
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
	rest := args[1:]
	if cmd == "apk" {
		if len(rest) == 0 || rest[0] != "import" {
			return errors.New("usage: otter-node apk import --config FILE APK...")
		}
		rest = rest[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/otter/node.toml", "config file")
	outPath := fs.String("out", "", "backup file (backup)")
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
	if cmd != "run" && cmd != "import" && cmd != "backup" && cmd != "stats" {
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
		fmt.Fprintf(out, "users=%d records=%d oplog_seq=%d blobs=%d blob_bytes=%d peers=%d\n",
			st.Users, st.Records, st.OplogSeq, st.Blobs, st.BlobBytes, st.Peers)
		return nil
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
	rank, nl := replication.NewRanker(time.Now), netlog.StoreLogger{S: a.st}
	dialer := &replication.MultiDialer{EP: replication.NetDialer{AllowPlain: a.cfg.Mesh.AllowPlain}, Rank: rank, Log: nl}
	repl := replication.New(a.svc, dialer, a.log, replication.WithNetlog(nl, rank))
	go repl.Run(ctx)     // before serving, so accepted peer sessions use the run context
	a.svc.Fetcher = repl // readers asking for a chunk this node lacks are served from a peer (D45)
	go repl.RunPuller(ctx, a.cfg.BlobBytesPerSec)
	go a.svc.RunJanitor(ctx, 10*time.Minute)
	wcfg := wss.Config{Listen: a.cfg.WSS.Listen, Path: a.cfg.WSS.Path, TLSCert: a.cfg.WSS.TLSCert, TLSKey: a.cfg.WSS.TLSKey, SiteDir: a.cfg.WSS.SiteDir}
	srv := wss.NewServer(wcfg, gw, repl)
	errc := make(chan error, 1)
	go func() { errc <- wss.Serve(srv, wcfg) }()
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
