// Command otter-node runs an OtterMSG relay node.
package main

import (
	"bytes"
	"context"
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
	"ottermsg/server/internal/config"
	"ottermsg/server/internal/gateway"
	"ottermsg/server/internal/keys"
	pb "ottermsg/server/internal/proto/otterv1"
	"ottermsg/server/internal/replication"
	"ottermsg/server/internal/service"
	"ottermsg/server/internal/store"
	"ottermsg/server/internal/transport/wss"
)

var version = "dev"

const usage = `usage: otter-node <command> --config FILE
  run                  serve clients
  import FILE...       apply signed record files (manifest, bootstrap invite)
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

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	cmd := args[0]
	if cmd == "version" {
		fmt.Fprintln(out, version)
		return nil
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/otter/node.toml", "config file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
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
	repl := replication.New(a.svc, replication.NetDialer{AllowPlain: a.cfg.Mesh.AllowPlain}, a.log)
	go repl.Run(ctx) // before serving, so accepted peer sessions use the run context
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
