// Package wss serves the client WebSocket on a secret path, everything else as a plain website.
package wss

import (
	"net/http"
	"time"
)

type Config struct {
	Listen  string
	Path    string
	TLSCert string
	TLSKey  string
	SiteDir string
}

// NewServer routes cfg.Path to the client handler and cfg.Path+"/peer" to the peer handler (nil: not mounted).
func NewServer(cfg Config, ws, peer http.Handler) *http.Server {
	mux := http.NewServeMux()
	mux.Handle(cfg.Path, ws)
	if peer != nil {
		mux.Handle(cfg.Path+"/peer", peer)
	}
	var site http.Handler = http.NotFoundHandler()
	if cfg.SiteDir != "" {
		site = http.FileServer(http.Dir(cfg.SiteDir))
	}
	mux.Handle("/", site)
	return &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
}

func Serve(srv *http.Server, cfg Config) error {
	if cfg.TLSCert != "" {
		return srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	}
	return srv.ListenAndServe()
}
