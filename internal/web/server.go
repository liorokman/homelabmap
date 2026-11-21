package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/liorokman/homelabmap/internal/store"
)

//go:embed static
var staticFS embed.FS

type Server struct {
	cfg   Config
	store *store.Store
	log   *slog.Logger
	auth  *oidcAuth
	now   func() time.Time

	// scannerSeen is the unix time of the last agent poll.
	scannerSeen atomic.Int64
	// lastSighting is the unix time the passive listener last reported.
	lastSighting atomic.Int64
	// wake nudges a long-polling agent when a scan is queued.
	wake chan struct{}
	// longPoll is how long an agent poll waits for work.
	longPoll time.Duration
}

func New(cfg Config, st *store.Store, log *slog.Logger) *Server {
	return &Server{
		cfg:   cfg,
		store: st,
		log:   log,
		auth:  &oidcAuth{cfg: cfg, store: st},
		now:   func() time.Time { return time.Now().UTC() },
		wake:  make(chan struct{}, 1),

		longPoll: 25 * time.Second,
	}
}

func (s *Server) notifyAgent() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// UIHandler serves the web UI and its API.
func (s *Server) UIHandler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	files := http.FileServerFS(static)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /auth/login", s.handleLogin)
	mux.HandleFunc("GET /auth/callback", s.handleCallback)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	mux.HandleFunc("GET /logged-out", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><title>homelabmap</title><p>Signed out. <a href="/">Sign in again</a></p>`))
	})

	app := http.NewServeMux()
	app.HandleFunc("GET /api/status", s.handleStatus)
	app.HandleFunc("GET /api/graph", s.handleGraph)
	app.HandleFunc("GET /api/scans", s.handleScans)
	app.HandleFunc("GET /api/sightings", s.handleSightings)
	app.HandleFunc("POST /api/scan", s.handleScanNow)
	app.Handle("GET /", files)
	mux.Handle("/", s.requireUser(app))

	return s.securityHeaders(mux)
}

// AgentHandler serves the scanner. It is bound to a separate listener that
// is only published on the host's loopback interface.
func (s *Server) AgentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /agent/v1/job", s.handleAgentJob)
	mux.HandleFunc("POST /agent/v1/result", s.handleAgentResult)
	mux.HandleFunc("POST /agent/v1/sightings", s.handleAgentSightings)
	return s.requireAgent(mux)
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	formAction := "'self'"
	if u, err := url.Parse(s.cfg.OIDCIssuer); err == nil && u.Host != "" {
		formAction += " " + u.Scheme + "://" + u.Host // logout redirects to the IdP
	}
	csp := "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
		"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action " + formAction
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if s.cookieSecure() {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// Run serves both listeners and the scheduler until ctx ends.
func (s *Server) Run(ctx context.Context) error {
	s.rebuildStaleGraphs(ctx)
	ui := &http.Server{Addr: s.cfg.Listen, Handler: s.UIHandler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: time.Minute, WriteTimeout: time.Minute, IdleTimeout: 2 * time.Minute}
	agent := &http.Server{Addr: s.cfg.AgentListen, Handler: s.AgentHandler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 5 * time.Minute, WriteTimeout: time.Minute, IdleTimeout: 2 * time.Minute}

	g, ctx := errgroup.WithContext(ctx)
	for _, srv := range []*http.Server{ui, agent} {
		g.Go(func() error {
			s.log.Info("listening", "addr", srv.Addr)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		})
	}
	g.Go(func() error { s.runScheduler(ctx); return nil })
	g.Go(func() error {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return errors.Join(ui.Shutdown(sctx), agent.Shutdown(sctx))
	})
	return g.Wait()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// serverError logs details and returns a generic message.
func (s *Server) serverError(w http.ResponseWriter, what string, err error) {
	s.log.Error(what, "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func urlQueryEscape(s string) string { return url.QueryEscape(s) }
