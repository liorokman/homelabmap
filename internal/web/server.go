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
	pw    *passwordAuth
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
		pw:    newPasswordAuth(),
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
	if s.cfg.PasswordLogin() {
		mux.HandleFunc("POST /auth/password", s.handlePasswordLogin)
		mux.HandleFunc("POST /auth/setup", s.handleSetup)
		mux.HandleFunc("GET /signin/forgot", s.handleForgot)
		mux.HandleFunc("POST /auth/reset", s.handleReset)
	} else {
		mux.HandleFunc("GET /auth/login", s.handleLogin)
		mux.HandleFunc("GET /auth/callback", s.handleCallback)
	}
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	mux.HandleFunc("GET /signin", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("signed-out") != "" {
			s.renderSignin(w, r, "/", true)
			return
		}
		s.handleSignin(w, r)
	})
	mux.HandleFunc("GET /logged-out", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/signin?signed-out=1", http.StatusFound)
	})

	app := http.NewServeMux()
	app.HandleFunc("GET /api/status", s.handleStatus)
	app.HandleFunc("GET /api/graph", s.handleGraph)
	app.HandleFunc("GET /api/scans", s.handleScans)
	app.HandleFunc("GET /api/sightings", s.handleSightings)
	app.HandleFunc("POST /api/scan", s.handleScanNow)
	if s.cfg.PasswordLogin() {
		app.HandleFunc("POST /api/password", s.handleChangePassword)
	}
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
		// same-origin: nothing leaks to other sites, and browsers keep
		// sending a real Origin on our own form posts.
		h.Set("Referrer-Policy", "same-origin")
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
	if err := s.announceSetup(ctx); err != nil {
		return err
	}
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

// announceSetup logs the one-time setup code while password login has no
// account yet. Whoever can read the log can create the account; visitors
// who merely reach the sign-in page first can't.
func (s *Server) announceSetup(ctx context.Context) error {
	if !s.cfg.PasswordLogin() {
		return nil
	}
	exists, err := s.store.HasLocalUser(ctx)
	if err != nil || exists {
		return err
	}
	s.log.Warn("no account yet: open the sign-in page and create one with this setup code",
		"url", s.cfg.PublicURL.JoinPath("/signin").String(), "setup_code", s.pw.setupCode)
	return nil
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
