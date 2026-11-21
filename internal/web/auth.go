package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/liorokman/homelabmap/internal/store"
)

const (
	loginCookie  = "homelabmap_login"
	loginTTL     = 10 * time.Minute
	devUserName  = "local developer"
	ctxKeyUser   = ctxKey("user")
	sessionBytes = 32
)

type ctxKey string

// User is the authenticated person, as stored in the session.
type User struct {
	Subject string `json:"subject"`
	Name    string `json:"name"`
	Email   string `json:"email"`
}

func userFrom(ctx context.Context) *User {
	u, _ := ctx.Value(ctxKeyUser).(*User)
	return u
}

func randomToken() string {
	b := make([]byte, sessionBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never fails on supported platforms
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// oidcAuth performs the authorization-code flow with PKCE (S256), plus
// state and nonce checks. The provider is discovered lazily so the app
// starts even while the identity provider is down.
type oidcAuth struct {
	cfg   Config
	store *store.Store

	// client, if set, is used for all calls to the identity provider.
	client *http.Client

	mu       sync.Mutex
	provider *oidc.Provider
	endSess  string
}

// ctx attaches the IdP HTTP client to a context for go-oidc and oauth2.
func (a *oidcAuth) ctx(ctx context.Context) context.Context {
	if a.client == nil {
		return ctx
	}
	return oidc.ClientContext(ctx, a.client)
}

func (a *oidcAuth) init(ctx context.Context) (*oidc.Provider, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.provider != nil {
		return a.provider, nil
	}
	ctx, cancel := context.WithTimeout(a.ctx(ctx), 10*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(ctx, a.cfg.OIDCIssuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	var extra struct {
		EndSession string `json:"end_session_endpoint"`
	}
	_ = p.Claims(&extra)
	a.provider, a.endSess = p, extra.EndSession
	return p, nil
}

func (a *oidcAuth) oauth(p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     a.cfg.OIDCClientID,
		ClientSecret: a.cfg.OIDCClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  a.cfg.PublicURL.String() + "/auth/callback",
		Scopes:       a.cfg.OIDCScopes,
	}
}

// safeReturn only allows local absolute paths, preventing open redirects.
func safeReturn(s string) string {
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "/\\") || strings.ContainsAny(s, "\r\n") {
		return "/"
	}
	return s
}

func (s *Server) cookieSecure() bool { return s.cfg.PublicURL.Scheme == "https" }

// sessionCookieName uses the __Host- prefix when possible: the browser then
// guarantees Secure, Path=/ and no Domain attribute.
func (s *Server) sessionCookieName() string {
	if s.cookieSecure() {
		return "__Host-homelabmap"
	}
	return "homelabmap_session"
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	p, err := s.auth.init(r.Context())
	if err != nil {
		s.log.Error("login unavailable", "err", err)
		http.Error(w, "The identity provider is unreachable. Try again shortly.", http.StatusServiceUnavailable)
		return
	}
	id := randomToken()
	flow := store.LoginFlow{
		State:     randomToken(),
		Nonce:     randomToken(),
		Verifier:  oauth2.GenerateVerifier(),
		ReturnTo:  safeReturn(r.URL.Query().Get("return")),
		ExpiresAt: s.now().Add(loginTTL),
	}
	if err := s.store.CreateLoginFlow(r.Context(), hashToken(id), flow); err != nil {
		s.serverError(w, "creating login flow", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: loginCookie, Value: id, Path: "/auth/", MaxAge: int(loginTTL.Seconds()),
		HttpOnly: true, Secure: s.cookieSecure(), SameSite: http.SameSiteLaxMode,
	})
	url := s.auth.oauth(p).AuthCodeURL(flow.State, oauth2.S256ChallengeOption(flow.Verifier), oidc.Nonce(flow.Nonce))
	http.Redirect(w, r, url, http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := s.auth.ctx(r.Context())
	fail := func(msg string, err error) {
		s.log.Warn("login failed", "reason", msg, "err", err)
		http.Error(w, "Login failed: "+msg+". Go back to / to try again.", http.StatusForbidden)
	}
	c, err := r.Cookie(loginCookie)
	if err != nil {
		fail("missing login cookie", err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: loginCookie, Path: "/auth/", MaxAge: -1, HttpOnly: true, Secure: s.cookieSecure(), SameSite: http.SameSiteLaxMode})
	flow, err := s.store.TakeLoginFlow(ctx, hashToken(c.Value), s.now())
	if err != nil {
		fail("login expired or already used", err)
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		fail("identity provider said "+e, errors.New(q.Get("error_description")))
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(flow.State)) != 1 {
		fail("state mismatch", nil)
		return
	}
	p, err := s.auth.init(ctx)
	if err != nil {
		fail("identity provider unreachable", err)
		return
	}
	tok, err := s.auth.oauth(p).Exchange(ctx, q.Get("code"), oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		fail("code exchange", err)
		return
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		fail("no ID token", nil)
		return
	}
	idt, err := p.Verifier(&oidc.Config{ClientID: s.cfg.OIDCClientID}).Verify(ctx, rawID)
	if err != nil {
		fail("invalid ID token", err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(flow.Nonce)) != 1 {
		fail("nonce mismatch", nil)
		return
	}
	var claims struct {
		Email             string   `json:"email"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
	}
	if err := idt.Claims(&claims); err != nil {
		fail("unreadable claims", err)
		return
	}
	if len(s.cfg.OIDCAllowedGroups) > 0 && !slices.ContainsFunc(claims.Groups, func(g string) bool {
		return slices.Contains(s.cfg.OIDCAllowedGroups, g)
	}) {
		fail("you are not in an allowed group", fmt.Errorf("user %s groups %v", idt.Subject, claims.Groups))
		return
	}
	name := claims.Name
	if name == "" {
		name = claims.PreferredUsername
	}
	sid := randomToken()
	exp := s.now().Add(s.cfg.SessionTTL)
	if err := s.store.CreateSession(ctx, hashToken(sid), store.Session{
		Subject: idt.Subject, Name: name, Email: claims.Email, ExpiresAt: exp,
	}, s.now()); err != nil {
		s.serverError(w, "creating session", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: s.sessionCookieName(), Value: sid, Path: "/", Expires: exp,
		HttpOnly: true, Secure: s.cookieSecure(), SameSite: http.SameSiteLaxMode,
	})
	s.log.Info("login", "subject", idt.Subject, "name", name)
	http.Redirect(w, r, flow.ReturnTo, http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	if c, err := r.Cookie(s.sessionCookieName()); err == nil {
		_ = s.store.DeleteSession(r.Context(), hashToken(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: s.sessionCookieName(), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.cookieSecure(), SameSite: http.SameSiteLaxMode})
	dest := "/logged-out"
	if !s.cfg.InsecureNoAuth {
		if _, err := s.auth.init(r.Context()); err == nil && s.auth.endSess != "" {
			dest = s.auth.endSess
		}
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// requireUser loads the session; unauthenticated API calls get 401 and
// page loads are sent to the login.
func (s *Server) requireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.InsecureNoAuth {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyUser, &User{Subject: "dev", Name: devUserName})))
			return
		}
		if c, err := r.Cookie(s.sessionCookieName()); err == nil {
			sess, err := s.store.GetSession(r.Context(), hashToken(c.Value), s.now())
			if err == nil {
				u := &User{Subject: sess.Subject, Name: sess.Name, Email: sess.Email}
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyUser, u)))
				return
			}
			if !errors.Is(err, store.ErrNotFound) {
				s.serverError(w, "loading session", err)
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
			return
		}
		http.Redirect(w, r, "/auth/login?return="+urlQueryEscape(r.URL.RequestURI()), http.StatusFound)
	})
}

// sameOrigin rejects cross-site state-changing requests. Browsers always
// send Origin on POST; a missing header means a non-browser client.
func (s *Server) sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return r.Header.Get("Sec-Fetch-Site") == "" || r.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	want := s.cfg.PublicURL.Scheme + "://" + s.cfg.PublicURL.Host
	if s.cfg.InsecureNoAuth {
		return o == want || o == "http://"+r.Host
	}
	return o == want
}
