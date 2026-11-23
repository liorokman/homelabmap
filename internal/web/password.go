package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/liorokman/homelabmap/internal/store"
)

// Password login is used when no OIDC provider is configured. There is one
// account, created on first run with a setup code from the server log.

const (
	minPasswordLen = 12
	maxPasswordLen = 1024 // bytes; bounds the hashing work per request
	maxUsernameLen = 64
	maxLoginForm   = 8 << 10

	// loginFailMax failed sign-ins (or setup attempts) within loginFailWindow
	// block further attempts until the oldest failure ages out.
	loginFailMax    = 10
	loginFailWindow = 15 * time.Minute
	// hashConcurrency bounds simultaneous Argon2 computations (and memory).
	hashConcurrency = 2
)

// argonParams are Argon2id's cost settings. They are stored in each hash,
// so they can be raised later without invalidating existing passwords.
type argonParams struct {
	memory  uint32 // KiB
	time    uint32
	threads uint8
}

// defaultArgon exceeds OWASP's minimum (19 MiB, t=2) at about 0.1 s per hash.
var defaultArgon = argonParams{memory: 64 * 1024, time: 2, threads: 1}

const (
	argonSaltLen = 16
	argonKeyLen  = 32
)

// hashPassword returns the PHC string format:
// $argon2id$v=19$m=65536,t=2,p=1$<salt>$<key> (unpadded base64).
func hashPassword(password string, p argonParams) string {
	salt := make([]byte, argonSaltLen)
	_, _ = rand.Read(salt) // crypto/rand.Read never fails on supported platforms
	key := argon2.IDKey([]byte(password), salt, p.time, p.memory, p.threads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.memory, p.time, p.threads, b64.EncodeToString(salt), b64.EncodeToString(key))
}

var errBadHash = errors.New("unrecognised password hash")

// verifyPassword checks password against an encoded hash in constant time.
func verifyPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false, errBadHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errBadHash
	}
	var p argonParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil ||
		p.memory == 0 || p.memory > 1<<20 || p.time == 0 || p.time > 16 || p.threads == 0 {
		return false, errBadHash
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return false, errBadHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) < 16 || len(want) > 64 {
		return false, errBadHash
	}
	got := argon2.IDKey([]byte(password), salt, p.time, p.memory, p.threads, uint32(len(want))) //nolint:gosec // len checked ≤ 64
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// newSetupCode returns a one-time code like "K7QM-2XPA-9DTE" (60 bits).
func newSetupCode() string {
	t := rand.Text() // base32, 26 characters
	return t[0:4] + "-" + t[4:8] + "-" + t[8:12]
}

func normaliseSetupCode(s string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(s))
}

// loginLimiter counts recent failures. It is global, not per client: behind
// a reverse proxy every client has the proxy's address, and there is only
// one account to guess anyway.
type loginLimiter struct {
	mu    sync.Mutex
	fails []time.Time
}

// blocked returns how long to wait before another attempt, or 0.
func (l *loginLimiter) blocked(now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(now)
	if len(l.fails) < loginFailMax {
		return 0
	}
	return l.fails[0].Add(loginFailWindow).Sub(now)
}

func (l *loginLimiter) fail(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(now)
	l.fails = append(l.fails, now)
}

func (l *loginLimiter) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails = nil
}

func (l *loginLimiter) prune(now time.Time) {
	i := 0
	for i < len(l.fails) && now.Sub(l.fails[i]) >= loginFailWindow {
		i++
	}
	l.fails = l.fails[i:]
}

// passwordAuth holds password-login state.
type passwordAuth struct {
	params    argonParams
	setupCode string
	limiter   loginLimiter
	sem       chan struct{}

	dummyOnce sync.Once
	dummy     string
}

func newPasswordAuth() *passwordAuth {
	return &passwordAuth{params: defaultArgon, setupCode: newSetupCode(), sem: make(chan struct{}, hashConcurrency)}
}

// SetupCode is the one-time code that creates the first password account
// (also logged at startup while there is none). The demo prints it.
func (s *Server) SetupCode() string { return s.pw.setupCode }

// withHashSlot runs f while holding one of the hashing slots.
func (a *passwordAuth) withHashSlot(r *http.Request, f func()) bool {
	select {
	case a.sem <- struct{}{}:
	case <-r.Context().Done():
		return false
	}
	defer func() { <-a.sem }()
	f()
	return true
}

// dummyHash is verified for unknown usernames so that they take as long as
// a wrong password and don't reveal which names exist.
func (a *passwordAuth) dummyHash() string {
	a.dummyOnce.Do(func() { a.dummy = hashPassword(randomToken(), a.params) })
	return a.dummy
}

func validUsername(u string) error {
	if u == "" || len(u) > maxUsernameLen || !utf8.ValidString(u) || strings.TrimSpace(u) != u {
		return fmt.Errorf("the username must be 1 to %d characters, without leading or trailing spaces", maxUsernameLen)
	}
	for _, r := range u {
		if !unicode.IsPrint(r) {
			return errors.New("the username contains an invalid character")
		}
	}
	return nil
}

func validPassword(p string) error {
	switch {
	case utf8.RuneCountInString(p) < minPasswordLen:
		return fmt.Errorf("the password must be at least %d characters", minPasswordLen)
	case len(p) > maxPasswordLen:
		return fmt.Errorf("the password must be at most %d bytes", maxPasswordLen)
	}
	return nil
}

// passwordForm parses a same-origin form post, or answers the request.
func (s *Server) passwordForm(w http.ResponseWriter, r *http.Request) bool {
	if !s.sameOrigin(r) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginForm)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return false
	}
	return true
}

// throttled answers with 429 when too many attempts failed recently.
func (s *Server) throttled(w http.ResponseWriter, view signinView) bool {
	wait := s.pw.limiter.blocked(s.now())
	if wait <= 0 {
		return false
	}
	view.Error = fmt.Sprintf("Too many failed attempts. Try again in %d minutes.", int(wait.Minutes())+1)
	w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())+1))
	s.renderSigninView(w, http.StatusTooManyRequests, view)
	return true
}

func (s *Server) handlePasswordLogin(w http.ResponseWriter, r *http.Request) {
	if !s.passwordForm(w, r) {
		return
	}
	username, password := r.PostForm.Get("username"), r.PostForm.Get("password")
	view := signinView{Mode: modePassword, Return: safeReturn(r.PostForm.Get("return")), Username: username}
	if s.throttled(w, view) {
		return
	}
	var u *store.LocalUser
	var err error
	if len(username) <= maxUsernameLen && len(password) <= maxPasswordLen {
		u, err = s.store.GetLocalUser(r.Context(), username)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.serverError(w, "loading account", err)
			return
		}
	}
	hash := s.pw.dummyHash()
	if u != nil {
		hash = u.PasswordHash
	}
	var ok bool
	if !s.pw.withHashSlot(r, func() { ok, err = verifyPassword(hash, password) }) {
		return // client went away
	}
	if err != nil {
		s.serverError(w, "checking password", err)
		return
	}
	if !ok || u == nil {
		s.pw.limiter.fail(s.now())
		s.log.Warn("login failed", "reason", "wrong username or password", "username", username)
		view.Error = "Wrong username or password."
		s.renderSigninView(w, http.StatusUnauthorized, view)
		return
	}
	s.pw.limiter.reset()
	s.startLocalSession(w, r, u.Username, view.Return)
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if !s.passwordForm(w, r) {
		return
	}
	exists, err := s.store.HasLocalUser(r.Context())
	if err != nil {
		s.serverError(w, "checking accounts", err)
		return
	}
	if exists {
		http.Redirect(w, r, "/signin", http.StatusSeeOther)
		return
	}
	f := r.PostForm
	username, password := f.Get("username"), f.Get("password")
	view := signinView{Mode: modeSetup, Return: "/", Username: username}
	if s.throttled(w, view) {
		return
	}
	code := normaliseSetupCode(f.Get("setup_code"))
	if subtle.ConstantTimeCompare([]byte(code), []byte(normaliseSetupCode(s.pw.setupCode))) != 1 {
		s.pw.limiter.fail(s.now())
		s.log.Warn("account setup refused", "reason", "wrong setup code")
		view.Error = "Wrong setup code. It is in the homelabmap-web log."
		s.renderSigninView(w, http.StatusForbidden, view)
		return
	}
	err = validUsername(username)
	if err == nil {
		err = validPassword(password)
	}
	if err == nil && password != f.Get("confirm") {
		err = errors.New("the passwords don't match")
	}
	if err != nil {
		view.Error = strings.ToUpper(err.Error()[:1]) + err.Error()[1:] + "."
		s.renderSigninView(w, http.StatusBadRequest, view)
		return
	}
	var hash string
	if !s.pw.withHashSlot(r, func() { hash = hashPassword(password, s.pw.params) }) {
		return
	}
	err = s.store.CreateFirstLocalUser(r.Context(), store.LocalUser{Username: username, PasswordHash: hash, CreatedAt: s.now()})
	if errors.Is(err, store.ErrUserExists) {
		http.Redirect(w, r, "/signin", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.serverError(w, "creating account", err)
		return
	}
	s.pw.limiter.reset()
	s.log.Info("account created", "username", username)
	s.startLocalSession(w, r, username, "/")
}

// startLocalSession signs a password user in with a fresh session.
func (s *Server) startLocalSession(w http.ResponseWriter, r *http.Request, username, returnTo string) {
	sid := randomToken()
	exp := s.now().Add(s.cfg.SessionTTL)
	if err := s.store.CreateSession(r.Context(), hashToken(sid), store.Session{
		Subject: "local:" + username, Name: username, ExpiresAt: exp,
	}, s.now()); err != nil {
		s.serverError(w, "creating session", err)
		return
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure via cookieSecure(): https is required with login
		Name: s.sessionCookieName(), Value: sid, Path: "/", Expires: exp,
		HttpOnly: true, Secure: s.cookieSecure(), SameSite: http.SameSiteLaxMode,
	})
	s.log.Info("login", "subject", "local:"+username, "name", username)
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

// handleChangePassword changes the signed-in local account's password. It
// requires the current password, and ends the account's other sessions.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) || r.Header.Get("X-Homelabmap-Request") != "1" {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	fail := func(code int, msg string) { writeJSON(w, code, map[string]string{"error": msg}) }
	u := userFrom(r.Context())
	username, ok := strings.CutPrefix(u.Subject, "local:")
	if !ok {
		fail(http.StatusForbidden, "This account's password is managed by the identity provider.")
		return
	}
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoginForm)).Decode(&req); err != nil {
		fail(http.StatusBadRequest, "Bad request.")
		return
	}
	if wait := s.pw.limiter.blocked(s.now()); wait > 0 {
		w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())+1))
		fail(http.StatusTooManyRequests, fmt.Sprintf("Too many failed attempts. Try again in %d minutes.", int(wait.Minutes())+1))
		return
	}
	acct, err := s.store.GetLocalUser(r.Context(), username)
	if errors.Is(err, store.ErrNotFound) {
		fail(http.StatusForbidden, "The account no longer exists.")
		return
	}
	if err != nil {
		s.serverError(w, "loading account", err)
		return
	}
	if len(req.Current) > maxPasswordLen {
		req.Current = "" // still verified, so the timing matches
	}
	var match bool
	if !s.pw.withHashSlot(r, func() { match, err = verifyPassword(acct.PasswordHash, req.Current) }) {
		return
	}
	if err != nil {
		s.serverError(w, "checking password", err)
		return
	}
	if !match {
		s.pw.limiter.fail(s.now())
		s.log.Warn("password change refused", "reason", "wrong current password", "username", username)
		fail(http.StatusForbidden, "The current password is wrong.")
		return
	}
	if err := validPassword(req.New); err != nil {
		fail(http.StatusBadRequest, strings.ToUpper(err.Error()[:1])+err.Error()[1:]+".")
		return
	}
	if req.New == req.Current {
		fail(http.StatusBadRequest, "The new password is the same as the current one.")
		return
	}
	var hash string
	if !s.pw.withHashSlot(r, func() { hash = hashPassword(req.New, s.pw.params) }) {
		return
	}
	if err := s.store.SetLocalPassword(r.Context(), acct.Username, hash); err != nil {
		s.serverError(w, "changing password", err)
		return
	}
	s.pw.limiter.reset()
	var keep string
	if c, err := r.Cookie(s.sessionCookieName()); err == nil {
		keep = hashToken(c.Value)
	}
	ended, err := s.store.DeleteOtherSessions(r.Context(), u.Subject, keep)
	if err != nil {
		s.serverError(w, "ending other sessions", err)
		return
	}
	s.log.Info("password changed", "username", acct.Username, "other_sessions_ended", ended)
	writeJSON(w, http.StatusOK, map[string]int64{"otherSessionsEnded": ended})
}

// ResetCodeTTL is how long a reset code from "homelabmap-web reset-code"
// stays valid.
const ResetCodeTTL = 15 * time.Minute

// ErrNoAccount means there is no password account to reset yet.
var ErrNoAccount = errors.New("no account yet: create it on the sign-in page with the setup code from the log")

// CreateResetCode makes a one-time password reset code for the local
// account and returns it with its expiry. Only its hash is stored, and it
// replaces any earlier code. Running it requires access to the host, which
// is the proof of ownership a reset needs.
func CreateResetCode(ctx context.Context, st *store.Store, now time.Time) (string, time.Time, error) {
	if _, err := st.OnlyLocalUser(ctx); errors.Is(err, store.ErrNotFound) {
		return "", time.Time{}, ErrNoAccount
	} else if err != nil {
		return "", time.Time{}, err
	}
	code := newSetupCode()
	exp := now.Add(ResetCodeTTL)
	if err := st.SetPasswordReset(ctx, hashToken(normaliseSetupCode(code)), exp); err != nil {
		return "", time.Time{}, err
	}
	return code, exp, nil
}

// handleReset sets a new password with a reset code, ends all of the
// account's sessions and signs in.
func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	if !s.passwordForm(w, r) {
		return
	}
	f := r.PostForm
	view := signinView{Mode: modeReset, Return: "/"}
	if s.throttled(w, view) {
		return
	}
	password := f.Get("password")
	err := validPassword(password)
	if err == nil && password != f.Get("confirm") {
		err = errors.New("the passwords don't match")
	}
	if err != nil {
		view.Error = strings.ToUpper(err.Error()[:1]) + err.Error()[1:] + "."
		s.renderSigninView(w, http.StatusBadRequest, view)
		return
	}
	// Taken only now, so a typo in the new password doesn't use up the code.
	err = s.store.TakePasswordReset(r.Context(), hashToken(normaliseSetupCode(f.Get("reset_code"))), s.now())
	if errors.Is(err, store.ErrNotFound) {
		s.pw.limiter.fail(s.now())
		s.log.Warn("password reset refused", "reason", "wrong or expired reset code")
		view.Error = "Wrong or expired reset code. Run the command again for a new one."
		s.renderSigninView(w, http.StatusForbidden, view)
		return
	}
	if err != nil {
		s.serverError(w, "checking reset code", err)
		return
	}
	acct, err := s.store.OnlyLocalUser(r.Context())
	if err != nil {
		s.serverError(w, "loading account", err)
		return
	}
	var hash string
	if !s.pw.withHashSlot(r, func() { hash = hashPassword(password, s.pw.params) }) {
		return
	}
	if err := s.store.SetLocalPassword(r.Context(), acct.Username, hash); err != nil {
		s.serverError(w, "resetting password", err)
		return
	}
	ended, err := s.store.DeleteOtherSessions(r.Context(), "local:"+acct.Username, "")
	if err != nil {
		s.serverError(w, "ending sessions", err)
		return
	}
	s.pw.limiter.reset()
	s.log.Info("password reset", "username", acct.Username, "sessions_ended", ended)
	s.startLocalSession(w, r, acct.Username, "/")
}
