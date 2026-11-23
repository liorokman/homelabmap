package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/liorokman/homelabmap/internal/store"
)

// cheapArgon keeps the tests fast; production uses defaultArgon.
var cheapArgon = argonParams{memory: 64, time: 1, threads: 1}

func newPasswordHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t, func(c *Config) { c.OIDCIssuer, c.OIDCClientID = "", "" })
	h.s.pw.params = cheapArgon
	return h
}

func (h *harness) postForm(t *testing.T, path string, form url.Values, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", h.app.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func (h *harness) body(t *testing.T, path string) string {
	t.Helper()
	b, _ := io.ReadAll(h.get(t, path).Body)
	return string(b)
}

func setupForm(code, user, pw string) url.Values {
	return url.Values{"setup_code": {code}, "username": {user}, "password": {pw}, "confirm": {pw}}
}

func TestPasswordHash(t *testing.T) {
	enc := hashPassword("correct horse battery", defaultArgon)
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=65536,t=2,p=1$") {
		t.Fatalf("encoding: %s", enc)
	}
	if enc == hashPassword("correct horse battery", defaultArgon) {
		t.Error("hashes of the same password should differ (salt)")
	}
	if ok, err := verifyPassword(enc, "correct horse battery"); !ok || err != nil {
		t.Errorf("right password: %v %v", ok, err)
	}
	if ok, err := verifyPassword(enc, "correct horse battery!"); ok || err != nil {
		t.Errorf("wrong password: %v %v", ok, err)
	}
	for _, bad := range []string{
		"", "plain", "$argon2i$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$" + strings.Repeat("A", 43),
		"$argon2id$v=16$m=64,t=1,p=1$c2FsdHNhbHQ$" + strings.Repeat("A", 43),
		"$argon2id$v=19$m=0,t=1,p=1$c2FsdHNhbHQ$" + strings.Repeat("A", 43),
		"$argon2id$v=19$m=x$c2FsdHNhbHQ$" + strings.Repeat("A", 43),
		"$argon2id$v=19$m=64,t=1,p=1$!!$" + strings.Repeat("A", 43),
		"$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$AAAA",
	} {
		if _, err := verifyPassword(bad, "x"); err == nil {
			t.Errorf("accepted malformed hash %q", bad)
		}
	}
}

func TestValidation(t *testing.T) {
	for _, u := range []string{"", " admin", "admin ", "a\tb", strings.Repeat("a", 65), "\xff"} {
		if validUsername(u) == nil {
			t.Errorf("username %q accepted", u)
		}
	}
	if err := validUsername("Lab Admin"); err != nil {
		t.Error(err)
	}
	if validPassword("elevenchars") == nil || validPassword(strings.Repeat("x", maxPasswordLen+1)) == nil {
		t.Error("bad password length accepted")
	}
	if err := validPassword("twelve chars"); err != nil {
		t.Error(err)
	}
	if c := newSetupCode(); len(c) != 14 || normaliseSetupCode(strings.ToLower(c)) != strings.ReplaceAll(c, "-", "") {
		t.Errorf("setup code %q", c)
	}
}

func TestPasswordFirstRunAndLogin(t *testing.T) {
	h := newPasswordHarness(t)
	code := h.s.pw.setupCode

	// No account yet: the landing page asks to create one; no OIDC routes.
	if b := h.body(t, "/signin"); !strings.Contains(b, `action="/auth/setup"`) || strings.Contains(b, "/auth/login") {
		t.Fatalf("first-run page: %s", b)
	}
	if b := h.body(t, "/signin?signed-out=1"); !strings.Contains(b, `action="/auth/setup"`) {
		t.Error("signed-out page should still offer setup")
	}
	if r := h.get(t, "/auth/login"); !strings.HasPrefix(r.Header.Get("Location"), "/signin") {
		t.Errorf("OIDC login in password mode: %d %s", r.StatusCode, r.Header.Get("Location"))
	}

	// Setup is refused cross-site, with a wrong code, or with bad input.
	if r, _ := h.postForm(t, "/auth/setup", setupForm(code, "admin", "a long password"), map[string]string{"Sec-Fetch-Site": "cross-site"}); r.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site setup: %d", r.StatusCode)
	}
	if r, b := h.postForm(t, "/auth/setup", setupForm("AAAA-BBBB-CCCC", "admin", "a long password"), nil); r.StatusCode != http.StatusForbidden || !strings.Contains(b, "Wrong setup code") {
		t.Errorf("wrong code: %d %s", r.StatusCode, b)
	}
	if r, b := h.postForm(t, "/auth/setup", setupForm(code, "admin", "short"), nil); r.StatusCode != http.StatusBadRequest || !strings.Contains(b, "at least 12") {
		t.Errorf("short password: %d %s", r.StatusCode, b)
	}
	f := setupForm(code, "admin", "a long password")
	f.Set("confirm", "another password")
	if r, b := h.postForm(t, "/auth/setup", f, nil); r.StatusCode != http.StatusBadRequest || !strings.Contains(b, "match") {
		t.Errorf("mismatch: %d %s", r.StatusCode, b)
	}
	if r, b := h.postForm(t, "/auth/setup", setupForm(code, " admin", "a long password"), nil); r.StatusCode != http.StatusBadRequest || !strings.Contains(b, "username") {
		t.Errorf("bad username: %d %s", r.StatusCode, b)
	}
	if ok, _ := h.st.HasLocalUser(context.Background()); ok {
		t.Fatal("a refused setup created an account")
	}

	// The code is accepted in lower case without dashes; setup signs in.
	r, _ := h.postForm(t, "/auth/setup", setupForm(strings.ToLower(strings.ReplaceAll(code, "-", "")), "Admin", "a long password"), nil)
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/" {
		t.Fatalf("setup: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	if r := h.get(t, "/api/status"); r.StatusCode != http.StatusOK {
		t.Fatalf("signed in after setup: %d", r.StatusCode)
	}
	u, err := h.st.GetLocalUser(context.Background(), "admin")
	if err != nil || !strings.HasPrefix(u.PasswordHash, "$argon2id$") || strings.Contains(u.PasswordHash, "a long password") {
		t.Fatalf("stored account: %+v %v", u, err)
	}

	// A second setup is refused, even with the code.
	h.client.Jar, _ = newJar()
	if r, _ := h.postForm(t, "/auth/setup", setupForm(code, "mallory", "another long password"), nil); r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/signin" {
		t.Errorf("second setup: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	if _, err := h.st.GetLocalUser(context.Background(), "mallory"); err == nil {
		t.Fatal("second account created")
	}

	// Now the landing page has the password form and keeps the return path.
	if b := h.body(t, "/signin?return=%2F%23table"); !strings.Contains(b, `action="/auth/password"`) || !strings.Contains(b, `value="/#table"`) {
		t.Fatalf("login page: %s", b)
	}
	login := func(user, pw string) (*http.Response, string) {
		return h.postForm(t, "/auth/password", url.Values{"username": {user}, "password": {pw}, "return": {"/#table"}}, nil)
	}
	if r, b := login("admin", "wrong password!"); r.StatusCode != http.StatusUnauthorized || !strings.Contains(b, "Wrong username or password") || !strings.Contains(b, `value="admin"`) {
		t.Errorf("wrong password: %d %s", r.StatusCode, b)
	}
	if r, _ := login("nobody", "a long password"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("unknown user: %d", r.StatusCode)
	}
	if r, _ := h.postForm(t, "/auth/password", url.Values{"username": {"admin"}, "password": {"a long password"}}, map[string]string{"Sec-Fetch-Site": "cross-site"}); r.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site login: %d", r.StatusCode)
	}
	if r, _ := h.postForm(t, "/auth/password", url.Values{"username": {"admin"}, "password": {"a long password"}, "return": {"https://evil.example/"}}, nil); r.Header.Get("Location") != "/" {
		t.Errorf("open redirect: %s", r.Header.Get("Location"))
	}
	h.client.Jar, _ = newJar()
	r, _ = login("ADMIN", "a long password") // usernames ignore case
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/#table" {
		t.Fatalf("login: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	if r := h.get(t, "/api/status"); r.StatusCode != http.StatusOK {
		t.Fatalf("signed in: %d", r.StatusCode)
	}

	// Logout ends the session and stays local (no identity provider).
	r, _ = h.postForm(t, "/auth/logout", nil, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/signin?signed-out=1" {
		t.Errorf("logout: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	if r := h.get(t, "/api/status"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("session survived logout: %d", r.StatusCode)
	}
	if b := h.body(t, "/signin?signed-out=1"); !strings.Contains(b, "signed out") || !strings.Contains(b, `action="/auth/password"`) {
		t.Errorf("signed-out page: %s", b)
	}
}

func TestPasswordLoginThrottled(t *testing.T) {
	h := newPasswordHarness(t)
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	h.s.now = func() time.Time { return now }
	if err := h.st.CreateFirstLocalUser(context.Background(), store.LocalUser{Username: "admin", PasswordHash: hashPassword("a long password", cheapArgon), CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	login := func(pw string) *http.Response {
		r, _ := h.postForm(t, "/auth/password", url.Values{"username": {"admin"}, "password": {pw}}, nil)
		return r
	}
	for range loginFailMax {
		if r := login("wrong password!"); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("failure: %d", r.StatusCode)
		}
	}
	// Even the right password waits until the window has passed.
	if r := login("a long password"); r.StatusCode != http.StatusTooManyRequests || r.Header.Get("Retry-After") == "" {
		t.Fatalf("throttled: %d", r.StatusCode)
	}
	now = now.Add(loginFailWindow)
	if r := login("a long password"); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("after the window: %d", r.StatusCode)
	}
	// Success clears the counter.
	if r := login("wrong password!"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("after success: %d", r.StatusCode)
	}
}

func TestAnnounceSetup(t *testing.T) {
	var buf bytes.Buffer
	h := newPasswordHarness(t)
	h.s.log = slog.New(slog.NewTextHandler(&buf, nil))
	if err := h.s.announceSetup(context.Background()); err != nil || !strings.Contains(buf.String(), h.s.pw.setupCode) {
		t.Fatalf("setup code not logged: %v %s", err, buf.String())
	}
	buf.Reset()
	_ = h.st.CreateFirstLocalUser(context.Background(), store.LocalUser{Username: "admin", PasswordHash: "x", CreatedAt: time.Now()})
	if err := h.s.announceSetup(context.Background()); err != nil || buf.Len() != 0 {
		t.Errorf("setup code logged with an account: %v %s", err, buf.String())
	}
}

// newJar gives a fresh, signed-out browser.
func newJar() (http.CookieJar, error) { return cookiejar.New(nil) }

func TestChangePassword(t *testing.T) {
	h := newPasswordHarness(t)
	ctx := context.Background()
	if err := h.st.CreateFirstLocalUser(ctx, store.LocalUser{Username: "Admin", PasswordHash: hashPassword("old password 1", cheapArgon), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	signIn := func(pw string) {
		t.Helper()
		if r, b := h.postForm(t, "/auth/password", url.Values{"username": {"admin"}, "password": {pw}}, nil); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("sign in: %d %s", r.StatusCode, b)
		}
	}
	// Another browser signed in to the same account.
	other, _ := newJar()
	h.client.Jar = other
	signIn("old password 1")
	mine, _ := newJar()
	h.client.Jar = mine
	signIn("old password 1")

	var st statusResponse
	if err := json.NewDecoder(h.get(t, "/api/status").Body).Decode(&st); err != nil || !st.CanChangePassword {
		t.Fatalf("status should offer a password change: %+v %v", st, err)
	}

	change := func(cur, next string, hdr map[string]string) (int, string) {
		t.Helper()
		b, _ := json.Marshal(map[string]string{"current": cur, "new": next})
		req, _ := http.NewRequest("POST", h.app.URL+"/api/password", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Homelabmap-Request", "1")
		for k, v := range hdr {
			if v == "" {
				req.Header.Del(k)
			} else {
				req.Header.Set(k, v)
			}
		}
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	if code, _ := change("old password 1", "new password 22", map[string]string{"Sec-Fetch-Site": "cross-site"}); code != http.StatusForbidden {
		t.Errorf("cross-site: %d", code)
	}
	if code, _ := change("old password 1", "new password 22", map[string]string{"X-Homelabmap-Request": ""}); code != http.StatusForbidden {
		t.Errorf("without the custom header: %d", code)
	}
	if code, b := change("wrong password!", "new password 22", nil); code != http.StatusForbidden || !strings.Contains(b, "current password is wrong") {
		t.Errorf("wrong current: %d %s", code, b)
	}
	if code, b := change("old password 1", "short", nil); code != http.StatusBadRequest || !strings.Contains(b, "at least 12") {
		t.Errorf("short new: %d %s", code, b)
	}
	if code, b := change("old password 1", "old password 1", nil); code != http.StatusBadRequest || !strings.Contains(b, "same") {
		t.Errorf("unchanged: %d %s", code, b)
	}
	code, b := change("old password 1", "new password 22", nil)
	if code != http.StatusOK || !strings.Contains(b, `"otherSessionsEnded":1`) {
		t.Fatalf("change: %d %s", code, b)
	}
	// This browser stays signed in; the other one is signed out.
	if r := h.get(t, "/api/status"); r.StatusCode != http.StatusOK {
		t.Errorf("own session ended: %d", r.StatusCode)
	}
	h.client.Jar = other
	if r := h.get(t, "/api/status"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("other session survived: %d", r.StatusCode)
	}
	// Only the new password works now.
	h.client.Jar, _ = newJar()
	if r, _ := h.postForm(t, "/auth/password", url.Values{"username": {"admin"}, "password": {"old password 1"}}, nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("old password still works: %d", r.StatusCode)
	}
	signIn("new password 22")

	// Too many wrong current passwords are throttled.
	h.s.pw.limiter.reset()
	for range loginFailMax {
		change("wrong password!", "another password 3", nil)
	}
	if code, _ := change("new password 22", "another password 3", nil); code != http.StatusTooManyRequests {
		t.Errorf("throttled: %d", code)
	}
	if code, _ := change("x", "y", map[string]string{"Content-Type": "text/plain"}); code != http.StatusTooManyRequests {
		t.Errorf("still throttled: %d", code)
	}
}

func TestChangePasswordRefusedForOIDC(t *testing.T) {
	h := newHarness(t, nil)
	h.login(t)
	var st statusResponse
	if err := json.NewDecoder(h.get(t, "/api/status").Body).Decode(&st); err != nil || st.CanChangePassword {
		t.Errorf("OIDC status offers a password change: %+v %v", st, err)
	}
	req, _ := http.NewRequest("POST", h.app.URL+"/api/password", strings.NewReader(`{}`))
	req.Header.Set("X-Homelabmap-Request", "1")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Errorf("password change in OIDC mode: %d", resp.StatusCode)
	}
}

func TestForgotPasswordReset(t *testing.T) {
	h := newPasswordHarness(t)
	ctx := context.Background()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	h.s.now = func() time.Time { return now }

	// No account yet: no reset code, and the forgot page sends to setup.
	if _, _, err := CreateResetCode(ctx, h.st, now); !errors.Is(err, ErrNoAccount) {
		t.Errorf("reset code without an account: %v", err)
	}
	if r := h.get(t, "/signin/forgot"); r.StatusCode != http.StatusFound || r.Header.Get("Location") != "/signin" {
		t.Errorf("forgot page without an account: %d %s", r.StatusCode, r.Header.Get("Location"))
	}

	if err := h.st.CreateFirstLocalUser(ctx, store.LocalUser{Username: "admin", PasswordHash: hashPassword("forgotten pass", cheapArgon), CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	other, _ := newJar()
	h.client.Jar = other
	if r, _ := h.postForm(t, "/auth/password", url.Values{"username": {"admin"}, "password": {"forgotten pass"}}, nil); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("sign in: %d", r.StatusCode)
	}
	h.client.Jar, _ = newJar()

	if b := h.body(t, "/signin"); !strings.Contains(b, `href="/signin/forgot"`) {
		t.Error("login page has no forgot link")
	}
	if b := h.body(t, "/signin/forgot"); !strings.Contains(b, `action="/auth/reset"`) || !strings.Contains(b, "reset-code") {
		t.Fatalf("forgot page: %s", b)
	}

	reset := func(code, pw, confirm string, hdr map[string]string) (*http.Response, string) {
		return h.postForm(t, "/auth/reset", url.Values{"reset_code": {code}, "password": {pw}, "confirm": {confirm}}, hdr)
	}
	if r, b := reset("AAAA-BBBB-CCCC", "brand new pass", "brand new pass", nil); r.StatusCode != http.StatusForbidden || !strings.Contains(b, "Wrong or expired") {
		t.Errorf("no code made: %d %s", r.StatusCode, b)
	}

	first, _, err := CreateResetCode(ctx, h.st, now)
	if err != nil {
		t.Fatal(err)
	}
	code, exp, err := CreateResetCode(ctx, h.st, now) // replaces the first
	if err != nil || !exp.Equal(now.Add(ResetCodeTTL)) {
		t.Fatalf("reset code: %v %v", exp, err)
	}
	if r, _ := reset(code, "brand new pass", "brand new pass", map[string]string{"Sec-Fetch-Site": "cross-site"}); r.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site reset: %d", r.StatusCode)
	}
	if r, _ := reset(first, "brand new pass", "brand new pass", nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("replaced code accepted: %d", r.StatusCode)
	}
	// Bad new passwords don't use the code up.
	if r, b := reset(code, "short", "short", nil); r.StatusCode != http.StatusBadRequest || !strings.Contains(b, "at least 12") {
		t.Errorf("short password: %d %s", r.StatusCode, b)
	}
	if r, b := reset(code, "brand new pass", "brand new pas", nil); r.StatusCode != http.StatusBadRequest || !strings.Contains(b, "match") {
		t.Errorf("mismatch: %d %s", r.StatusCode, b)
	}
	r, _ := reset(strings.ToLower(code), "brand new pass", "brand new pass", nil)
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/" {
		t.Fatalf("reset: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	if r := h.get(t, "/api/status"); r.StatusCode != http.StatusOK {
		t.Errorf("signed in after reset: %d", r.StatusCode)
	}
	if r, _ := reset(code, "another new pass", "another new pass", nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("code reused: %d", r.StatusCode)
	}
	// The old session elsewhere is gone, and only the new password works.
	h.client.Jar = other
	if r := h.get(t, "/api/status"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("old session survived the reset: %d", r.StatusCode)
	}
	h.client.Jar, _ = newJar()
	if r, _ := h.postForm(t, "/auth/password", url.Values{"username": {"admin"}, "password": {"forgotten pass"}}, nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("old password works: %d", r.StatusCode)
	}

	// Codes expire.
	code, _, _ = CreateResetCode(ctx, h.st, now)
	now = now.Add(ResetCodeTTL)
	if r, _ := reset(code, "another new pass", "another new pass", nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("expired code accepted: %d", r.StatusCode)
	}
	// Wrong codes are throttled like wrong passwords.
	for range loginFailMax {
		reset("AAAA-BBBB-CCCC", "another new pass", "another new pass", nil)
	}
	code, _, _ = CreateResetCode(ctx, h.st, now)
	if r, _ := reset(code, "another new pass", "another new pass", nil); r.StatusCode != http.StatusTooManyRequests {
		t.Errorf("throttled: %d", r.StatusCode)
	}
}

func TestSignedOutPageWithoutLogin(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.InsecureNoAuth, c.OIDCIssuer, c.OIDCClientID = true, "", "" })
	b := h.body(t, "/signin?signed-out=1")
	if !strings.Contains(b, `href="/"`) || strings.Contains(b, "/auth/login") || strings.Contains(b, "<form") {
		t.Errorf("no-auth signed-out page should only lead back to the app: %s", b)
	}
}
