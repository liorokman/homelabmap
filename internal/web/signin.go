package web

import (
	"html/template"
	"net/http"
	"net/url"
)

// Sign-in page modes.
const (
	modeOIDC     = "oidc"     // a button to the identity provider
	modePassword = "password" // username and password
	modeSetup    = "setup"    // first run: create the account
	modeReset    = "reset"    // forgot password: reset code from the command
	modeNoAuth   = "noauth"   // HOMELABMAP_INSECURE_NO_AUTH: nothing to sign in to
)

// signinView is what the sign-in page shows.
type signinView struct {
	Mode      string
	Return    string // local path to go to after signing in
	Provider  string
	SignedOut bool
	Error     string
	Username  string // kept in the form after a failed attempt
	LoginURL  string // OIDC mode: the sign-in link
}

// signinPage is the only page anonymous visitors see. It is self-contained
// (inline styles, no scripts) because the app's assets require a session.
var signinPage = template.Must(template.New("signin").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>homelabmap · Sign in</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%234f46e5' stroke-width='2' stroke-linecap='round'%3E%3Ccircle cx='12' cy='5' r='2.5'/%3E%3Ccircle cx='5' cy='19' r='2.5'/%3E%3Ccircle cx='19' cy='19' r='2.5'/%3E%3Cpath d='M12 7.5v4M12 11.5l-5.5 5.5M12 11.5l5.5 5.5'/%3E%3C/svg%3E">
<style>
:root { --bg: #f6f7f9; --surface: #fff; --text: #1b2130; --muted: #5d6778; --border: #dfe3ea; --accent: #4f46e5; --accent-ink: #fff; --ok: #15803d; --err: #b91c1c; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #11151c; --surface: #181d26; --text: #e6e9ef; --muted: #9aa3b2; --border: #2a313d; --accent: #818cf8; --accent-ink: #11151c; --ok: #4ade80; --err: #f87171; }
}
* { box-sizing: border-box; }
html, body { height: 100%; margin: 0; }
body { background: var(--bg); color: var(--text); font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  display: grid; place-items: center; padding: 16px; }
main { width: min(380px, 100%); background: var(--surface); border: 1px solid var(--border); border-radius: 14px;
  padding: 32px 28px; text-align: center; }
svg { width: 44px; height: 44px; fill: none; stroke: var(--accent); stroke-width: 2; stroke-linecap: round; }
h1 { margin: 10px 0 4px; font-size: 22px; letter-spacing: -.01em; }
p { margin: 0 0 22px; color: var(--muted); }
.note { color: var(--ok); margin: -8px 0 18px; font-size: 14px; }
.error { color: var(--err); margin: -8px 0 18px; font-size: 14px; }
.btn { display: block; width: 100%; padding: 11px 16px; border: 0; border-radius: 9px; background: var(--accent); color: var(--accent-ink);
  font: inherit; font-weight: 600; text-decoration: none; cursor: pointer; }
.btn:hover { filter: brightness(1.08); }
.btn:focus-visible, input:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
form { text-align: left; }
label { display: block; margin: 0 0 14px; font-size: 13.5px; font-weight: 600; }
input { display: block; width: 100%; margin-top: 5px; padding: 9px 11px; border: 1px solid var(--border); border-radius: 8px;
  background: var(--bg); color: var(--text); font: inherit; font-weight: 400; }
label small { margin-top: 4px; font-weight: 400; }
main small a { color: var(--accent); }
.steps { text-align: left; font-size: 13.5px; margin: 0 0 18px; }
.steps p { margin: 0 0 8px; color: var(--muted); }
pre, code { font: 12.5px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
pre { margin: 0 0 8px; padding: 8px 10px; background: var(--bg); border: 1px solid var(--border); border-radius: 8px;
  white-space: pre-wrap; word-break: break-all; color: var(--text); }
small { display: block; margin-top: 14px; color: var(--muted); font-size: 12.5px; }
</style>
</head>
<body>
<main>
  <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M12 7.5v4M12 11.5l-5.5 5.5M12 11.5l5.5 5.5"/></svg>
  <h1>homelabmap</h1>
  <p>{{if eq .Mode "setup"}}Create the account to sign in with{{else if eq .Mode "reset"}}Reset your password{{else}}Home network topology map{{end}}</p>
  {{if .SignedOut}}<div class="note" role="status">You have been signed out.</div>{{end}}
  {{if .Error}}<div class="error" role="alert">{{.Error}}</div>{{end}}
  {{if eq .Mode "oidc"}}
  <a class="btn" href="{{.LoginURL}}">Sign in{{if .Provider}} with {{.Provider}}{{end}}</a>
  <small>Access is limited to accounts allowed by the identity provider.</small>
  {{else if eq .Mode "noauth"}}
  <a class="btn" href="{{.Return}}">Continue</a>
  <small>Login is disabled (HOMELABMAP_INSECURE_NO_AUTH, development only).</small>
  {{else if eq .Mode "password"}}
  <form method="post" action="/auth/password">
    <input type="hidden" name="return" value="{{.Return}}">
    <label>Username <input name="username" value="{{.Username}}" autocomplete="username" required autofocus></label>
    <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
    <button class="btn" type="submit">Sign in</button>
  </form>
  <small><a href="/signin/forgot">Forgot password?</a></small>
  {{else if eq .Mode "reset"}}
  <div class="steps">
    <p>On the host running homelabmap, get a reset code:</p>
    <pre>docker compose exec web homelabmap-web reset-code</pre>
    <p>Not using Compose? <code>docker exec homelabmap-web homelabmap-web reset-code</code>, with your container's name. The code works once, for 15 minutes.</p>
  </div>
  <form method="post" action="/auth/reset">
    <label>Reset code <input name="reset_code" autocomplete="one-time-code" spellcheck="false" required autofocus></label>
    <label>New password <input name="password" type="password" autocomplete="new-password" required minlength="12">
      <small>At least 12 characters. All sessions are signed out.</small></label>
    <label>Repeat new password <input name="confirm" type="password" autocomplete="new-password" required minlength="12"></label>
    <button class="btn" type="submit">Reset password and sign in</button>
  </form>
  <small><a href="/signin">Back to sign in</a></small>
  {{else}}
  <form method="post" action="/auth/setup">
    <label>Setup code <input name="setup_code" autocomplete="off" spellcheck="false" required autofocus>
      <small>Printed in the homelabmap-web log, e.g. <code>docker compose logs homelabmap-web</code>.</small></label>
    <label>Username <input name="username" value="{{.Username}}" autocomplete="username" required maxlength="64"></label>
    <label>Password <input name="password" type="password" autocomplete="new-password" required minlength="12">
      <small>At least 12 characters.</small></label>
    <label>Repeat password <input name="confirm" type="password" autocomplete="new-password" required minlength="12"></label>
    <button class="btn" type="submit">Create account and sign in</button>
  </form>
  {{end}}
</main>
</body>
</html>
`))

// handleSignin shows the landing page, or sends a signed-in visitor on.
func (s *Server) handleSignin(w http.ResponseWriter, r *http.Request) {
	ret := safeReturn(r.URL.Query().Get("return"))
	if _, ok := s.currentUser(r); ok {
		http.Redirect(w, r, ret, http.StatusFound) //nolint:gosec // ret passed safeReturn: a local path
		return
	}
	s.renderSignin(w, r, ret, false)
}

func (s *Server) renderSignin(w http.ResponseWriter, r *http.Request, ret string, signedOut bool) {
	view := signinView{Mode: modeOIDC, Return: ret, Provider: s.cfg.OIDCProviderName, SignedOut: signedOut}
	if s.cfg.InsecureNoAuth {
		view.Mode = modeNoAuth
	} else if s.cfg.PasswordLogin() {
		view.Mode = modePassword
		exists, err := s.store.HasLocalUser(r.Context())
		if err != nil {
			s.serverError(w, "checking accounts", err)
			return
		}
		if !exists {
			view.Mode, view.SignedOut = modeSetup, false
		}
	}
	s.renderSigninView(w, http.StatusOK, view)
}

// handleForgot shows the reset form, while there is an account to reset.
func (s *Server) handleForgot(w http.ResponseWriter, r *http.Request) {
	exists, err := s.store.HasLocalUser(r.Context())
	if err != nil {
		s.serverError(w, "checking accounts", err)
		return
	}
	if !exists {
		http.Redirect(w, r, "/signin", http.StatusFound)
		return
	}
	s.renderSigninView(w, http.StatusOK, signinView{Mode: modeReset, Return: "/"})
}

func (s *Server) renderSigninView(w http.ResponseWriter, code int, v signinView) {
	if v.Mode == modeOIDC {
		v.LoginURL = "/auth/login?return=" + url.QueryEscape(v.Return)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = signinPage.Execute(w, v)
}
