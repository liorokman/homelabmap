package web

import (
	"html/template"
	"net/http"
	"net/url"
)

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
:root { --bg: #f6f7f9; --surface: #fff; --text: #1b2130; --muted: #5d6778; --border: #dfe3ea; --accent: #4f46e5; --accent-ink: #fff; --ok: #15803d; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #11151c; --surface: #181d26; --text: #e6e9ef; --muted: #9aa3b2; --border: #2a313d; --accent: #818cf8; --accent-ink: #11151c; --ok: #4ade80; }
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
a.btn { display: block; padding: 11px 16px; border-radius: 9px; background: var(--accent); color: var(--accent-ink);
  font-weight: 600; text-decoration: none; }
a.btn:hover { filter: brightness(1.08); }
a.btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
small { display: block; margin-top: 14px; color: var(--muted); font-size: 12.5px; }
</style>
</head>
<body>
<main>
  <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="19" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="M12 7.5v4M12 11.5l-5.5 5.5M12 11.5l5.5 5.5"/></svg>
  <h1>homelabmap</h1>
  <p>Home network topology map</p>
  {{if .SignedOut}}<div class="note" role="status">You have been signed out.</div>{{end}}
  <a class="btn" href="{{.LoginURL}}">Sign in{{if .Provider}} with {{.Provider}}{{end}}</a>
  <small>Access is limited to accounts allowed by the identity provider.</small>
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
	s.renderSignin(w, ret, false)
}

func (s *Server) renderSignin(w http.ResponseWriter, ret string, signedOut bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = signinPage.Execute(w, map[string]any{
		"LoginURL":  "/auth/login?return=" + url.QueryEscape(ret),
		"Provider":  s.cfg.OIDCProviderName,
		"SignedOut": signedOut,
	})
}
