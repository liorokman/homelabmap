package web

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/liorokman/homelabmap/internal/obs"
	"github.com/liorokman/homelabmap/internal/store"
)

const testToken = "0123456789abcdef0123456789abcdef-agent"

// fakeIdP is a minimal OpenID provider that enforces PKCE S256.
type fakeIdP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	mu     sync.Mutex
	codes  map[string]pendingCode
	groups []string
}

type pendingCode struct{ challenge, nonce string }

func newFakeIdP(t *testing.T) *fakeIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, codes: map[string]pendingCode{}, groups: []string{"homelabmap-users"}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		u := f.srv.URL
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": u, "authorization_endpoint": u + "/authorize", "token_endpoint": u + "/token",
			"jwks_uri": u + "/keys", "end_session_endpoint": u + "/logout",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		pc, ok := f.codes[r.Form.Get("code")]
		delete(f.codes, r.Form.Get("code"))
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != pc.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
		now := time.Now()
		idt, _ := jwt.Signed(signer).Claims(map[string]any{
			"iss": f.srv.URL, "sub": "user-1", "aud": "homelabmap", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
			"nonce": pc.nonce, "name": "Test User", "email": "test@example.invalid", "groups": f.groups,
		}).Serialize()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": idt, "expires_in": 3600})
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// authorize plays the user approving the login: it records the PKCE
// challenge and nonce from the authorization URL and returns a code.
func (f *fakeIdP) authorize(t *testing.T, authURL string) (code, state string) {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("authorization request without PKCE S256: %s", authURL)
	}
	if q.Get("nonce") == "" || q.Get("state") == "" {
		t.Fatalf("missing nonce/state: %s", authURL)
	}
	code = "code-" + q.Get("state")[:8]
	f.mu.Lock()
	f.codes[code] = pendingCode{challenge: q.Get("code_challenge"), nonce: q.Get("nonce")}
	f.mu.Unlock()
	return code, q.Get("state")
}

type harness struct {
	s      *Server
	st     *store.Store
	app    *httptest.Server
	agent  *httptest.Server
	client *http.Client
	idp    *fakeIdP
}

func newHarness(t *testing.T, mutate func(*Config)) *harness {
	t.Helper()
	idp := newFakeIdP(t)
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "homelabmap.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	h := &harness{st: st, idp: idp}
	// The app server must exist before its URL can go into the config.
	var handler http.Handler
	h.app = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(h.app.Close)
	pub, _ := url.Parse(h.app.URL)
	cfg := Config{
		PublicURL: pub, AgentToken: testToken, OIDCIssuer: idp.srv.URL, OIDCClientID: "homelabmap",
		OIDCScopes: []string{"openid", "profile", "email"}, SessionTTL: time.Hour,
		ScanInterval: time.Hour, Retention: 24 * time.Hour, OSRescan: time.Hour, OSScanMax: 10, ProbeMaxPerHour: 5,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	h.s = New(cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.s.auth.client = idp.srv.Client()
	h.s.longPoll = 200 * time.Millisecond
	handler = h.s.UIHandler()
	h.agent = httptest.NewServer(h.s.AgentHandler())
	t.Cleanup(h.agent.Close)

	jar, _ := cookiejar.New(nil)
	h.client = h.app.Client()
	h.client.Jar = jar
	h.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return h
}

func (h *harness) get(t *testing.T, path string) *http.Response {
	t.Helper()
	resp, err := h.client.Get(h.app.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// login runs the whole browser flow and returns the callback response.
func (h *harness) login(t *testing.T) *http.Response {
	t.Helper()
	resp := h.get(t, "/")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/signin") {
		t.Fatalf("unauthenticated / should go to the landing page, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// The landing page offers the sign-in link; follow it like a person would.
	resp = h.get(t, resp.Header.Get("Location"))
	body, _ := io.ReadAll(resp.Body)
	m := regexp.MustCompile(`href="(/auth/login\?[^"]+)"`).FindSubmatch(body)
	if resp.StatusCode != http.StatusOK || m == nil {
		t.Fatalf("landing page: %d %s", resp.StatusCode, body)
	}
	resp = h.get(t, html.UnescapeString(string(m[1])))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	code, state := h.idp.authorize(t, resp.Header.Get("Location"))
	return h.get(t, "/auth/callback?code="+code+"&state="+url.QueryEscape(state))
}

func TestOIDCLoginWithPKCE(t *testing.T) {
	h := newHarness(t, nil)
	if resp := h.get(t, "/api/status"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("API without session: %d", resp.StatusCode)
	}
	resp := h.login(t)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("callback: %d %s %s", resp.StatusCode, resp.Header.Get("Location"), b)
	}
	var sessCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-homelabmap" {
			sessCookie = c
		}
	}
	if sessCookie == nil || !sessCookie.HttpOnly || !sessCookie.Secure || sessCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie flags: %+v", sessCookie)
	}

	resp = h.get(t, "/api/status")
	var st statusResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil || st.User == nil || st.User.Name != "Test User" {
		t.Fatalf("status after login: %d %+v %v", resp.StatusCode, st, err)
	}
	if resp.Header.Get("Content-Security-Policy") == "" || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("security headers missing")
	}
}

func TestOIDCCallbackRejections(t *testing.T) {
	t.Run("state mismatch", func(t *testing.T) {
		h := newHarness(t, nil)
		resp := h.get(t, "/auth/login")
		code, _ := h.idp.authorize(t, resp.Header.Get("Location"))
		if r := h.get(t, "/auth/callback?code="+code+"&state=forged"); r.StatusCode != http.StatusForbidden {
			t.Errorf("forged state accepted: %d", r.StatusCode)
		}
	})
	t.Run("replayed callback", func(t *testing.T) {
		h := newHarness(t, nil)
		resp := h.get(t, "/auth/login")
		loginCookie := resp.Cookies()[0]
		code, state := h.idp.authorize(t, resp.Header.Get("Location"))
		cb := "/auth/callback?code=" + code + "&state=" + url.QueryEscape(state)
		if r := h.get(t, cb); r.StatusCode != http.StatusFound {
			t.Fatalf("first callback: %d", r.StatusCode)
		}
		// Re-send the same login cookie the browser already discarded.
		req, _ := http.NewRequest(http.MethodGet, h.app.URL+cb, nil)
		req.AddCookie(loginCookie)
		r, err := h.app.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusForbidden {
			t.Errorf("replay accepted: %d", r.StatusCode)
		}
	})
	t.Run("no login cookie", func(t *testing.T) {
		h := newHarness(t, nil)
		if r := h.get(t, "/auth/callback?code=x&state=y"); r.StatusCode != http.StatusForbidden {
			t.Errorf("callback without flow: %d", r.StatusCode)
		}
	})
	t.Run("group not allowed", func(t *testing.T) {
		h := newHarness(t, func(c *Config) { c.OIDCAllowedGroups = []string{"admins"} })
		if r := h.login(t); r.StatusCode != http.StatusForbidden {
			t.Errorf("user outside allowed groups logged in: %d", r.StatusCode)
		}
	})
	t.Run("group allowed", func(t *testing.T) {
		h := newHarness(t, func(c *Config) { c.OIDCAllowedGroups = []string{"admins", "homelabmap-users"} })
		if r := h.login(t); r.StatusCode != http.StatusFound {
			t.Errorf("allowed group refused: %d", r.StatusCode)
		}
	})
}

func TestSafeReturn(t *testing.T) {
	for in, want := range map[string]string{
		"/":                    "/",
		"/api/graph?x=1":       "/api/graph?x=1",
		"//evil.example":       "/",
		"/\\evil.example":      "/",
		"https://evil.example": "/",
		"":                     "/",
		"/ok\r\nSet-Cookie:":   "/",
	} {
		if got := safeReturn(in); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScanNowRequiresSameOrigin(t *testing.T) {
	h := newHarness(t, nil)
	h.login(t)
	post := func(origin string, header bool) int {
		req, _ := http.NewRequest(http.MethodPost, h.app.URL+"/api/scan", nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if header {
			req.Header.Set("X-Homelabmap-Request", "1")
		}
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := post("https://evil.example", true); c != http.StatusForbidden {
		t.Errorf("cross-origin scan request: %d", c)
	}
	if c := post(h.app.URL, false); c != http.StatusForbidden {
		t.Errorf("scan request without custom header: %d", c)
	}
	if c := post(h.app.URL, true); c != http.StatusAccepted {
		t.Errorf("same-origin scan request: %d", c)
	}
	if a, err := h.st.Active(context.Background()); err != nil || a.Trigger != "manual" {
		t.Errorf("manual scan not queued: %+v %v", a, err)
	}
}

func (h *harness) agentDo(t *testing.T, method, path, token string, body io.Reader, gz bool) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, h.agent.URL+path, body)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if gz {
		req.Header.Set("Content-Encoding", "gzip")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestAgentFlow(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()

	if r := h.agentDo(t, "GET", "/agent/v1/job", "wrong-token", nil, false); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", r.StatusCode)
	}
	if r := h.agentDo(t, "GET", "/agent/v1/job", testToken, nil, false); r.StatusCode != http.StatusNoContent {
		t.Fatalf("idle poll: %d", r.StatusCode)
	}

	sc, _, _ := h.st.Enqueue(ctx, "manual", time.Now())
	r := h.agentDo(t, "GET", "/agent/v1/job", testToken, nil, false)
	var job obs.Job
	if r.StatusCode != http.StatusOK || json.NewDecoder(r.Body).Decode(&job) != nil || job.ID != sc.ID || job.OSScanMax != 10 {
		t.Fatalf("job: %d %+v", r.StatusCode, job)
	}

	res := obs.Result{
		JobID: job.ID, StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(), Subnets: []string{"10.0.0.0/24"},
		Sweep: []obs.SweepHost{{IP: "10.0.0.1", MAC: "00:00:5e:00:00:01"}, {IP: "10.0.0.20", MAC: "00:00:5e:00:00:20"}},
		SNMP: []obs.SNMPDevice{{IP: "10.0.0.1", SysName: "gw", SysDescr: "RouterOS", SysObjectID: "1.3.6.1.4.1.14988.1",
			Forwarding: true, BridgeMAC: "00:00:5e:00:00:01",
			Interfaces: []obs.Interface{{Index: 2, Name: "ether2"}},
			FDB:        []obs.FDBEntry{{MAC: "00:00:5e:00:00:20", IfIndex: 2}}}},
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_ = json.NewEncoder(zw).Encode(res)
	zw.Close()

	// A result for a scan that isn't running is refused.
	wrong := res
	wrong.JobID = 999
	wb, _ := json.Marshal(wrong)
	if r := h.agentDo(t, "POST", "/agent/v1/result", testToken, bytes.NewReader(wb), false); r.StatusCode != http.StatusConflict {
		t.Errorf("result for unknown scan: %d", r.StatusCode)
	}
	if r := h.agentDo(t, "POST", "/agent/v1/result", testToken, &buf, true); r.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("result: %d %s", r.StatusCode, b)
	}

	h.login(t)
	gr := h.get(t, "/api/graph")
	var g struct {
		Nodes []struct{ Label, Location string }
	}
	if err := json.NewDecoder(gr.Body).Decode(&g); err != nil || len(g.Nodes) != 2 {
		t.Fatalf("graph: %+v %v", g, err)
	}

	// The next job asks to fingerprint the host whose OS is unknown.
	h.st.Enqueue(ctx, "manual", time.Now())
	r = h.agentDo(t, "GET", "/agent/v1/job", testToken, nil, false)
	job = obs.Job{}
	if json.NewDecoder(r.Body).Decode(&job) != nil || len(job.OSScanMACs) != 1 || job.OSScanMACs[0] != "00:00:5e:00:00:20" {
		t.Errorf("os scan targets: %+v", job)
	}
	if len(job.KnownMACs) != 2 {
		t.Errorf("known macs: %v", job.KnownMACs)
	}
}

func TestEmptyResultKeepsLastMap(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	sc, _, _ := h.st.Enqueue(ctx, "manual", time.Now())
	h.st.Claim(ctx, time.Now())
	b, _ := json.Marshal(obs.Result{JobID: sc.ID, Errors: []string{"sweep: nmap: permission denied"}})
	if r := h.agentDo(t, "POST", "/agent/v1/result", testToken, bytes.NewReader(b), false); r.StatusCode != http.StatusAccepted {
		t.Fatalf("empty result: %d", r.StatusCode)
	}
	recent, _ := h.st.Recent(ctx, 1)
	if recent[0].Status != store.StatusFailed || !strings.Contains(recent[0].Error, "permission denied") {
		t.Errorf("empty scan should fail with the scanner's reason: %+v", recent[0])
	}
}

func TestConfigValidation(t *testing.T) {
	base := map[string]string{
		"HOMELABMAP_PUBLIC_URL": "https://homelabmap.example", "HOMELABMAP_AGENT_TOKEN": testToken,
		"HOMELABMAP_OIDC_ISSUER": "https://idp.example/app/", "HOMELABMAP_OIDC_CLIENT_ID": "homelabmap",
	}
	set := func(t *testing.T, over map[string]string) {
		cleanEnv(t)
		for _, k := range []string{"HOMELABMAP_PUBLIC_URL", "HOMELABMAP_AGENT_TOKEN", "HOMELABMAP_OIDC_ISSUER", "HOMELABMAP_OIDC_CLIENT_ID", "HOMELABMAP_INSECURE_NO_AUTH", "HOMELABMAP_LISTEN", "HOMELABMAP_SCAN_INTERVAL", "HOMELABMAP_PROBE_MAX_PER_HOUR"} {
			t.Setenv(k, "")
		}
		for k, v := range base {
			t.Setenv(k, v)
		}
		for k, v := range over {
			t.Setenv(k, v)
		}
	}
	t.Run("valid", func(t *testing.T) {
		set(t, nil)
		if _, err := LoadConfig(); err != nil {
			t.Fatal(err)
		}
	})
	cases := map[string]map[string]string{
		"short agent token":        {"HOMELABMAP_AGENT_TOKEN": "short"},
		"http public url with sso": {"HOMELABMAP_PUBLIC_URL": "http://homelabmap.example"},
		"oidc issuer only":         {"HOMELABMAP_OIDC_CLIENT_ID": ""},
		"oidc client only":         {"HOMELABMAP_OIDC_ISSUER": ""},
		"http url with password":   {"HOMELABMAP_OIDC_ISSUER": "", "HOMELABMAP_OIDC_CLIENT_ID": "", "HOMELABMAP_PUBLIC_URL": "http://homelabmap.example"},
		"no-auth on all ifaces":    {"HOMELABMAP_INSECURE_NO_AUTH": "true", "HOMELABMAP_LISTEN": ":8080"},
		"scan interval too short":  {"HOMELABMAP_SCAN_INTERVAL": "10s"},
		"negative probe budget":    {"HOMELABMAP_PROBE_MAX_PER_HOUR": "-1"},
	}
	for name, over := range cases {
		t.Run(name, func(t *testing.T) {
			set(t, over)
			if _, err := LoadConfig(); err == nil {
				t.Error("expected an error")
			}
		})
	}
	t.Run("password login without oidc", func(t *testing.T) {
		set(t, map[string]string{"HOMELABMAP_OIDC_ISSUER": "", "HOMELABMAP_OIDC_CLIENT_ID": ""})
		c, err := LoadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if !c.PasswordLogin() {
			t.Error("password login expected without OIDC")
		}
	})
	t.Run("no-auth on loopback", func(t *testing.T) {
		set(t, map[string]string{"HOMELABMAP_INSECURE_NO_AUTH": "true", "HOMELABMAP_LISTEN": "127.0.0.1:8080",
			"HOMELABMAP_OIDC_ISSUER": "", "HOMELABMAP_PUBLIC_URL": "http://127.0.0.1:8080"})
		if _, err := LoadConfig(); err != nil {
			t.Fatal(err)
		}
	})
}

// postJSON sends v as the agent.
func (h *harness) postJSON(t *testing.T, path string, v any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(v)
	return h.agentDo(t, "POST", path, testToken, bytes.NewReader(b), false)
}

func TestPassiveSightingProbesNewDevice(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()

	// A first full scan establishes the map.
	sc, _, _ := h.st.Enqueue(ctx, "schedule", time.Now())
	h.st.Claim(ctx, time.Now())
	full := obs.Result{JobID: sc.ID, StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(),
		Sweep: []obs.SweepHost{{IP: "10.0.0.1", MAC: "00:00:5e:00:00:01"}},
		SNMP:  []obs.SNMPDevice{{IP: "10.0.0.1", SysName: "gw", Forwarding: true, BridgeMAC: "00:00:5e:00:00:01"}}}
	if r := h.postJSON(t, "/agent/v1/result", full); r.StatusCode != http.StatusNoContent {
		t.Fatalf("full result: %d", r.StatusCode)
	}

	// Junk is dropped; a known MAC and a new one are recorded.
	r := h.postJSON(t, "/agent/v1/sightings", obs.Sightings{Sightings: []obs.Sighting{
		{MAC: "00:00:5e:00:00:01", IP: "10.0.0.1", Via: "arp"},
		{MAC: "3C:7C:3F:00:00:42", IP: "10.0.0.42", Via: "arp"},
		{MAC: "3c:7c:3f:00:00:42", IP: "fe80::3e7c:3fff:fe00:42", Via: "ndp"},
		{MAC: "01:00:5e:00:00:01", IP: "10.0.0.9", Via: "arp"},
		{MAC: "3c:7c:3f:00:00:43", IP: "not-an-ip", Via: "arp"},
		{MAC: "3c:7c:3f:00:00:44", IP: "10.0.0.44", Via: "smoke-signals"},
	}})
	if r.StatusCode != http.StatusNoContent {
		t.Fatalf("sightings: %d", r.StatusCode)
	}

	// The scanner gets a probe for just the new device.
	r = h.agentDo(t, "GET", "/agent/v1/job", testToken, nil, false)
	var job obs.Job
	if json.NewDecoder(r.Body).Decode(&job) != nil || len(job.Probe) != 1 || job.Probe[0].MAC != "3c:7c:3f:00:00:42" ||
		len(job.Probe[0].IPs) != 1 || job.Probe[0].IPs[0] != "10.0.0.42" {
		t.Fatalf("probe job: %+v", job)
	}

	probe := obs.Result{JobID: job.ID, StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(), Probe: true,
		Sweep: []obs.SweepHost{{IP: "10.0.0.42", MAC: "3c:7c:3f:00:00:42", Vendor: "ASUSTek"}},
		DNS:   map[string]string{"10.0.0.42": "laptop.lan"}}
	if r := h.postJSON(t, "/agent/v1/result", probe); r.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("probe result: %d %s", r.StatusCode, b)
	}

	// The map now has both devices: the probe merged into the full scan.
	h.login(t)
	var g struct {
		Nodes []struct {
			Label string
			IPv6  []string
		}
	}
	if err := json.NewDecoder(h.get(t, "/api/graph").Body).Decode(&g); err != nil || len(g.Nodes) != 2 {
		t.Fatalf("graph after probe: %+v %v", g, err)
	}
	var laptop bool
	for _, n := range g.Nodes {
		if n.Label == "laptop" {
			laptop = len(n.IPv6) == 1
		}
	}
	if !laptop {
		t.Errorf("probed device missing or without its IPv6 address: %+v", g.Nodes)
	}

	var rows []store.SightingRow
	if err := json.NewDecoder(h.get(t, "/api/sightings").Body).Decode(&rows); err != nil || len(rows) != 3 {
		t.Errorf("sightings API: %+v %v", rows, err)
	}
	var st statusResponse
	if err := json.NewDecoder(h.get(t, "/api/status").Body).Decode(&st); err != nil || st.LastSightingAt == nil {
		t.Errorf("status lastSightingAt: %+v %v", st, err)
	}

	// Hearing the same device again doesn't probe it again.
	h.postJSON(t, "/agent/v1/sightings", obs.Sightings{Sightings: []obs.Sighting{{MAC: "3c:7c:3f:00:00:42", IP: "10.0.0.42", Via: "arp"}}})
	if r := h.agentDo(t, "GET", "/agent/v1/job", testToken, nil, false); r.StatusCode != http.StatusNoContent {
		t.Errorf("known device probed again: %d", r.StatusCode)
	}
}

func TestProbeWithoutAnswerKeepsMap(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	p, _, _ := h.st.EnqueueProbe(ctx, []obs.ProbeTarget{{MAC: "3c:7c:3f:00:00:42", IPs: []string{"10.0.0.42"}}}, 10, time.Now())
	h.st.Claim(ctx, time.Now())
	if r := h.postJSON(t, "/agent/v1/result", obs.Result{JobID: p.ID, Probe: true}); r.StatusCode != http.StatusAccepted {
		t.Fatalf("empty probe: %d", r.StatusCode)
	}
	sc, _ := h.st.Get(ctx, p.ID)
	if sc.Status != store.StatusFailed || !strings.Contains(sc.Error, "did not answer") {
		t.Errorf("probe status: %+v", sc)
	}
	// A full-scan result can't be passed off as a probe, or vice versa:
	// the job's trigger decides.
	full, _, _ := h.st.Enqueue(ctx, "manual", time.Now())
	h.st.Claim(ctx, time.Now())
	if r := h.postJSON(t, "/agent/v1/result", obs.Result{JobID: full.ID, Probe: true}); r.StatusCode != http.StatusAccepted {
		t.Errorf("empty full scan flagged as probe: %d", r.StatusCode)
	}
	if sc, _ := h.st.Get(ctx, full.ID); !strings.Contains(sc.Error, "no hosts") {
		t.Errorf("full scan handled as probe: %+v", sc)
	}
}

func TestSightingsLimits(t *testing.T) {
	h := newHarness(t, nil)
	many := make([]obs.Sighting, maxSightings+1)
	if r := h.postJSON(t, "/agent/v1/sightings", obs.Sightings{Sightings: many}); r.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized batch: %d", r.StatusCode)
	}
	if r := h.agentDo(t, "POST", "/agent/v1/sightings", testToken, strings.NewReader("{"), false); r.StatusCode != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", r.StatusCode)
	}
	if r := h.agentDo(t, "POST", "/agent/v1/sightings", "nope", strings.NewReader("{}"), false); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad token: %d", r.StatusCode)
	}
}

func TestLandingPageAndLogout(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.OIDCProviderName = "ExampleIdP" })
	resp := h.get(t, "/signin?return=%2F%23table%2Fheard")
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Sign in with ExampleIdP") ||
		!strings.Contains(string(body), `href="/auth/login?return=%2F%23table%2Fheard"`) {
		t.Fatalf("landing page: %d %s", resp.StatusCode, body)
	}
	// An open redirect can't be smuggled through the landing page.
	body, _ = io.ReadAll(h.get(t, "/signin?return=https%3A%2F%2Fevil.example%2F").Body)
	if strings.Contains(string(body), "evil.example") {
		t.Error("foreign return URL kept")
	}
	if b, _ := io.ReadAll(h.get(t, "/signin?signed-out=1").Body); !strings.Contains(string(b), "signed out") {
		t.Error("signed-out note missing")
	}

	h.login(t)
	// Signed in, the landing page moves on.
	if resp := h.get(t, "/signin?return=%2F"); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Errorf("signed-in landing: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	// The browser's logout form post: Origin may be "null", Sec-Fetch-Site decides.
	logout := func(hdr map[string]string) *http.Response {
		req, _ := http.NewRequest("POST", h.app.URL+"/auth/logout", nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	if r := logout(map[string]string{"Origin": "null", "Sec-Fetch-Site": "cross-site"}); r.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site logout: %d", r.StatusCode)
	}
	r := logout(map[string]string{"Origin": "null", "Sec-Fetch-Site": "same-origin"})
	if r.StatusCode != http.StatusSeeOther {
		t.Fatalf("same-origin logout: %d", r.StatusCode)
	}
	loc, _ := url.Parse(r.Header.Get("Location"))
	if !strings.HasSuffix(loc.Path, "/logout") || loc.Query().Get("client_id") != "homelabmap" ||
		!strings.HasSuffix(loc.Query().Get("post_logout_redirect_uri"), "/signin?signed-out=1") {
		t.Errorf("logout redirect: %s", loc)
	}
	if resp := h.get(t, "/api/status"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("session survived logout: %d", resp.StatusCode)
	}
}

// cleanEnv empties every HOMELABMAP_ variable for the test (restored after),
// so a developer's .env can't leak into config tests.
func cleanEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "HOMELABMAP_") {
			t.Setenv(k, "")
		}
	}
}
