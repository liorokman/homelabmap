package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
	"github.com/liorokman/homelabmap/internal/store"
)

func TestDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"14d": 14 * 24 * time.Hour, "90m": 90 * time.Minute, " 1h30m ": 90 * time.Minute, "1500ms": 1500 * time.Millisecond} {
		if got, err := parseDuration(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "x", "-1d", "1.5d", "9999d"} {
		if _, err := parseDuration(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for d, want := range map[time.Duration]string{14 * 24 * time.Hour: "14d", 36 * time.Hour: "36h", 90 * time.Minute: "90m", 1500 * time.Millisecond: "1.5s"} {
		if got := Duration(d).String(); got != want {
			t.Errorf("%v: %q", d, got)
		}
	}
	var d Duration
	if json.Unmarshal([]byte(`3600`), &d) == nil {
		t.Error("number accepted as a duration")
	}
}

func TestTargetURL(t *testing.T) {
	for in, want := range map[string]string{
		"pve.example.net":                  "https://pve.example.net:8006",
		"pve.example.net:8443":             "https://pve.example.net:8443",
		"192.0.2.5":                        "https://192.0.2.5:8006",
		"2001:db8::5":                      "https://[2001:db8::5]:8006",
		"https://pve.example.net:8006/":    "https://pve.example.net:8006",
		"http://cosmos.example.net/prefix": "http://cosmos.example.net/prefix",
	} {
		if got, err := targetURL(in, 8006); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	if got, _ := targetURL("unifi.example.net", 443); got != "https://unifi.example.net" {
		t.Errorf("default https port: %q", got)
	}
	for _, bad := range []string{"", "bad host", "ftp://x.example", "https://user:pw@x.example", "x.example:99999", "https://x.example/?q=1", "-x.example"} {
		if _, err := targetURL(bad, 443); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func validSettings() *Settings {
	s := defaultSettings(Config{ScanInterval: time.Hour, Retention: 24 * time.Hour, ForgetAfter: 24 * time.Hour,
		OSRescan: 24 * time.Hour, OSScanMax: 10, ProbeMaxPerHour: 5, SessionTTL: time.Hour})
	s.Scan.Subnets = []string{"192.0.2.0/24"}
	s.SNMP.Default = SNMPCred{Version: "2c", Community: "public"}
	s.SNMP.Hosts = []SNMPHostEntry{{Match: "192.0.2.10", Credentials: SNMPCred{Version: "3", User: "admin", AuthPass: "authpass1", PrivPass: "privpass1"}}}
	s.Proxmox = []ProxmoxEntry{{Host: "pve.example.net", TokenID: "homelabmap@pve!scanner", TokenSecret: "pve-secret"}}
	s.UniFi = []UniFiEntry{{Host: "unifi.example.net", APIKey: "unifi-key", HistoryHours: 720}}
	s.Cosmos = []CosmosEntry{{Host: "cosmos.example.net", Token: "cosmos-token"}}
	return &s
}

func TestValidate(t *testing.T) {
	s := validSettings()
	s.normalise()
	if errs := s.validate(); len(errs) != 0 {
		t.Fatalf("valid settings: %+v", errs)
	}
	longest := strings.Repeat("é", maxDescription)
	s.UniFi[0].Description = " " + longest + " "
	s.normalise()
	if s.UniFi[0].Description != longest || len(s.validate()) != 0 {
		t.Errorf("a %d-character description should be trimmed and allowed", maxDescription)
	}
	if s.UniFi[0].Site != "default" || s.SNMP.Hosts[0].Credentials.AuthProto != "SHA" || s.SNMP.Hosts[0].ID == "" {
		t.Errorf("defaults not filled: %+v %+v", s.UniFi[0], s.SNMP.Hosts[0])
	}

	b := validSettings()
	b.Scan.Subnets = []string{"192.0.2.0/24", "not-a-subnet"}
	b.Scan.Interval = Duration(time.Minute)
	b.SNMP.Default = SNMPCred{Version: "2c"}
	b.SNMP.Seeds = []string{"x"}
	b.SNMP.Hosts = append(b.SNMP.Hosts, SNMPHostEntry{Match: "192.0.2.10", Credentials: SNMPCred{Version: "3", User: "u", PrivPass: "p"}},
		SNMPHostEntry{Match: "bad host!", Credentials: SNMPCred{}})
	b.Proxmox[0].TokenID = "no-realm"
	b.Proxmox = append(b.Proxmox, ProxmoxEntry{Host: "pve.example.net:8006", TokenID: "a@pve!b", TokenSecret: "s"}) // same URL
	b.UniFi[0].APIKey = ""
	b.UniFi[0].Description = strings.Repeat("é", maxDescription+1)
	b.Cosmos[0].Host = "ftp://cosmos.example.net"
	b.Cosmos = append(b.Cosmos, CosmosEntry{ID: "dup", Host: "c2.example.net", Token: "t"}, CosmosEntry{ID: "dup", Host: "c3.example.net", Token: "t"})
	b.normalise()
	var fields []string
	for _, e := range b.validate() {
		fields = append(fields, e.Field)
	}
	for _, want := range []string{"cosmos", "scan.subnets", "scan.interval", "snmp.default.community", "snmp.seeds", ".match", ".authPass", ".version", ".tokenId", ".host", ".apiKey", ".description"} {
		if !slices.ContainsFunc(fields, func(f string) bool { return strings.HasSuffix(f, want) || f == want }) {
			t.Errorf("no error for %s: %v", want, fields)
		}
	}
}

func TestSecretsAtRest(t *testing.T) {
	box, _ := newSecretBox(testToken)
	s := validSettings()
	s.normalise()
	doc, err := box.encode(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"public", "authpass1", "privpass1", "pve-secret", "unifi-key", "cosmos-token"} {
		if strings.Contains(doc, secret) {
			t.Errorf("%q stored in clear text", secret)
		}
	}
	back, err := box.decode(doc)
	if err != nil || back.Proxmox[0].TokenSecret != "pve-secret" || back.SNMP.Hosts[0].Credentials.PrivPass != "privpass1" || len(back.lost) != 0 {
		t.Fatalf("round trip: %+v %v", back, err)
	}
	// Ciphertexts are bound to their field.
	var raw Settings
	_ = json.Unmarshal([]byte(doc), &raw)
	raw.UniFi[0].APIKey, raw.Cosmos[0].Token = raw.Cosmos[0].Token, raw.UniFi[0].APIKey
	swapped, _ := json.Marshal(raw)
	if back, _ := box.decode(string(swapped)); back.UniFi[0].APIKey != "" || len(back.lost) != 2 {
		t.Errorf("swapped ciphertexts decrypted: %+v", back.lost)
	}
	// Another agent token can't read them.
	other, _ := newSecretBox("another-agent-token-0123456789abcdef")
	if back, _ := other.decode(doc); back.Proxmox[0].TokenSecret != "" || len(back.lost) != 6 {
		t.Errorf("other key: %+v", back.lost)
	}
	if _, err := box.decode("{"); err == nil {
		t.Error("bad JSON accepted")
	}
}

func (h *harness) settingsReq(t *testing.T, method string, body any, hdr map[string]string) (int, map[string]any, string) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.app.URL+"/api/settings", rd)
	req.Header.Set("X-Homelabmap-Request", "1")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out, string(raw)
}

// pageSettings is what the page has: the redacted settings.
func pageSettings(t *testing.T, out map[string]any) *Settings {
	t.Helper()
	b, _ := json.Marshal(out["settings"])
	var s Settings
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

func TestSettingsAPI(t *testing.T) {
	h := newPasswordHarness(t)
	signIn(t, h)

	code, out, raw := h.settingsReq(t, "GET", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("get: %d %s", code, raw)
	}
	page := pageSettings(t, out)
	page.SNMP.Default = SNMPCred{Version: "2c", Community: "public"}
	page.Proxmox = []ProxmoxEntry{{Host: "pve.example.net", TokenID: "homelabmap@pve!scanner", TokenSecret: "pve-secret"}}
	page.UniFi = []UniFiEntry{{Host: "unifi.example.net", APIKey: "unifi-key", HistoryHours: 24}}

	if code, _, _ := h.settingsReq(t, "PUT", page, map[string]string{"Sec-Fetch-Site": "cross-site"}); code != http.StatusForbidden {
		t.Errorf("cross-site save: %d", code)
	}
	code, out, raw = h.settingsReq(t, "PUT", page, nil)
	if code != http.StatusOK {
		t.Fatalf("save: %d %s", code, raw)
	}
	for _, secret := range []string{"public", "pve-secret", "unifi-key"} {
		if strings.Contains(raw, secret) {
			t.Errorf("%q sent back to the browser", secret)
		}
	}
	page = pageSettings(t, out)
	if page.Proxmox[0].TokenSecret != keepSecret || page.Proxmox[0].ID == "" || page.UniFi[0].Site != "default" {
		t.Fatalf("saved page: %+v", page)
	}

	// Saving the page as is keeps the secrets; an empty one clears it; a
	// new value replaces it.
	page.UniFi[0].APIKey = "new-unifi-key"
	page.SNMP.Default.Community = ""
	if code, _, raw := h.settingsReq(t, "PUT", page, nil); code != http.StatusBadRequest || !strings.Contains(raw, "snmp.default.community") {
		t.Errorf("cleared required secret: %d %s", code, raw)
	}
	page.SNMP.Default = SNMPCred{}
	code, _, raw = h.settingsReq(t, "PUT", page, nil)
	if code != http.StatusOK {
		t.Fatalf("second save: %d %s", code, raw)
	}
	cur := h.s.settings()
	if cur.Proxmox[0].TokenSecret != "pve-secret" || cur.UniFi[0].APIKey != "new-unifi-key" || cur.SNMP.Default.Version != "" {
		t.Errorf("secrets after save: %+v %+v %+v", cur.Proxmox[0], cur.UniFi[0], cur.SNMP.Default)
	}

	// A stale page can't overwrite newer settings.
	if code, _, _ := h.settingsReq(t, "PUT", page, nil); code != http.StatusConflict {
		t.Errorf("stale save: %d", code)
	}
	if code, _, _ := h.settingsReq(t, "PUT", map[string]any{"version": cur.Version, "bogus": 1}, nil); code != http.StatusBadRequest {
		t.Errorf("unknown field: %d", code)
	}

	// The scanner gets the secrets, in clear text, with the URLs built.
	resp := h.agentDo(t, "GET", "/agent/v1/settings", testToken, nil, false)
	var ss obs.ScannerSettings
	if err := json.NewDecoder(resp.Body).Decode(&ss); err != nil || len(ss.Proxmox) != 1 || ss.Proxmox[0].URL != "https://pve.example.net:8006" ||
		ss.Proxmox[0].TokenSecret != "pve-secret" || ss.UniFi[0].APIKey != "new-unifi-key" || ss.SNMP.Default != nil {
		t.Errorf("scanner settings: %+v %v", ss, err)
	}
	if r := h.agentDo(t, "GET", "/agent/v1/settings", "wrong", nil, false); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("settings without the agent token: %d", r.StatusCode)
	}

	// The settings survive a restart, and a different agent token loses
	// the secrets (and says so).
	again, err := New(h.s.cfg, h.st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil || again.settings().Proxmox[0].TokenSecret != "pve-secret" || again.settings().Version != cur.Version {
		t.Fatalf("reloaded: %+v %v", again.settings(), err)
	}
	cfg := h.s.cfg
	cfg.AgentToken = "a-different-agent-token-0123456789ab"
	rotated, err := New(cfg, h.st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil || rotated.settings().Proxmox[0].TokenSecret != "" || len(rotated.settings().lost) != 2 {
		t.Errorf("rotated token: %+v %v", rotated.settings().lost, err)
	}
	if body := rotated.settingsBody(rotated.settings()); len(body.Lost) != 2 {
		t.Errorf("lost secrets not reported: %+v", body)
	}
}

func signIn(t *testing.T, h *harness) {
	t.Helper()
	if err := h.st.CreateFirstLocalUser(context.Background(), store.LocalUser{Username: "admin", PasswordHash: hashPassword("a long password", cheapArgon), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if r, _ := h.postForm(t, "/auth/password", map[string][]string{"username": {"admin"}, "password": {"a long password"}}, nil); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("sign in: %d", r.StatusCode)
	}
}

func TestSettingsAdminsOnly(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.OIDCAdminGroups = []string{"homelabmap-admins"} })
	h.login(t)
	var st statusResponse
	_ = json.NewDecoder(h.get(t, "/api/status").Body).Decode(&st)
	if st.User == nil || st.User.Admin {
		t.Errorf("a non-admin is reported as admin: %+v", st.User)
	}
	if code, _, _ := h.settingsReq(t, "GET", nil, nil); code != http.StatusForbidden {
		t.Errorf("non-admin get: %d", code)
	}
	if code, _, _ := h.settingsReq(t, "PUT", map[string]any{}, nil); code != http.StatusForbidden {
		t.Errorf("non-admin put: %d", code)
	}
	h.idp.groups = []string{"homelabmap-users", "homelabmap-admins"}
	h.client.Jar, _ = newJar()
	h.login(t)
	if code, _, raw := h.settingsReq(t, "GET", nil, nil); code != http.StatusOK {
		t.Errorf("admin get: %d %s", code, raw)
	}

	// Without admin groups, everyone who signs in is an admin.
	open := newHarness(t, nil)
	open.login(t)
	if code, _, _ := open.settingsReq(t, "GET", nil, nil); code != http.StatusOK {
		t.Errorf("no admin groups: %d", code)
	}
}

func TestLegacyImport(t *testing.T) {
	h := newHarness(t, nil)
	h.changeSettings(t, func(s *Settings) {
		s.UniFi = []UniFiEntry{{ID: "u1", Host: "unifi.example.net", APIKey: "kept", Site: "default"}}
	})
	legacy := obs.LegacySettings{
		Set: []string{"HOMELABMAP_SUBNETS", "HOMELABMAP_SNMP_COMMUNITY", "HOMELABMAP_PVE_URL", "HOMELABMAP_UNIFI_URL", "HOMELABMAP_SSDP"},
		Settings: obs.ScannerSettings{
			Subnets: []string{"198.51.100.0/24"}, SSDP: false,
			SNMP:    obs.SNMPSettings{Default: &obs.SNMPCredentials{Version: "2c", Community: "from-env"}},
			Proxmox: []obs.ProxmoxTarget{{URL: "https://pve.example.net:8006", TokenID: "a@pve!b", TokenSecret: "env-secret"}},
			UniFi:   []obs.UniFiTarget{{URL: "https://other.example.net", APIKey: "env-key"}},
		},
	}
	post := func() map[string]bool {
		resp := h.postJSON(t, "/agent/v1/legacy-settings", legacy)
		var out map[string]bool
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out
	}
	if out := post(); !out["imported"] {
		t.Fatalf("first import: %+v", out)
	}
	s := h.s.settings()
	// Only empty settings are filled: the subnets and UniFi were set.
	if !slices.Equal(s.Scan.Subnets, []string{"192.0.2.0/24"}) || len(s.UniFi) != 1 || s.UniFi[0].APIKey != "kept" {
		t.Errorf("overwrote settings: %+v %+v", s.Scan.Subnets, s.UniFi)
	}
	if s.SNMP.Default.Community != "from-env" || len(s.Proxmox) != 1 || s.Proxmox[0].TokenSecret != "env-secret" || s.Scan.SSDP {
		t.Errorf("not imported: %+v %+v ssdp=%v", s.SNMP.Default, s.Proxmox, s.Scan.SSDP)
	}
	// Once only, even after a restart and with the settings emptied.
	h.changeSettings(t, func(s *Settings) { s.Proxmox = nil })
	again, err := New(h.s.cfg, h.st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil || !again.settings().scannerImported {
		t.Fatalf("import flag lost: %v", err)
	}
	if out := post(); out["imported"] || len(h.s.settings().Proxmox) != 0 {
		t.Errorf("imported twice: %+v %+v", out, h.s.settings().Proxmox)
	}
}

func TestJobsCarrySettingsAndNeedSubnets(t *testing.T) {
	h := newHarness(t, nil)
	h.changeSettings(t, func(s *Settings) {
		s.SNMP.Default = SNMPCred{Version: "2c", Community: "public"}
		s.Scan.OSScanMax = 3
	})
	ctx := context.Background()
	if _, _, err := h.st.Enqueue(ctx, "manual", time.Now()); err != nil {
		t.Fatal(err)
	}
	resp := h.agentDo(t, "GET", "/agent/v1/job", testToken, nil, false)
	var job obs.Job
	if err := json.NewDecoder(resp.Body).Decode(&job); err != nil || job.Settings == nil ||
		!slices.Equal(job.Settings.Subnets, []string{"192.0.2.0/24"}) || job.Settings.SNMP.Default.Community != "public" || job.OSScanMax != 3 {
		t.Fatalf("job: %+v %v", job, err)
	}

	// No subnets: nothing to scan, and the UI is told.
	h.changeSettings(t, func(s *Settings) { s.Scan.Subnets = nil })
	h.login(t)
	var st statusResponse
	_ = json.NewDecoder(h.get(t, "/api/status").Body).Decode(&st)
	if !st.NeedsSubnets {
		t.Error("status should ask for subnets")
	}
	req, _ := http.NewRequest("POST", h.app.URL+"/api/scan", nil)
	req.Header.Set("X-Homelabmap-Request", "1")
	r, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusConflict {
		t.Errorf("scan without subnets: %d", r.StatusCode)
	}
}
