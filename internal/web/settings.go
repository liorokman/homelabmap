package web

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/liorokman/homelabmap/internal/obs"
)

// Settings is everything on the Settings page: what to scan, the
// credentials, and the schedule. It is stored in the database with its
// secrets encrypted; the environment only supplies the first values
// (OIDC, addresses and the agent token stay in the environment).
type Settings struct {
	Version int64          `json:"version"`
	Scan    ScanSettings   `json:"scan"`
	Login   LoginSettings  `json:"login"`
	SNMP    SNMPSettings   `json:"snmp"`
	Proxmox []ProxmoxEntry `json:"proxmox"`
	UniFi   []UniFiEntry   `json:"unifi"`
	Cosmos  []CosmosEntry  `json:"cosmos"`

	// scannerImported: the scanner's environment was imported once.
	scannerImported bool
	// lost are secrets that couldn't be decrypted (the agent token changed).
	lost []string
}

type ScanSettings struct {
	Subnets         []string `json:"subnets"`
	Interval        Duration `json:"interval"`
	Retention       Duration `json:"retention"`
	ForgetAfter     Duration `json:"forgetAfter"`
	OSRescan        Duration `json:"osRescan"`
	OSScanMax       int      `json:"osScanMax"`
	ProbeMaxPerHour int      `json:"probeMaxPerHour"`
	JobTimeout      Duration `json:"jobTimeout"`
	Passive         bool     `json:"passive"`
	SSDP            bool     `json:"ssdp"`
}

type LoginSettings struct {
	SessionTTL Duration `json:"sessionTtl"`
}

type SNMPSettings struct {
	// Default applies to hosts no override matches; Version "" = none.
	Default     SNMPCred        `json:"default"`
	Hosts       []SNMPHostEntry `json:"hosts"`
	Seeds       []string        `json:"seeds"`
	Timeout     Duration        `json:"timeout"`
	Retries     int             `json:"retries"`
	Concurrency int             `json:"concurrency"`
}

// SNMPCred is a v2c community or a v3 user. Community, AuthPass and
// PrivPass are secrets.
type SNMPCred struct {
	Version   string `json:"version"`
	Community string `json:"community"`
	User      string `json:"user"`
	AuthProto string `json:"authProto"`
	AuthPass  string `json:"authPass"`
	PrivProto string `json:"privProto"`
	PrivPass  string `json:"privPass"`
}

// SNMPHostEntry overrides the credentials for an IP, CIDR or hostname.
type SNMPHostEntry struct {
	ID          string   `json:"id"`
	Match       string   `json:"match"`
	Description string   `json:"description"`
	Credentials SNMPCred `json:"credentials"`
}

// ProxmoxEntry is one Proxmox VE cluster, reached at Host (a hostname or
// IP with an optional port, default 8006, or a full URL).
type ProxmoxEntry struct {
	ID          string `json:"id"`
	Host        string `json:"host"`
	Description string `json:"description"`
	TokenID     string `json:"tokenId"`
	TokenSecret string `json:"tokenSecret"`
	InsecureTLS bool   `json:"insecureTls"`
}

// UniFiEntry is one UniFi OS console (default port 443).
type UniFiEntry struct {
	ID           string `json:"id"`
	Host         string `json:"host"`
	Description  string `json:"description"`
	APIKey       string `json:"apiKey"`
	Site         string `json:"site"`
	InsecureTLS  bool   `json:"insecureTls"`
	HistoryHours int    `json:"historyHours"`
}

// CosmosEntry is one Cosmos server (default port 443).
type CosmosEntry struct {
	ID          string `json:"id"`
	Host        string `json:"host"`
	Description string `json:"description"`
	Token       string `json:"token"`
	InsecureTLS bool   `json:"insecureTls"`
}

// Duration is a time.Duration written like "90m", "12h" or "14d".
type Duration time.Duration

func (d Duration) D() time.Duration { return time.Duration(d) }

func (d Duration) String() string {
	t := time.Duration(d)
	switch {
	case t >= 24*time.Hour && t%(24*time.Hour) == 0:
		return strconv.FormatInt(int64(t/(24*time.Hour)), 10) + "d"
	case t >= time.Hour && t%time.Hour == 0:
		return strconv.FormatInt(int64(t/time.Hour), 10) + "h"
	case t >= time.Minute && t%time.Minute == 0:
		return strconv.FormatInt(int64(t/time.Minute), 10) + "m"
	}
	return t.String()
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New(`durations are strings such as "30m", "12h" or "14d"`)
	}
	v, err := parseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// parseDuration is time.ParseDuration plus whole days ("14d").
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil || days < 0 || days > 3650 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q (use e.g. 30m, 12h or 14d)", s)
	}
	return v, nil
}

// defaultSettings are the first settings: the environment's values (or
// their defaults) from Config, and the scanner's old defaults.
func defaultSettings(cfg Config) Settings {
	or := func(d, def time.Duration) time.Duration {
		if d <= 0 {
			return def
		}
		return d
	}
	cfg.ScanInterval, cfg.Retention = or(cfg.ScanInterval, time.Hour), or(cfg.Retention, 14*24*time.Hour)
	cfg.ForgetAfter, cfg.OSRescan = or(cfg.ForgetAfter, 30*24*time.Hour), or(cfg.OSRescan, 7*24*time.Hour)
	cfg.SessionTTL = or(cfg.SessionTTL, 12*time.Hour)
	return Settings{
		Scan: ScanSettings{
			Interval: Duration(cfg.ScanInterval), Retention: Duration(cfg.Retention),
			ForgetAfter: Duration(cfg.ForgetAfter), OSRescan: Duration(cfg.OSRescan),
			OSScanMax: cfg.OSScanMax, ProbeMaxPerHour: cfg.ProbeMaxPerHour,
			JobTimeout: Duration(15 * time.Minute), Passive: true, SSDP: true,
		},
		Login: LoginSettings{SessionTTL: Duration(cfg.SessionTTL)},
		SNMP:  SNMPSettings{Timeout: Duration(1500 * time.Millisecond), Retries: 1, Concurrency: 48},
	}
}

// clone returns a deep copy, so a stored *Settings is never modified.
func (s *Settings) clone() *Settings {
	c := *s
	c.Scan.Subnets = slices.Clone(s.Scan.Subnets)
	c.SNMP.Hosts = slices.Clone(s.SNMP.Hosts)
	c.SNMP.Seeds = slices.Clone(s.SNMP.Seeds)
	c.Proxmox = slices.Clone(s.Proxmox)
	c.UniFi = slices.Clone(s.UniFi)
	c.Cosmos = slices.Clone(s.Cosmos)
	c.lost = slices.Clone(s.lost)
	return &c
}

// secrets maps a stable path ("unifi.<id>.apiKey") to every secret field.
// Paths name the entry by ID, so a secret follows its entry when the list
// is reordered.
func (s *Settings) secrets() map[string]*string {
	m := map[string]*string{}
	cred := func(prefix string, c *SNMPCred) {
		m[prefix+".community"], m[prefix+".authPass"], m[prefix+".privPass"] = &c.Community, &c.AuthPass, &c.PrivPass
	}
	cred("snmp.default", &s.SNMP.Default)
	for i := range s.SNMP.Hosts {
		cred("snmp.hosts."+s.SNMP.Hosts[i].ID, &s.SNMP.Hosts[i].Credentials)
	}
	for i := range s.Proxmox {
		m["proxmox."+s.Proxmox[i].ID+".tokenSecret"] = &s.Proxmox[i].TokenSecret
	}
	for i := range s.UniFi {
		m["unifi."+s.UniFi[i].ID+".apiKey"] = &s.UniFi[i].APIKey
	}
	for i := range s.Cosmos {
		m["cosmos."+s.Cosmos[i].ID+".token"] = &s.Cosmos[i].Token
	}
	return m
}

// keepSecret stands for "unchanged" in the API: the browser never sees a
// secret, it gets this instead and sends it back to keep the value.
const keepSecret = "__keep__"

// redacted is a copy safe to send to the browser.
func (s *Settings) redacted() *Settings {
	c := s.clone()
	for _, p := range c.secrets() {
		if *p != "" {
			*p = keepSecret
		}
	}
	return c
}

// keepSecrets replaces keepSecret in an edited copy with the current
// values. A secret whose entry is new, or whose current value is unknown,
// becomes empty.
func (s *Settings) keepSecrets(cur *Settings) {
	old := cur.secrets()
	for path, p := range s.secrets() {
		if *p == keepSecret {
			*p = ""
			if o, ok := old[path]; ok {
				*p = *o
			}
		}
	}
}

// newID names a list entry; IDs keep secrets tied to their entry.
func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// normalise trims fields, fills in defaults and IDs.
func (s *Settings) normalise() {
	trimList := func(l []string) []string {
		var out []string
		for _, v := range l {
			if v = strings.TrimSpace(v); v != "" && !slices.Contains(out, v) {
				out = append(out, v)
			}
		}
		return out
	}
	s.Scan.Subnets = trimList(s.Scan.Subnets)
	for i, v := range s.Scan.Subnets {
		if p, err := netip.ParsePrefix(v); err == nil {
			s.Scan.Subnets[i] = p.Masked().String()
		}
	}
	s.SNMP.Seeds = trimList(s.SNMP.Seeds)
	normCred := func(c *SNMPCred) {
		c.Version, c.User = strings.TrimSpace(c.Version), strings.TrimSpace(c.User)
		c.AuthProto, c.PrivProto = strings.ToUpper(strings.TrimSpace(c.AuthProto)), strings.ToUpper(strings.TrimSpace(c.PrivProto))
		switch c.Version {
		case "2c":
			c.User, c.AuthProto, c.AuthPass, c.PrivProto, c.PrivPass = "", "", "", "", ""
		case "3":
			c.Community = ""
			if c.AuthProto == "" {
				c.AuthProto = "SHA"
			}
			if c.PrivProto == "" {
				c.PrivProto = "AES"
			}
		default:
			*c = SNMPCred{}
		}
	}
	normCred(&s.SNMP.Default)
	for i := range s.SNMP.Hosts {
		h := &s.SNMP.Hosts[i]
		h.Match = strings.ToLower(strings.TrimSpace(h.Match))
		h.Description = strings.TrimSpace(h.Description)
		normCred(&h.Credentials)
		if h.ID == "" {
			h.ID = newID()
		}
	}
	for i := range s.Proxmox {
		e := &s.Proxmox[i]
		e.Host, e.TokenID = strings.TrimSpace(e.Host), strings.TrimSpace(e.TokenID)
		e.Description = strings.TrimSpace(e.Description)
		if e.ID == "" {
			e.ID = newID()
		}
	}
	for i := range s.UniFi {
		e := &s.UniFi[i]
		e.Host, e.Site = strings.TrimSpace(e.Host), strings.TrimSpace(e.Site)
		e.Description = strings.TrimSpace(e.Description)
		if e.Site == "" {
			e.Site = "default"
		}
		if e.ID == "" {
			e.ID = newID()
		}
	}
	for i := range s.Cosmos {
		e := &s.Cosmos[i]
		e.Host = strings.TrimSpace(e.Host)
		e.Description = strings.TrimSpace(e.Description)
		if e.ID == "" {
			e.ID = newID()
		}
	}
}

// maxDescription caps an entry's description, in characters.
const maxDescription = 200

// FieldError is a validation problem, with the field it is about.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

var (
	hostnameRe = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	tokenIDRe  = regexp.MustCompile(`^[^@!\s]+@[^@!\s]+![^@!\s]+$`)
	idRe       = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
	authProtos = []string{"MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"}
	privProtos = []string{"DES", "AES", "AES192", "AES256"}
)

func validHostname(h string) bool {
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	return len(h) <= 253 && hostnameRe.MatchString(h)
}

// targetURL turns an entry's Host into the URL the scanner uses: a full
// http(s) URL as given, or https://host[:port] with defPort if none.
func targetURL(host string, defPort int) (string, error) {
	if strings.Contains(host, "://") {
		u, err := url.Parse(host)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || !validHostname(u.Hostname()) ||
			u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return "", errors.New("use a hostname such as pve.example.net, hostname:port, or an http(s) URL")
		}
		return strings.TrimRight(u.String(), "/"), nil
	}
	h, port := host, ""
	if hh, p, err := net.SplitHostPort(host); err == nil {
		h, port = hh, p
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("invalid port %q", p)
		}
	}
	if h == "" || !validHostname(h) {
		return "", errors.New("use a hostname such as pve.example.net, hostname:port, or an http(s) URL")
	}
	if port == "" && defPort != 443 {
		port = strconv.Itoa(defPort)
	}
	if port == "" {
		return "https://" + bracket(h), nil
	}
	return "https://" + net.JoinHostPort(h, port), nil
}

func bracket(h string) string {
	if a, err := netip.ParseAddr(h); err == nil && a.Is6() {
		return "[" + h + "]"
	}
	return h
}

// validate checks a normalised copy; it returns every problem found.
func (s *Settings) validate() []FieldError {
	var errs []FieldError
	bad := func(field, format string, args ...any) {
		errs = append(errs, FieldError{field, fmt.Sprintf(format, args...)})
	}
	for _, v := range s.Scan.Subnets {
		if _, err := netip.ParsePrefix(v); err != nil {
			bad("scan.subnets", "%q is not a subnet such as 192.168.1.0/24", v)
		}
	}
	durations := []struct {
		field    string
		d        Duration
		min, max time.Duration
	}{
		{"scan.interval", s.Scan.Interval, 5 * time.Minute, 7 * 24 * time.Hour},
		{"scan.retention", s.Scan.Retention, time.Hour, 3650 * 24 * time.Hour},
		{"scan.forgetAfter", s.Scan.ForgetAfter, time.Hour, 3650 * 24 * time.Hour},
		{"scan.osRescan", s.Scan.OSRescan, time.Hour, 3650 * 24 * time.Hour},
		{"scan.jobTimeout", s.Scan.JobTimeout, time.Minute, 24 * time.Hour},
		{"login.sessionTtl", s.Login.SessionTTL, time.Minute, 90 * 24 * time.Hour},
		{"snmp.timeout", s.SNMP.Timeout, 100 * time.Millisecond, 30 * time.Second},
	}
	for _, d := range durations {
		if d.d.D() < d.min || d.d.D() > d.max {
			bad(d.field, "must be between %s and %s", Duration(d.min), Duration(d.max))
		}
	}
	ints := []struct {
		field    string
		v        int
		min, max int
	}{
		{"scan.osScanMax", s.Scan.OSScanMax, 0, 1000},
		{"scan.probeMaxPerHour", s.Scan.ProbeMaxPerHour, 0, 1000},
		{"snmp.retries", s.SNMP.Retries, 0, 5},
		{"snmp.concurrency", s.SNMP.Concurrency, 1, 256},
	}
	for _, n := range ints {
		if n.v < n.min || n.v > n.max {
			bad(n.field, "must be between %d and %d", n.min, n.max)
		}
	}
	for _, v := range s.SNMP.Seeds {
		if _, err := netip.ParseAddr(v); err != nil {
			bad("snmp.seeds", "%q is not an IP address", v)
		}
	}
	checkCred := func(field string, c SNMPCred, required bool) {
		switch c.Version {
		case "":
			if required {
				bad(field+".version", "choose SNMP v2c or v3")
			}
		case "2c":
			if c.Community == "" {
				bad(field+".community", "a v2c community is required")
			}
		case "3":
			if c.User == "" {
				bad(field+".user", "a v3 user is required")
			}
			if !slices.Contains(authProtos, c.AuthProto) {
				bad(field+".authProto", "unknown authentication protocol %q", c.AuthProto)
			}
			if !slices.Contains(privProtos, c.PrivProto) {
				bad(field+".privProto", "unknown privacy protocol %q", c.PrivProto)
			}
			if c.PrivPass != "" && c.AuthPass == "" {
				bad(field+".authPass", "privacy (encryption) needs an authentication password too")
			}
		default:
			bad(field+".version", "unknown SNMP version %q", c.Version)
		}
	}
	ids := map[string]bool{}
	checkID := func(kind, id string) {
		if !idRe.MatchString(id) || ids[kind+id] {
			bad(kind, "entry IDs must be unique (reload the page)")
		}
		ids[kind+id] = true
	}
	for _, h := range s.SNMP.Hosts {
		checkID("snmp.hosts", h.ID)
	}
	for _, e := range s.Proxmox {
		checkID("proxmox", e.ID)
	}
	for _, e := range s.UniFi {
		checkID("unifi", e.ID)
	}
	for _, e := range s.Cosmos {
		checkID("cosmos", e.ID)
	}
	checkCred("snmp.default", s.SNMP.Default, false)
	seen := map[string]bool{}
	for _, h := range s.SNMP.Hosts {
		f := "snmp.hosts." + h.ID
		_, perr := netip.ParsePrefix(h.Match)
		_, aerr := netip.ParseAddr(h.Match)
		switch {
		case h.Match == "":
			bad(f+".match", "enter an IP address, a subnet or a hostname")
		case perr != nil && aerr != nil && !hostnameRe.MatchString(h.Match):
			bad(f+".match", "%q is not an IP address, subnet or hostname", h.Match)
		case seen[h.Match]:
			bad(f+".match", "%s is listed twice", h.Match)
		}
		seen[h.Match] = true
		checkCred(f, h.Credentials, true)
	}
	hosts := func(kind string, id, host string, defPort int, seen map[string]bool) {
		f := kind + "." + id + ".host"
		u, err := targetURL(host, defPort)
		switch {
		case host == "":
			bad(f, "enter the hostname")
		case err != nil:
			bad(f, "%s", err)
		case seen[u]:
			bad(f, "%s is listed twice", host)
		}
		seen[u] = true
	}
	describe := func(kind, id, d string) {
		if utf8.RuneCountInString(d) > maxDescription {
			bad(kind+"."+id+".description", "at most %d characters", maxDescription)
		}
	}
	for _, h := range s.SNMP.Hosts {
		describe("snmp.hosts", h.ID, h.Description)
	}
	seenPVE, seenUniFi, seenCosmos := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, e := range s.Proxmox {
		describe("proxmox", e.ID, e.Description)
		hosts("proxmox", e.ID, e.Host, 8006, seenPVE)
		if !tokenIDRe.MatchString(e.TokenID) {
			bad("proxmox."+e.ID+".tokenId", "use the form user@realm!tokenname, e.g. homelabmap@pve!scanner")
		}
		if e.TokenSecret == "" {
			bad("proxmox."+e.ID+".tokenSecret", "the token secret is required")
		}
	}
	for _, e := range s.UniFi {
		hosts("unifi", e.ID, e.Host, 443, seenUniFi)
		describe("unifi", e.ID, e.Description)
		if e.APIKey == "" {
			bad("unifi."+e.ID+".apiKey", "the API key is required")
		}
		if e.HistoryHours < 0 || e.HistoryHours > 8760 {
			bad("unifi."+e.ID+".historyHours", "must be between 0 and 8760 hours")
		}
	}
	for _, e := range s.Cosmos {
		hosts("cosmos", e.ID, e.Host, 443, seenCosmos)
		describe("cosmos", e.ID, e.Description)
		if e.Token == "" {
			bad("cosmos."+e.ID+".token", "the API token is required")
		}
	}
	return errs
}

// forScanner is the scanner's share of the settings.
func (s *Settings) forScanner() *obs.ScannerSettings {
	cred := func(c SNMPCred) obs.SNMPCredentials {
		return obs.SNMPCredentials{Version: c.Version, Community: c.Community, User: c.User,
			AuthProto: c.AuthProto, AuthPass: c.AuthPass, PrivProto: c.PrivProto, PrivPass: c.PrivPass}
	}
	out := &obs.ScannerSettings{
		Subnets: slices.Clone(s.Scan.Subnets),
		SNMP: obs.SNMPSettings{Seeds: slices.Clone(s.SNMP.Seeds), TimeoutMS: int(s.SNMP.Timeout.D().Milliseconds()),
			Retries: s.SNMP.Retries, Concurrency: s.SNMP.Concurrency},
		OSScanMax: s.Scan.OSScanMax, JobTimeoutSeconds: int(s.Scan.JobTimeout.D().Seconds()),
		Passive: s.Scan.Passive, SSDP: s.Scan.SSDP,
	}
	if s.SNMP.Default.Version != "" {
		c := cred(s.SNMP.Default)
		out.SNMP.Default = &c
	}
	for _, h := range s.SNMP.Hosts {
		out.SNMP.Hosts = append(out.SNMP.Hosts, obs.SNMPHost{Match: h.Match, Credentials: cred(h.Credentials)})
	}
	for _, e := range s.Proxmox {
		if u, err := targetURL(e.Host, 8006); err == nil {
			out.Proxmox = append(out.Proxmox, obs.ProxmoxTarget{URL: u, TokenID: e.TokenID, TokenSecret: e.TokenSecret, InsecureTLS: e.InsecureTLS})
		}
	}
	for _, e := range s.UniFi {
		if u, err := targetURL(e.Host, 443); err == nil {
			out.UniFi = append(out.UniFi, obs.UniFiTarget{URL: u, APIKey: e.APIKey, Site: e.Site, InsecureTLS: e.InsecureTLS, HistoryHours: e.HistoryHours})
		}
	}
	for _, e := range s.Cosmos {
		if u, err := targetURL(e.Host, 443); err == nil {
			out.Cosmos = append(out.Cosmos, obs.CosmosTarget{URL: u, Token: e.Token, InsecureTLS: e.InsecureTLS})
		}
	}
	return out
}

// importLegacy fills settings that are still empty from the scanner's old
// environment, and names what it took.
func (s *Settings) importLegacy(l obs.LegacySettings) []string {
	set := map[string]bool{}
	for _, k := range l.Set {
		set[k] = true
	}
	ls := l.Settings
	var took []string
	if len(s.Scan.Subnets) == 0 && len(ls.Subnets) > 0 {
		s.Scan.Subnets, took = slices.Clone(ls.Subnets), append(took, "subnets")
	}
	if s.SNMP.Default.Version == "" && ls.SNMP.Default != nil {
		d := ls.SNMP.Default
		s.SNMP.Default = SNMPCred{Version: d.Version, Community: d.Community, User: d.User,
			AuthProto: d.AuthProto, AuthPass: d.AuthPass, PrivProto: d.PrivProto, PrivPass: d.PrivPass}
		took = append(took, "SNMP credentials")
	}
	if len(s.SNMP.Seeds) == 0 && len(ls.SNMP.Seeds) > 0 {
		s.SNMP.Seeds, took = slices.Clone(ls.SNMP.Seeds), append(took, "SNMP seeds")
	}
	if set["HOMELABMAP_SNMP_TIMEOUT"] {
		s.SNMP.Timeout = Duration(time.Duration(ls.SNMP.TimeoutMS) * time.Millisecond)
	}
	if set["HOMELABMAP_SNMP_RETRIES"] {
		s.SNMP.Retries = ls.SNMP.Retries
	}
	if set["HOMELABMAP_SNMP_CONCURRENCY"] {
		s.SNMP.Concurrency = ls.SNMP.Concurrency
	}
	if set["HOMELABMAP_JOB_TIMEOUT"] {
		s.Scan.JobTimeout = Duration(time.Duration(ls.JobTimeoutSeconds) * time.Second)
	}
	if set["HOMELABMAP_PASSIVE"] {
		s.Scan.Passive = ls.Passive
	}
	if set["HOMELABMAP_SSDP"] {
		s.Scan.SSDP = ls.SSDP
	}
	if len(s.Proxmox) == 0 {
		for _, t := range ls.Proxmox {
			s.Proxmox = append(s.Proxmox, ProxmoxEntry{ID: newID(), Host: t.URL, TokenID: t.TokenID, TokenSecret: t.TokenSecret, InsecureTLS: t.InsecureTLS})
			took = append(took, "Proxmox "+t.URL)
		}
	}
	if len(s.UniFi) == 0 {
		for _, t := range ls.UniFi {
			s.UniFi = append(s.UniFi, UniFiEntry{ID: newID(), Host: t.URL, APIKey: t.APIKey, Site: t.Site, InsecureTLS: t.InsecureTLS, HistoryHours: t.HistoryHours})
			took = append(took, "UniFi "+t.URL)
		}
	}
	if len(s.Cosmos) == 0 {
		for _, t := range ls.Cosmos {
			s.Cosmos = append(s.Cosmos, CosmosEntry{ID: newID(), Host: t.URL, Token: t.Token, InsecureTLS: t.InsecureTLS})
			took = append(took, "Cosmos "+t.URL)
		}
	}
	return took
}

// secretBox encrypts the settings' secrets at rest with AES-256-GCM, under
// a key derived from the agent token: a copy of the database alone (a
// backup, say) doesn't reveal them. Each ciphertext is bound to its field
// path, so ciphertexts can't be moved between fields.
type secretBox struct{ aead cipher.AEAD }

func newSecretBox(agentToken string) (*secretBox, error) {
	key, err := hkdf.Key(sha256.New, []byte(agentToken), nil, "homelabmap settings secrets v1", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &secretBox{aead}, nil
}

const sealedPrefix = "v1:"

func (b *secretBox) seal(path, plain string) string {
	nonce := make([]byte, b.aead.NonceSize())
	_, _ = rand.Read(nonce)
	return sealedPrefix + base64.RawStdEncoding.EncodeToString(b.aead.Seal(nonce, nonce, []byte(plain), []byte(path)))
}

func (b *secretBox) open(path, sealed string) (string, error) {
	raw, ok := strings.CutPrefix(sealed, sealedPrefix)
	if !ok {
		return "", errors.New("not an encrypted value")
	}
	ct, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil || len(ct) < b.aead.NonceSize() {
		return "", errors.New("corrupt encrypted value")
	}
	n := b.aead.NonceSize()
	plain, err := b.aead.Open(nil, ct[:n], ct[n:], []byte(path))
	if err != nil {
		return "", errors.New("can't decrypt (was HOMELABMAP_AGENT_TOKEN changed?)")
	}
	return string(plain), nil
}

// encode is the stored form: JSON with every secret encrypted.
func (b *secretBox) encode(s *Settings) (string, error) {
	c := s.clone()
	for path, p := range c.secrets() {
		if *p != "" {
			*p = b.seal(path, *p)
		}
	}
	raw, err := json.Marshal(c)
	return string(raw), err
}

// decode reads the stored form. Secrets that can't be decrypted are left
// empty and listed in lost, so the page can ask for them again.
func (b *secretBox) decode(doc string) (*Settings, error) {
	var s Settings
	if err := json.Unmarshal([]byte(doc), &s); err != nil {
		return nil, err
	}
	for path, p := range s.secrets() {
		if *p == "" {
			continue
		}
		v, err := b.open(path, *p)
		if err != nil {
			s.lost = append(s.lost, path)
		}
		*p = v
	}
	slices.Sort(s.lost)
	return &s, nil
}
