// Package scanner collects raw network observations for the frontend.
//
// It is deliberately small: no listening sockets, no storage, no topology
// logic. It polls the frontend for a job, runs the collectors and posts the
// result back.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
)

type Config struct {
	Server     string // frontend agent API base URL
	AgentToken string

	NmapPath       string
	NmapPrivileged bool
	// ListenPath is the homelabmap-listen helper for passive listening
	// (ARP and IPv6 neighbour discovery).
	ListenPath string

	// The rest comes from the web's Settings page with each job
	// (WithSettings), or from the environment with -once.

	Subnets []netip.Prefix
	SNMP    SNMPConfig
	UniFi   []obs.UniFiTarget
	PVE     []obs.ProxmoxTarget
	Cosmos  []obs.CosmosTarget

	OSScanMax  int
	JobTimeout time.Duration
	Passive    bool
	// SSDP enables the UPnP search (M-SEARCH) during scans.
	SSDP bool
}

// SNMPConfig holds credentials and tuning. In Config.SNMP the credentials
// are the default (Version "" = none) and Hosts the per-host overrides;
// forIP picks the ones for a target.
type SNMPConfig struct {
	Version   string // "2c" or "3"; "" = no credentials
	Community string
	// SNMPv3 (USM)
	User      string
	AuthProto string // SHA, SHA224, SHA256, SHA384, SHA512, MD5
	AuthPass  string
	PrivProto string // AES, AES192, AES256, DES
	PrivPass  string

	Hosts       []SNMPHost
	Seeds       []string // extra IPs to probe even if the sweep missed them
	Timeout     time.Duration
	Retries     int
	Concurrency int
}

// SNMPHost is a per-host credential override.
type SNMPHost struct {
	Match string // as configured: IP, CIDR or hostname
	Cred  obs.SNMPCredentials

	prefix netip.Prefix // IP (as /32 or /128) or CIDR; invalid for hostnames
	exact  bool         // an IP or a hostname, not a prefix
	ips    []string     // a hostname's addresses, filled by resolveHosts
}

func credConfig(c *obs.SNMPCredentials) SNMPConfig {
	if c == nil {
		return SNMPConfig{}
	}
	return SNMPConfig{Version: c.Version, Community: c.Community, User: c.User,
		AuthProto: c.AuthProto, AuthPass: c.AuthPass, PrivProto: c.PrivProto, PrivPass: c.PrivPass}
}

// usable reports whether the credentials can be used at all.
func (c SNMPConfig) usable() bool {
	switch c.Version {
	case "2c":
		return c.Community != ""
	case "3":
		return c.User != ""
	}
	return false
}

// forIP returns the credentials (with the tuning) for one target: an exact
// IP or hostname override, else the longest matching prefix, else the
// default. ok is false when none applies.
func (c SNMPConfig) forIP(ip string) (SNMPConfig, bool) {
	addr, err := parseAddr(ip)
	best, bestBits := -1, -1
	for i, h := range c.Hosts {
		switch {
		case h.exact && (slices.Contains(h.ips, ip) || (h.prefix.IsValid() && err == nil && h.prefix.Contains(addr))):
			best, bestBits = i, 1<<10
		case !h.exact && h.prefix.IsValid() && err == nil && h.prefix.Contains(addr) && h.prefix.Bits() > bestBits:
			best, bestBits = i, h.prefix.Bits()
		}
	}
	out := c
	out.Hosts, out.Seeds = nil, nil
	if best >= 0 {
		cred := credConfig(&c.Hosts[best].Cred)
		out.Version, out.Community, out.User = cred.Version, cred.Community, cred.User
		out.AuthProto, out.AuthPass, out.PrivProto, out.PrivPass = cred.AuthProto, cred.AuthPass, cred.PrivProto, cred.PrivPass
	}
	return out, out.usable()
}

// resolveHosts looks up the hostnames among the overrides.
func (c *SNMPConfig) resolveHosts(ctx context.Context) error {
	var errs []error
	for i := range c.Hosts {
		h := &c.Hosts[i]
		if h.prefix.IsValid() {
			continue
		}
		ips, err := net.DefaultResolver.LookupHost(ctx, h.Match)
		if err != nil {
			errs = append(errs, fmt.Errorf("SNMP host %s: %w", h.Match, err))
		}
		h.ips = ips
	}
	return errors.Join(errs...)
}

// overrideIPs are the single hosts with their own credentials, which are
// queried even if the sweep missed them.
func (c SNMPConfig) overrideIPs() []string {
	var out []string
	for _, h := range c.Hosts {
		if !h.exact {
			continue
		}
		if h.prefix.IsValid() {
			out = append(out, h.prefix.Addr().String())
		}
		out = append(out, h.ips...)
	}
	return out
}

// LoadConfig reads the scanner's own settings: how to reach the web, and
// the local tools. Everything else arrives with each job.
func LoadConfig() (Config, error) {
	c := Config{
		Server:     env("HOMELABMAP_SERVER", "http://127.0.0.1:8097"),
		AgentToken: os.Getenv("HOMELABMAP_AGENT_TOKEN"),
		NmapPath:   env("HOMELABMAP_NMAP_PATH", "nmap"),
		ListenPath: env("HOMELABMAP_LISTEN_PATH", "homelabmap-listen"),
	}
	var err error
	c.NmapPrivileged, err = envBool("HOMELABMAP_NMAP_PRIVILEGED", false)
	return c, err
}

// WithSettings returns the config for one job: c with the web's settings.
func (c Config) WithSettings(s obs.ScannerSettings) (Config, error) {
	var errs []error
	c.Subnets = nil
	for _, v := range s.Subnets {
		p, err := netip.ParsePrefix(strings.TrimSpace(v))
		if err != nil {
			errs = append(errs, fmt.Errorf("subnet %q: %w", v, err))
			continue
		}
		c.Subnets = append(c.Subnets, p.Masked())
	}
	c.SNMP = credConfig(s.SNMP.Default)
	c.SNMP.Seeds = s.SNMP.Seeds
	c.SNMP.Timeout = time.Duration(s.SNMP.TimeoutMS) * time.Millisecond
	c.SNMP.Retries = s.SNMP.Retries
	c.SNMP.Concurrency = s.SNMP.Concurrency
	for _, h := range s.SNMP.Hosts {
		sh := SNMPHost{Match: h.Match, Cred: h.Credentials, exact: true}
		if p, err := netip.ParsePrefix(h.Match); err == nil {
			sh.prefix, sh.exact = p.Masked(), p.IsSingleIP()
		} else if a, err := netip.ParseAddr(h.Match); err == nil {
			sh.prefix = netip.PrefixFrom(a, a.BitLen())
		}
		c.SNMP.Hosts = append(c.SNMP.Hosts, sh)
	}
	c.UniFi, c.PVE, c.Cosmos = s.UniFi, s.Proxmox, s.Cosmos
	c.OSScanMax = s.OSScanMax
	c.JobTimeout = time.Duration(s.JobTimeoutSeconds) * time.Second
	if c.JobTimeout <= 0 {
		c.JobTimeout = 15 * time.Minute
	}
	c.Passive, c.SSDP = s.Passive, s.SSDP
	return c, errors.Join(errs...)
}

// legacyVars are the environment variables that configured scans before
// the Settings page. The web imports them once (LegacySettings).
var legacyVars = []string{
	"HOMELABMAP_SUBNETS", "HOMELABMAP_SNMP_VERSION", "HOMELABMAP_SNMP_COMMUNITY", "HOMELABMAP_SNMP_USER",
	"HOMELABMAP_SNMP_AUTH_PROTO", "HOMELABMAP_SNMP_AUTH_PASS", "HOMELABMAP_SNMP_PRIV_PROTO", "HOMELABMAP_SNMP_PRIV_PASS",
	"HOMELABMAP_SNMP_SEEDS", "HOMELABMAP_SNMP_TIMEOUT", "HOMELABMAP_SNMP_RETRIES", "HOMELABMAP_SNMP_CONCURRENCY",
	"HOMELABMAP_UNIFI_URL", "HOMELABMAP_UNIFI_API_KEY", "HOMELABMAP_UNIFI_SITE", "HOMELABMAP_UNIFI_INSECURE_TLS",
	"HOMELABMAP_UNIFI_HISTORY_HOURS", "HOMELABMAP_PVE_URL", "HOMELABMAP_PVE_TOKEN_ID", "HOMELABMAP_PVE_TOKEN_SECRET",
	"HOMELABMAP_PVE_INSECURE_TLS", "HOMELABMAP_COSMOS_URL", "HOMELABMAP_COSMOS_TOKEN", "HOMELABMAP_COSMOS_INSECURE_TLS",
	"HOMELABMAP_OS_SCAN_MAX", "HOMELABMAP_JOB_TIMEOUT", "HOMELABMAP_PASSIVE", "HOMELABMAP_SSDP",
}

// LegacySettings reads the old scan environment variables, with the old
// defaults, and reports which were set.
func LegacySettings() (obs.LegacySettings, error) {
	var l obs.LegacySettings
	for _, k := range legacyVars {
		if os.Getenv(k) != "" {
			l.Set = append(l.Set, k)
		}
	}
	s := &l.Settings
	s.Subnets = splitList(os.Getenv("HOMELABMAP_SUBNETS"))
	var errs []error
	var err error
	if s.SSDP, err = envBool("HOMELABMAP_SSDP", true); err != nil {
		errs = append(errs, err)
	}
	if s.Passive, err = envBool("HOMELABMAP_PASSIVE", true); err != nil {
		errs = append(errs, err)
	}
	if s.OSScanMax, err = envInt("HOMELABMAP_OS_SCAN_MAX", 48); err != nil {
		errs = append(errs, err)
	}
	jt, err := envDuration("HOMELABMAP_JOB_TIMEOUT", 15*time.Minute)
	errs = append(errs, err)
	s.JobTimeoutSeconds = int(jt.Seconds())

	st, err := envDuration("HOMELABMAP_SNMP_TIMEOUT", 1500*time.Millisecond)
	errs = append(errs, err)
	s.SNMP.TimeoutMS = int(st.Milliseconds())
	if s.SNMP.Retries, err = envInt("HOMELABMAP_SNMP_RETRIES", 1); err != nil {
		errs = append(errs, err)
	}
	if s.SNMP.Concurrency, err = envInt("HOMELABMAP_SNMP_CONCURRENCY", 48); err != nil {
		errs = append(errs, err)
	}
	s.SNMP.Seeds = splitList(os.Getenv("HOMELABMAP_SNMP_SEEDS"))
	cred := obs.SNMPCredentials{
		Version:   env("HOMELABMAP_SNMP_VERSION", "2c"),
		Community: os.Getenv("HOMELABMAP_SNMP_COMMUNITY"),
		User:      os.Getenv("HOMELABMAP_SNMP_USER"),
		AuthProto: env("HOMELABMAP_SNMP_AUTH_PROTO", "SHA"),
		AuthPass:  os.Getenv("HOMELABMAP_SNMP_AUTH_PASS"),
		PrivProto: env("HOMELABMAP_SNMP_PRIV_PROTO", "AES"),
		PrivPass:  os.Getenv("HOMELABMAP_SNMP_PRIV_PASS"),
	}
	if credConfig(&cred).usable() {
		s.SNMP.Default = &cred
	}

	if u := strings.TrimRight(os.Getenv("HOMELABMAP_UNIFI_URL"), "/"); u != "" {
		t := obs.UniFiTarget{URL: u, APIKey: os.Getenv("HOMELABMAP_UNIFI_API_KEY"), Site: env("HOMELABMAP_UNIFI_SITE", "default")}
		if t.InsecureTLS, err = envBool("HOMELABMAP_UNIFI_INSECURE_TLS", false); err != nil {
			errs = append(errs, err)
		}
		if t.HistoryHours, err = envInt("HOMELABMAP_UNIFI_HISTORY_HOURS", 720); err != nil {
			errs = append(errs, err)
		}
		s.UniFi = append(s.UniFi, t)
	}
	if u := strings.TrimRight(os.Getenv("HOMELABMAP_PVE_URL"), "/"); u != "" {
		t := obs.ProxmoxTarget{URL: u, TokenID: os.Getenv("HOMELABMAP_PVE_TOKEN_ID"), TokenSecret: os.Getenv("HOMELABMAP_PVE_TOKEN_SECRET")}
		if t.InsecureTLS, err = envBool("HOMELABMAP_PVE_INSECURE_TLS", false); err != nil {
			errs = append(errs, err)
		}
		s.Proxmox = append(s.Proxmox, t)
	}
	if u := strings.TrimRight(os.Getenv("HOMELABMAP_COSMOS_URL"), "/"); u != "" {
		t := obs.CosmosTarget{URL: u, Token: os.Getenv("HOMELABMAP_COSMOS_TOKEN")}
		if t.InsecureTLS, err = envBool("HOMELABMAP_COSMOS_INSECURE_TLS", false); err != nil {
			errs = append(errs, err)
		}
		s.Cosmos = append(s.Cosmos, t)
	}
	return l, errors.Join(errs...)
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) (bool, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def, fmt.Errorf("%s: %w", k, err)
	}
	return b, nil
}

func envInt(k string, def int) (int, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def, fmt.Errorf("%s: %w", k, err)
	}
	return n, nil
}

func envDuration(k string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def, fmt.Errorf("%s: %w", k, err)
	}
	return d, nil
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
