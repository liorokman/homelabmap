// Package scanner collects raw network observations for the frontend.
//
// It is deliberately small: no listening sockets, no storage, no topology
// logic. It polls the frontend for a job, runs the collectors and posts the
// result back.
package scanner

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Server     string // frontend agent API base URL
	AgentToken string

	Subnets []netip.Prefix

	SNMP SNMPConfig

	UniFiURL         string
	UniFiAPIKey      string
	UniFiSite        string
	UniFiInsecureTLS bool

	PVEURL         string
	PVETokenID     string // user@realm!tokenid
	PVETokenSecret string
	PVEInsecureTLS bool

	NmapPath       string
	NmapPrivileged bool
	OSScanMax      int

	JobTimeout time.Duration
}

type SNMPConfig struct {
	Version   string // "2c" or "3"
	Community string
	// SNMPv3 (USM)
	User      string
	AuthProto string // SHA, SHA256, SHA512, MD5
	AuthPass  string
	PrivProto string // AES, AES256, DES
	PrivPass  string

	Seeds       []string // extra IPs to probe even if the sweep missed them
	Timeout     time.Duration
	Retries     int
	Concurrency int
}

// LoadConfig reads HOMELABMAP_* environment variables.
func LoadConfig() (Config, error) {
	c := Config{
		Server:         env("HOMELABMAP_SERVER", "http://127.0.0.1:8097"),
		AgentToken:     os.Getenv("HOMELABMAP_AGENT_TOKEN"),
		UniFiURL:       strings.TrimRight(os.Getenv("HOMELABMAP_UNIFI_URL"), "/"),
		UniFiAPIKey:    os.Getenv("HOMELABMAP_UNIFI_API_KEY"),
		UniFiSite:      env("HOMELABMAP_UNIFI_SITE", "default"),
		PVEURL:         strings.TrimRight(os.Getenv("HOMELABMAP_PVE_URL"), "/"),
		PVETokenID:     os.Getenv("HOMELABMAP_PVE_TOKEN_ID"),
		PVETokenSecret: os.Getenv("HOMELABMAP_PVE_TOKEN_SECRET"),
		NmapPath:       env("HOMELABMAP_NMAP_PATH", "nmap"),
		SNMP: SNMPConfig{
			Version:   env("HOMELABMAP_SNMP_VERSION", "2c"),
			Community: os.Getenv("HOMELABMAP_SNMP_COMMUNITY"),
			User:      os.Getenv("HOMELABMAP_SNMP_USER"),
			AuthProto: env("HOMELABMAP_SNMP_AUTH_PROTO", "SHA"),
			AuthPass:  os.Getenv("HOMELABMAP_SNMP_AUTH_PASS"),
			PrivProto: env("HOMELABMAP_SNMP_PRIV_PROTO", "AES"),
			PrivPass:  os.Getenv("HOMELABMAP_SNMP_PRIV_PASS"),
			Seeds:     splitList(os.Getenv("HOMELABMAP_SNMP_SEEDS")),
		},
	}
	var errs []error
	var err error
	if c.UniFiInsecureTLS, err = envBool("HOMELABMAP_UNIFI_INSECURE_TLS", false); err != nil {
		errs = append(errs, err)
	}
	if c.PVEInsecureTLS, err = envBool("HOMELABMAP_PVE_INSECURE_TLS", false); err != nil {
		errs = append(errs, err)
	}
	if c.NmapPrivileged, err = envBool("HOMELABMAP_NMAP_PRIVILEGED", false); err != nil {
		errs = append(errs, err)
	}
	if c.OSScanMax, err = envInt("HOMELABMAP_OS_SCAN_MAX", 48); err != nil {
		errs = append(errs, err)
	}
	if c.SNMP.Retries, err = envInt("HOMELABMAP_SNMP_RETRIES", 1); err != nil {
		errs = append(errs, err)
	}
	if c.SNMP.Concurrency, err = envInt("HOMELABMAP_SNMP_CONCURRENCY", 48); err != nil {
		errs = append(errs, err)
	}
	if c.SNMP.Timeout, err = envDuration("HOMELABMAP_SNMP_TIMEOUT", 1500*time.Millisecond); err != nil {
		errs = append(errs, err)
	}
	if c.JobTimeout, err = envDuration("HOMELABMAP_JOB_TIMEOUT", 15*time.Minute); err != nil {
		errs = append(errs, err)
	}

	for _, s := range splitList(env("HOMELABMAP_SUBNETS", "")) {
		p, perr := netip.ParsePrefix(s)
		if perr != nil {
			errs = append(errs, fmt.Errorf("HOMELABMAP_SUBNETS: %w", perr))
			continue
		}
		c.Subnets = append(c.Subnets, p.Masked())
	}
	if len(c.Subnets) == 0 {
		errs = append(errs, errors.New("HOMELABMAP_SUBNETS is required (e.g. 10.20.20.0/22)"))
	}
	switch c.SNMP.Version {
	case "2c":
		if c.SNMP.Community == "" {
			errs = append(errs, errors.New("HOMELABMAP_SNMP_COMMUNITY is required for SNMP v2c"))
		}
	case "3":
		if c.SNMP.User == "" {
			errs = append(errs, errors.New("HOMELABMAP_SNMP_USER is required for SNMP v3"))
		}
	default:
		errs = append(errs, fmt.Errorf("HOMELABMAP_SNMP_VERSION must be 2c or 3, got %q", c.SNMP.Version))
	}
	if (c.PVEURL == "") != (c.PVETokenID == "") || (c.PVETokenID == "") != (c.PVETokenSecret == "") {
		errs = append(errs, errors.New("set all of HOMELABMAP_PVE_URL, HOMELABMAP_PVE_TOKEN_ID, HOMELABMAP_PVE_TOKEN_SECRET, or none"))
	}
	if (c.UniFiURL == "") != (c.UniFiAPIKey == "") {
		errs = append(errs, errors.New("set both HOMELABMAP_UNIFI_URL and HOMELABMAP_UNIFI_API_KEY, or neither"))
	}
	return c, errors.Join(errs...)
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
