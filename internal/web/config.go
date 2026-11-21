// Package web is the homelabmap frontend: UI, API, OIDC login, scheduler and
// the agent endpoint the scanner talks to.
package web

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Listen      string // UI + API (behind the Cosmos route)
	AgentListen string // scanner API (published on host loopback only)
	DBPath      string
	PublicURL   *url.URL

	AgentToken string

	OIDCIssuer        string
	OIDCClientID      string
	OIDCClientSecret  string // optional: PKCE works with public clients
	OIDCScopes        []string
	OIDCAllowedGroups []string
	SessionTTL        time.Duration

	ScanInterval time.Duration
	Retention    time.Duration
	OSRescan     time.Duration
	OSScanMax    int

	// InsecureNoAuth disables login for local development. Refused unless
	// the UI listens on loopback.
	InsecureNoAuth bool
}

func LoadConfig() (Config, error) {
	c := Config{
		Listen:           env("HOMELABMAP_LISTEN", ":8080"),
		AgentListen:      env("HOMELABMAP_AGENT_LISTEN", ":8081"),
		DBPath:           env("HOMELABMAP_DB", "/data/homelabmap.db"),
		AgentToken:       os.Getenv("HOMELABMAP_AGENT_TOKEN"),
		OIDCIssuer:       os.Getenv("HOMELABMAP_OIDC_ISSUER"),
		OIDCClientID:     os.Getenv("HOMELABMAP_OIDC_CLIENT_ID"),
		OIDCClientSecret: os.Getenv("HOMELABMAP_OIDC_CLIENT_SECRET"),
		OIDCScopes:       strings.Fields(env("HOMELABMAP_OIDC_SCOPES", "openid profile email")),
	}
	for _, g := range strings.Split(os.Getenv("HOMELABMAP_OIDC_ALLOWED_GROUPS"), ",") {
		if g = strings.TrimSpace(g); g != "" {
			c.OIDCAllowedGroups = append(c.OIDCAllowedGroups, g)
		}
	}
	var errs []error
	durations := []struct {
		dst  *time.Duration
		key  string
		def  time.Duration
		minD time.Duration
	}{
		{&c.SessionTTL, "HOMELABMAP_SESSION_TTL", 12 * time.Hour, time.Minute},
		{&c.ScanInterval, "HOMELABMAP_SCAN_INTERVAL", time.Hour, 5 * time.Minute},
		{&c.Retention, "HOMELABMAP_RETENTION", 14 * 24 * time.Hour, time.Hour},
		{&c.OSRescan, "HOMELABMAP_OS_RESCAN", 7 * 24 * time.Hour, time.Hour},
	}
	for _, d := range durations {
		*d.dst = d.def
		if v := os.Getenv(d.key); v != "" {
			p, err := time.ParseDuration(v)
			switch {
			case err != nil:
				errs = append(errs, fmt.Errorf("%s: %w", d.key, err))
			case p < d.minD:
				errs = append(errs, fmt.Errorf("%s: must be at least %s", d.key, d.minD))
			default:
				*d.dst = p
			}
		}
	}
	c.OSScanMax = 48
	if v := os.Getenv("HOMELABMAP_OS_SCAN_MAX"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			errs = append(errs, fmt.Errorf("HOMELABMAP_OS_SCAN_MAX: invalid %q", v))
		}
		c.OSScanMax = n
	}
	if v := os.Getenv("HOMELABMAP_INSECURE_NO_AUTH"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("HOMELABMAP_INSECURE_NO_AUTH: %w", err))
		}
		c.InsecureNoAuth = b
	}

	pub := os.Getenv("HOMELABMAP_PUBLIC_URL")
	if pub == "" {
		errs = append(errs, errors.New("HOMELABMAP_PUBLIC_URL is required (e.g. https://homelabmap.example.net)"))
	} else if u, err := url.Parse(strings.TrimRight(pub, "/")); err != nil || u.Scheme == "" || u.Host == "" {
		errs = append(errs, fmt.Errorf("HOMELABMAP_PUBLIC_URL: invalid %q", pub))
	} else {
		c.PublicURL = u
	}

	if len(c.AgentToken) < 32 {
		errs = append(errs, errors.New("HOMELABMAP_AGENT_TOKEN must be at least 32 characters"))
	}
	if c.InsecureNoAuth {
		host, _, err := net.SplitHostPort(c.Listen)
		if err != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
			errs = append(errs, errors.New("HOMELABMAP_INSECURE_NO_AUTH requires HOMELABMAP_LISTEN on loopback (e.g. 127.0.0.1:8080)"))
		}
	} else {
		if c.OIDCIssuer == "" || c.OIDCClientID == "" {
			errs = append(errs, errors.New("HOMELABMAP_OIDC_ISSUER and HOMELABMAP_OIDC_CLIENT_ID are required"))
		}
		if c.PublicURL != nil && c.PublicURL.Scheme != "https" {
			errs = append(errs, errors.New("HOMELABMAP_PUBLIC_URL must be https when login is enabled"))
		}
	}
	return c, errors.Join(errs...)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
