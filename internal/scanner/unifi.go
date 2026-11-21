package scanner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
)

func httpClient(insecure bool) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		// Opt-in only, for appliances with self-signed certificates on the LAN.
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit user setting
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: tr}
}

type httpStatusError struct {
	Code int
	URL  string
}

func (e *httpStatusError) Error() string { return fmt.Sprintf("GET %s: HTTP %d", e.URL, e.Code) }

func getJSON(ctx context.Context, c *http.Client, u string, hdr map[string]string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	for k, val := range hdr {
		req.Header.Set(k, val)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return &httpStatusError{Code: resp.StatusCode, URL: redactURL(u)}
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(v)
}

func redactURL(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return "?"
	}
	p.RawQuery = ""
	return p.String()
}

// unifiCollect reads devices and clients from a UniFi OS console.
func unifiCollect(ctx context.Context, cfg Config) (*obs.UniFi, error) {
	c := httpClient(cfg.UniFiInsecureTLS)
	hdr := map[string]string{"X-API-KEY": cfg.UniFiAPIKey}

	// The classic Network API has switch ports, AP associations and
	// fingerprints. Newer consoles accept API keys on it too.
	legacy, lerr := unifiLegacy(ctx, c, cfg, hdr)
	if lerr == nil {
		return legacy, nil
	}
	integ, ierr := unifiIntegration(ctx, c, cfg, hdr)
	if ierr == nil {
		return integ, nil
	}
	return nil, errors.Join(fmt.Errorf("classic API: %w", lerr), fmt.Errorf("integration API: %w", ierr))
}

func unifiLegacy(ctx context.Context, c *http.Client, cfg Config, hdr map[string]string) (*obs.UniFi, error) {
	base := cfg.UniFiURL + "/proxy/network/api/s/" + url.PathEscape(cfg.UniFiSite)
	var dev, sta struct {
		Meta struct {
			RC  string `json:"rc"`
			Msg string `json:"msg"`
		} `json:"meta"`
		Data []json.RawMessage `json:"data"`
	}
	if err := getJSON(ctx, c, base+"/stat/device", hdr, &dev); err != nil {
		return nil, err
	}
	if dev.Meta.RC != "ok" {
		return nil, fmt.Errorf("stat/device: %s", dev.Meta.Msg)
	}
	if err := getJSON(ctx, c, base+"/stat/sta", hdr, &sta); err != nil {
		return nil, err
	}
	if sta.Meta.RC != "ok" {
		return nil, fmt.Errorf("stat/sta: %s", sta.Meta.Msg)
	}
	return &obs.UniFi{Flavor: "legacy", Devices: dev.Data, Clients: sta.Data}, nil
}

type integPage struct {
	Offset     int               `json:"offset"`
	Limit      int               `json:"limit"`
	Count      int               `json:"count"`
	TotalCount int               `json:"totalCount"`
	Data       []json.RawMessage `json:"data"`
}

func unifiIntegration(ctx context.Context, c *http.Client, cfg Config, hdr map[string]string) (*obs.UniFi, error) {
	base := cfg.UniFiURL + "/proxy/network/integration/v1"
	var sites struct {
		Data []struct {
			ID                string `json:"id"`
			InternalReference string `json:"internalReference"`
			Name              string `json:"name"`
		} `json:"data"`
	}
	if err := getJSON(ctx, c, base+"/sites", hdr, &sites); err != nil {
		return nil, err
	}
	siteID := ""
	for _, s := range sites.Data {
		if s.InternalReference == cfg.UniFiSite || s.Name == cfg.UniFiSite || len(sites.Data) == 1 {
			siteID = s.ID
			break
		}
	}
	if siteID == "" {
		return nil, fmt.Errorf("site %q not found", cfg.UniFiSite)
	}
	sbase := base + "/sites/" + url.PathEscape(siteID)

	list, err := integList(ctx, c, sbase+"/devices", hdr)
	if err != nil {
		return nil, err
	}
	// The list is a summary; details carry uplinks and ports.
	devices := make([]json.RawMessage, 0, len(list))
	for _, d := range list {
		var id struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(d, &id) != nil || id.ID == "" {
			devices = append(devices, d)
			continue
		}
		var detail json.RawMessage
		if err := getJSON(ctx, c, sbase+"/devices/"+url.PathEscape(id.ID), hdr, &detail); err != nil {
			devices = append(devices, d)
			continue
		}
		devices = append(devices, detail)
	}
	clients, err := integList(ctx, c, sbase+"/clients", hdr)
	if err != nil {
		return nil, err
	}
	return &obs.UniFi{Flavor: "integration", Devices: devices, Clients: clients}, nil
}

func integList(ctx context.Context, c *http.Client, u string, hdr map[string]string) ([]json.RawMessage, error) {
	var all []json.RawMessage
	for offset := 0; offset < 10000; {
		var p integPage
		if err := getJSON(ctx, c, fmt.Sprintf("%s?offset=%d&limit=200", u, offset), hdr, &p); err != nil {
			return nil, err
		}
		all = append(all, p.Data...)
		if len(p.Data) == 0 || len(all) >= p.TotalCount {
			break
		}
		offset += len(p.Data)
	}
	return all, nil
}
