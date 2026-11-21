package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
)

// cosmosCollect reads a Cosmos server's containers and routes. The token
// only needs Resources Read and Configuration Read; of the configuration,
// only the reverse-proxy routes are kept.
func cosmosCollect(ctx context.Context, cfg Config) (*obs.Cosmos, error) {
	c := httpClient(cfg.CosmosInsecureTLS)
	hdr := map[string]string{"Authorization": "Bearer " + cfg.CosmosToken}
	out := &obs.Cosmos{URL: cfg.CosmosURL}
	if u, err := url.Parse(cfg.CosmosURL); err == nil {
		if ips, err := net.DefaultResolver.LookupHost(ctx, u.Hostname()); err == nil {
			out.HostIPs = ips
		}
	}

	var apps struct {
		Status string            `json:"status"`
		Data   []json.RawMessage `json:"data"`
	}
	if err := getJSON(ctx, c, cfg.CosmosURL+"/cosmos/api/servapps", hdr, &apps); err != nil {
		return nil, fmt.Errorf("servapps: %w", err)
	}
	for _, raw := range apps.Data {
		if ct, ok := parseCosmosContainer(raw); ok {
			out.Containers = append(out.Containers, ct)
		}
	}
	slices.SortFunc(out.Containers, func(a, b obs.CosmosContainer) int { return strings.Compare(a.Name, b.Name) })

	// Routes are optional: without Configuration Read there are no links.
	var conf struct {
		Data json.RawMessage `json:"data"`
	}
	if err := getJSON(ctx, c, cfg.CosmosURL+"/cosmos/api/config", hdr, &conf); err != nil {
		return out, fmt.Errorf("config (routes): %w", err)
	}
	routes, err := parseCosmosRoutes(conf.Data)
	out.Routes = routes
	return out, err
}

func parseCosmosContainer(raw json.RawMessage) (obs.CosmosContainer, bool) {
	var r struct {
		ID         string            `json:"Id"`
		Names      []string          `json:"Names"`
		Image      string            `json:"Image"`
		State      string            `json:"State"`
		Status     string            `json:"Status"`
		Created    int64             `json:"Created"`
		Labels     map[string]string `json:"Labels"`
		HostConfig struct {
			NetworkMode string `json:"NetworkMode"`
		} `json:"HostConfig"`
		NetworkSettings struct {
			Networks map[string]json.RawMessage `json:"Networks"`
		} `json:"NetworkSettings"`
		Ports []struct {
			IP          string `json:"IP"`
			PrivatePort int    `json:"PrivatePort"`
			PublicPort  int    `json:"PublicPort"`
			Type        string `json:"Type"`
		} `json:"Ports"`
	}
	if json.Unmarshal(raw, &r) != nil || len(r.Names) == 0 {
		return obs.CosmosContainer{}, false
	}
	ct := obs.CosmosContainer{
		ID: r.ID, Name: strings.TrimPrefix(r.Names[0], "/"), Image: r.Image, State: r.State, Status: r.Status,
		NetworkMode: r.HostConfig.NetworkMode,
	}
	if r.Created > 0 {
		ct.Created = time.Unix(r.Created, 0).UTC()
	}
	for n := range r.NetworkSettings.Networks {
		ct.Networks = append(ct.Networks, n)
	}
	slices.Sort(ct.Networks)
	for _, p := range r.Ports {
		dp := obs.DockerPort{IP: p.IP, PrivatePort: p.PrivatePort, PublicPort: p.PublicPort, Type: p.Type}
		if !slices.Contains(ct.Ports, dp) {
			ct.Ports = append(ct.Ports, dp)
		}
	}
	// Stacks: Cosmos's own label, else the compose project.
	ct.Stack = r.Labels["cosmos-stack"]
	if ct.Stack == "" {
		ct.Stack = r.Labels["com.docker.compose.project"]
	}
	ct.StackMain = ct.Stack != "" && r.Labels["cosmos-stack-main"] == ct.Name
	return ct, true
}

// parseCosmosRoutes takes the reverse-proxy routes out of the full
// configuration and nothing else.
func parseCosmosRoutes(data json.RawMessage) ([]obs.CosmosRoute, error) {
	var conf struct {
		HTTPConfig struct {
			ProxyConfig struct {
				Routes []struct {
					Name        string `json:"Name"`
					UseHost     bool   `json:"UseHost"`
					Host        string `json:"Host"`
					UsePrefix   bool   `json:"UsePathPrefix"`
					PathPrefix  string `json:"PathPrefix"`
					Target      string `json:"Target"`
					Mode        string `json:"Mode"`
					AuthEnabled bool   `json:"AuthEnabled"`
					Disabled    bool   `json:"Disabled"`
				} `json:"Routes"`
			} `json:"ProxyConfig"`
		} `json:"HTTPConfig"`
	}
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, errors.New("unexpected config format")
	}
	var out []obs.CosmosRoute
	for _, r := range conf.HTTPConfig.ProxyConfig.Routes {
		cr := obs.CosmosRoute{Name: r.Name, Target: r.Target, Mode: r.Mode, AuthOnly: r.AuthEnabled, Disabled: r.Disabled}
		if r.UseHost {
			cr.Host = r.Host
		}
		if r.UsePrefix {
			cr.PathPrefix = r.PathPrefix
		}
		out = append(out, cr)
	}
	return out, nil
}
