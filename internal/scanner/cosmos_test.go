package scanner

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
)

func TestParseCosmosContainer(t *testing.T) {
	raw := `{"Id":"20a7c8","Names":["/homelabmap-web"],"Image":"registry.example.net/homelabmap/web:0.3.0",
	  "State":"running","Status":"Up 4 days","Created":1793451443,"Command":"/usr/local/bin/homelabmap-web --secret=x",
	  "Labels":{"cosmos-stack":"homelabmap","cosmos-stack-main":"homelabmap-web","cosmos-auto-update":"false"},
	  "HostConfig":{"NetworkMode":"bridge"},
	  "NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.5"}}},
	  "Mounts":[{"Source":"/var/lib/docker/volumes/homelabmap-data"}],
	  "Ports":[{"IP":"127.0.0.1","PrivatePort":8081,"PublicPort":8097,"Type":"tcp"},{"IP":"127.0.0.1","PrivatePort":8081,"PublicPort":8097,"Type":"tcp"},{"PrivatePort":8080,"Type":"tcp"}]}`
	c, ok := parseCosmosContainer(json.RawMessage(raw))
	if !ok || c.Name != "homelabmap-web" || c.Stack != "homelabmap" || !c.StackMain || c.State != "running" ||
		c.NetworkMode != "bridge" || len(c.Networks) != 1 || len(c.Ports) != 2 || !c.Created.Equal(time.Unix(1793451443, 0).UTC()) {
		t.Fatalf("parsed %+v", c)
	}
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), "secret") || strings.Contains(string(b), "volumes") {
		t.Errorf("command or mounts leaked into the result: %s", b)
	}

	compose, ok := parseCosmosContainer(json.RawMessage(`{"Names":["/authentik-server-1"],"State":"running",
	  "Labels":{"com.docker.compose.project":"authentik"},"HostConfig":{"NetworkMode":"authentik_default"}}`))
	if !ok || compose.Stack != "authentik" || compose.StackMain {
		t.Errorf("compose stack: %+v", compose)
	}
	if _, ok := parseCosmosContainer(json.RawMessage(`{"Names":[]}`)); ok {
		t.Error("nameless container accepted")
	}
}

func TestParseCosmosRoutesKeepsOnlyRoutes(t *testing.T) {
	conf := `{"HTTPConfig":{"CAPrivateKey":"-----BEGIN PRIVATE KEY-----xyz","SelfTLSKey":"k",
	  "ProxyConfig":{"Routes":[
	    {"Name":"registry","UseHost":true,"Host":"registry.example.net","Target":"http://registry:5000","Mode":"SERVAPP"},
	    {"Name":"old","UseHost":false,"Host":"ignored.example","UsePathPrefix":true,"PathPrefix":"/old","Target":"http://10.20.23.186:8080","Mode":"PROXY","AuthEnabled":true,"Disabled":true}
	  ]}},"EmailConfig":{"Password":"p"}}`
	routes, err := parseCosmosRoutes(json.RawMessage(conf))
	if err != nil || len(routes) != 2 {
		t.Fatalf("routes %+v %v", routes, err)
	}
	if routes[0] != (obs.CosmosRoute{Name: "registry", Host: "registry.example.net", Target: "http://registry:5000", Mode: "SERVAPP"}) {
		t.Errorf("route 0: %+v", routes[0])
	}
	if r := routes[1]; r.Host != "" || r.PathPrefix != "/old" || !r.AuthOnly || !r.Disabled {
		t.Errorf("route 1: %+v", r)
	}
	b, _ := json.Marshal(routes)
	if strings.Contains(string(b), "PRIVATE") || strings.Contains(string(b), `"p"`) {
		t.Errorf("secrets leaked: %s", b)
	}
	if _, err := parseCosmosRoutes(json.RawMessage(`[1,2]`)); err == nil {
		t.Error("garbage accepted")
	}
}
