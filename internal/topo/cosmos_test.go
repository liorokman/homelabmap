package topo

import (
	"slices"
	"testing"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
)

func TestCosmosContainersAndStacks(t *testing.T) {
	res := &obs.Result{StartedAt: tNow, Subnets: []string{"10.20.20.0/22"},
		Sweep: []obs.SweepHost{{IP: "10.20.23.80", MAC: "bc:24:11:00:00:28"}, {IP: "10.20.23.186", MAC: "d4:03:80:cb:3c:43"}},
		DNS:   map[string]string{"10.20.23.80": "cosmos.example.net", "10.20.23.186": "nuc"},
		Cosmos: &obs.Cosmos{URL: "https://cosmos.example.net", HostIPs: []string{"10.20.23.80"},
			Containers: []obs.CosmosContainer{
				{Name: "homelabmap-web", Image: "registry/homelabmap/web:0.4.0", State: "running", Status: "Up 2 hours", NetworkMode: "bridge", Stack: "homelabmap", StackMain: true,
					Ports: []obs.DockerPort{{IP: "127.0.0.1", PrivatePort: 8081, PublicPort: 8097, Type: "tcp"}}, Created: tNow.Add(-2 * time.Hour)},
				{Name: "homelabmap-scanner", Image: "registry/homelabmap/scanner:0.4.0", State: "running", NetworkMode: "host", Stack: "homelabmap"},
				{Name: "registry", Image: "registry:2.8.3", State: "running", NetworkMode: "bridge"},
				{Name: "registry-init", Image: "busybox:1.37", State: "exited", NetworkMode: "bridge"},
				{Name: "budget", Image: "example/budget:latest", State: "running", Stack: "eager_lovelace"},
			},
			Routes: []obs.CosmosRoute{
				{Name: "homelabmap", Host: "homelabmap.example.net", Target: "http://homelabmap-web:8080", Mode: "SERVAPP"},
				{Name: "registry", Host: "registry.example.net", Target: "http://registry:5000", Mode: "SERVAPP"},
				{Name: "registry-push", Host: "registry-push.example.net", Target: "http://registry:5000", Mode: "SERVAPP"},
				{Name: "nuc", Host: "nuc.example.net", Target: "http://10.20.23.186:8123", Mode: "PROXY"},
				{Name: "off", Host: "off.example.net", Target: "http://registry:5000", Mode: "SERVAPP", Disabled: true},
			},
		},
	}
	g := Build(1, res, History{})
	host := nodeByLabel(g, "cosmos")
	if host == nil {
		t.Fatalf("cosmos host missing: %+v", g.Nodes)
	}
	stack := nodeByLabel(g, "homelabmap")
	if stack == nil || stack.Role != RoleStack || stack.Parent != host.ID || stack.Status != "2/2 running" ||
		!slices.Equal(stack.Members, []string{"ctr-homelabmap-web", "ctr-homelabmap-scanner"}) ||
		!slices.Equal(stack.URLs, []string{"https://homelabmap.example.net"}) || stack.Power != PowerOn {
		t.Fatalf("stack: %+v", stack)
	}
	web := nodeByLabel(g, "homelabmap-web")
	if web == nil || web.Stack != stack.ID || web.Parent != stack.ID || web.Depth != host.Depth+2 ||
		!slices.Equal(web.Published, []string{"127.0.0.1:8097 → 8081/tcp"}) || !web.FirstSeen.Equal(tNow.Add(-2*time.Hour)) {
		t.Errorf("stacked container: %+v", web)
	}
	if sc := nodeByLabel(g, "homelabmap-scanner"); sc == nil || sc.Network != "host (shares the host's network)" {
		t.Errorf("host-network container: %+v", sc)
	}
	registry := nodeByLabel(g, "registry")
	if registry == nil || registry.Stack != "" || registry.Parent != host.ID ||
		!slices.Equal(registry.URLs, []string{"https://registry.example.net", "https://registry-push.example.net"}) {
		t.Errorf("stand-alone container: %+v", registry)
	}
	if wf := nodeByLabel(g, "budget"); wf == nil || wf.Stack != "" || wf.Parent != host.ID || nodeByLabel(g, "eager_lovelace") != nil {
		t.Errorf("a one-container stack is just the container: %+v", wf)
	}
	if init := nodeByLabel(g, "registry-init"); init == nil || init.Power != PowerOff || init.PowerState != "exited" {
		t.Errorf("exited container: %+v", init)
	}
	if m := nodeByLabel(g, "nuc"); m == nil || !slices.Equal(m.URLs, []string{"https://nuc.example.net"}) {
		t.Errorf("proxied LAN device: %+v", m)
	}
	edges := map[string]bool{}
	for _, e := range g.Edges {
		edges[e.Source+">"+e.Target] = true
	}
	for _, want := range []string{host.ID + ">stack-homelabmap", "stack-homelabmap>ctr-homelabmap-web", host.ID + ">ctr-registry"} {
		if !edges[want] {
			t.Errorf("missing edge %s", want)
		}
	}

	// Containers are never carried as absent: Cosmos lists what exists.
	next := &Graph{Nodes: []Node{*host}}
	CarryOver(next, g, tNow.Add(time.Hour), 30*24*time.Hour)
	for _, n := range next.Nodes {
		if n.Role == RoleDocker || n.Role == RoleStack {
			t.Errorf("carried %s", n.Label)
		}
	}

	// No host on the map: a warning, no orphan containers.
	res.Sweep = res.Sweep[1:]
	g = Build(2, res, History{})
	if nodeByLabel(g, "registry") != nil || len(g.Warnings) == 0 {
		t.Errorf("without host: warnings %v", g.Warnings)
	}
}
