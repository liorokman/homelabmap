package topo

import (
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/liorokman/homelabmap/internal/obs"
)

// addCosmos adds a Cosmos host's Docker containers to the map: each stack
// as a node under the host, its containers under the stack, and stand-alone
// containers under the host. The UI shows either the stacks or, with
// stacks opened, the containers grouped inside them.
func (b *builder) addCosmos(g *Graph) {
	cz := b.res.Cosmos
	if cz == nil {
		return
	}
	host := b.cosmosHost(cz)
	routes := cosmosURLs(cz.Routes)
	b.addProxyURLs(g, routes)
	if host == nil || len(cz.Containers) == 0 {
		if host == nil && len(cz.Containers) > 0 {
			b.warnGraph(g, "Cosmos at %s: its host isn't on the map, so its containers aren't shown", cz.URL)
		}
		return
	}
	hostNode := &g.Nodes[slices.IndexFunc(g.Nodes, func(n Node) bool { return n.ID == host.nodeID })]
	hostLabel := hostNode.Label

	stacks := map[string][]obs.CosmosContainer{}
	for _, c := range cz.Containers {
		if c.Stack != "" {
			stacks[c.Stack] = append(stacks[c.Stack], c)
		}
	}
	// A one-container "stack" (often a random compose project name such as
	// "eager_lovelace") is just that container.
	var names []string
	for name, members := range stacks {
		if len(members) > 1 {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	inStack := func(c obs.CosmosContainer) bool { return c.Stack != "" && len(stacks[c.Stack]) > 1 }

	edge := func(src, dst string) {
		g.Edges = append(g.Edges, Edge{ID: "d-" + src + "-" + dst, Source: src, Target: dst, Kind: KindVirtual, Sources: []string{"cosmos"}})
	}
	for _, name := range names {
		members := stacks[name]
		id := "stack-" + sanitizeID(name)
		running := 0
		var memberIDs, urls []string
		for _, c := range members {
			if c.State == "running" {
				running++
			}
			memberIDs = append(memberIDs, containerID(c.Name))
			for _, u := range routes[c.Name] {
				if !slices.Contains(urls, u) {
					urls = append(urls, u)
				}
			}
		}
		n := Node{
			ID: id, Label: name, Role: RoleStack, Icon: IconStack, Parent: host.nodeID,
			OS:     fmt.Sprintf("Docker stack, %d container%s", len(members), plural(len(members))),
			Status: fmt.Sprintf("%d/%d running", running, len(members)), Members: memberIDs, URLs: urls,
			Location: "stack on " + hostLabel, Connection: KindVirtual, Sources: []string{"cosmos"},
			Depth: hostNode.Depth + 1,
		}
		if running > 0 {
			n.Power, n.LastSeen = PowerOn, b.res.StartedAt
		} else {
			n.Power, n.PowerState = PowerOff, "stopped"
		}
		g.Nodes = append(g.Nodes, n)
		edge(host.nodeID, id)
	}
	for _, c := range cz.Containers {
		n := b.containerNode(c, routes[c.Name], hostLabel)
		if inStack(c) {
			n.Stack, n.Parent, n.Depth = "stack-"+sanitizeID(c.Stack), "stack-"+sanitizeID(c.Stack), hostNode.Depth+2
			n.Location = "stack " + c.Stack + " on " + hostLabel
		} else {
			n.Parent, n.Depth = host.nodeID, hostNode.Depth+1
		}
		g.Nodes = append(g.Nodes, n)
		edge(n.Parent, n.ID)
	}
	sortNodes(g)
}

func (b *builder) containerNode(c obs.CosmosContainer, urls []string, hostLabel string) Node {
	n := Node{
		ID: containerID(c.Name), Label: c.Name, Role: RoleDocker, Icon: IconDocker,
		OS: "Docker container", OSSource: "cosmos", Image: c.Image, Status: c.Status,
		Network: c.NetworkMode, URLs: urls, FirstSeen: c.Created,
		Location: "container on " + hostLabel, Connection: KindVirtual, Sources: []string{"cosmos"},
	}
	for _, p := range c.Ports {
		// IPv4 and IPv6 bindings of the same port read the same: list once.
		if ps := portString(p); !slices.Contains(n.Published, ps) {
			n.Published = append(n.Published, ps)
		}
	}
	if c.State == "running" {
		n.Power, n.PowerState, n.LastSeen = PowerOn, "running", b.res.StartedAt
	} else {
		n.Power, n.PowerState = PowerOff, c.State
	}
	if c.NetworkMode == "host" {
		n.Network = "host (shares the host's network)"
	}
	return n
}

// cosmosHost is the device the Cosmos server runs on.
func (b *builder) cosmosHost(cz *obs.Cosmos) *entity {
	for _, ip := range cz.HostIPs {
		for _, e := range b.ents {
			if !e.hidden && e.ips[ip] {
				return e
			}
		}
	}
	return nil
}

// cosmosURLs maps each route's target host (a container name, or an IP
// for proxied LAN devices) to the URLs that reach it.
func cosmosURLs(routes []obs.CosmosRoute) map[string][]string {
	out := map[string][]string{}
	for _, r := range routes {
		if r.Disabled || r.Host == "" {
			continue
		}
		t, err := url.Parse(r.Target)
		if err != nil || t.Hostname() == "" {
			continue
		}
		u := "https://" + r.Host + r.PathPrefix
		if !slices.Contains(out[t.Hostname()], u) {
			out[t.Hostname()] = append(out[t.Hostname()], u)
		}
	}
	return out
}

// addProxyURLs attaches routes that proxy to a LAN address to that device.
func (b *builder) addProxyURLs(g *Graph, routes map[string][]string) {
	for target, urls := range routes {
		if _, err := netip.ParseAddr(target); err != nil {
			continue
		}
		for i := range g.Nodes {
			if slices.Contains(g.Nodes[i].IPs, target) {
				for _, u := range urls {
					if !slices.Contains(g.Nodes[i].URLs, u) {
						g.Nodes[i].URLs = append(g.Nodes[i].URLs, u)
					}
				}
			}
		}
	}
}

func (b *builder) warnGraph(g *Graph, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if !slices.Contains(g.Warnings, msg) {
		g.Warnings = append(g.Warnings, msg)
	}
}

func containerID(name string) string { return "ctr-" + sanitizeID(name) }

func sanitizeID(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, s)
}

func portString(p obs.DockerPort) string {
	if p.PublicPort == 0 {
		return fmt.Sprintf("%d/%s (not published)", p.PrivatePort, p.Type)
	}
	ip := p.IP
	if ip == "" || ip == "0.0.0.0" || ip == "::" {
		ip = "*"
	}
	return fmt.Sprintf("%s:%d → %d/%s", ip, p.PublicPort, p.PrivatePort, p.Type)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
