package topo

import (
	"cmp"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
)

// CarryOver keeps devices from the previous map that this scan didn't see,
// marked absent, until they haven't been seen for forget. Network gear and
// end devices are carried; VMs and containers are not (the hypervisor
// lists the ones that still exist, running or not), nor are devices
// without a name (an absent "10.20.23.228" tells nobody anything).
//
// It then groups devices that rotated their private MAC (see linkRotated).
func CarryOver(g, prev *Graph, now time.Time, forget time.Duration) {
	if prev != nil {
		carry(g, prev, now, forget)
	}
	linkRotated(g)
}

func carry(g, prev *Graph, now time.Time, forget time.Duration) {
	ids := map[string]bool{}
	macs := map[string]bool{}
	for _, n := range g.Nodes {
		ids[n.ID] = true
		for _, m := range append(slices.Clone(n.MACs), n.OtherMACs...) {
			macs[m] = true
		}
	}
	carried := map[string]bool{}
	for _, p := range prev.Nodes {
		if ids[p.ID] || p.Role == RoleVM || p.Role == RoleContainer || unnamed(p.Label) {
			continue
		}
		if slices.ContainsFunc(p.MACs, func(m string) bool { return macs[m] }) {
			continue // here under another identity
		}
		last := p.LastSeen
		if last.IsZero() {
			last = prev.ScanStarted
		}
		if now.Sub(last) > forget {
			continue
		}
		c := p
		c.Absent, c.Power, c.PowerState, c.New = true, PowerOff, NotSeen, false
		c.LastSeen = last
		if c.Location != "" && !strings.HasPrefix(c.Location, "last seen: ") {
			c.Location = "last seen: " + c.Location
		}
		g.Nodes = append(g.Nodes, c)
		ids[c.ID] = true
		carried[c.ID] = true
	}
	if len(carried) == 0 {
		return
	}
	// Keep the carried devices where they were: their old links, as long
	// as the other end is still on the map.
	have := map[[2]string]bool{}
	for _, e := range g.Edges {
		have[[2]string{e.Source, e.Target}] = true
	}
	for _, e := range prev.Edges {
		if !carried[e.Source] && !carried[e.Target] {
			continue
		}
		if !ids[e.Source] || !ids[e.Target] || have[[2]string{e.Source, e.Target}] {
			continue
		}
		e.ID = "c-" + e.Source + "-" + e.Target
		e.Absent = true
		g.Edges = append(g.Edges, e)
		have[[2]string{e.Source, e.Target}] = true
	}
	for i := range g.Nodes {
		if carried[g.Nodes[i].ID] && !ids[g.Nodes[i].Parent] {
			g.Nodes[i].Parent = ""
		}
	}
	sortNodes(g)
}

// linkRotated merges devices that are one device using successive private
// (randomised) MACs: phones and laptops rotate them, and each new one looks
// like a new device. Two devices are linked when every MAC of both is
// private and they share a specific name (hostname or alias). If two
// devices with that name are present at the same time they really are two,
// and nothing is merged.
func linkRotated(g *Graph) {
	groups := map[string][]int{}
	for i, n := range g.Nodes {
		if k := rotationKey(n); k != "" {
			groups[k] = append(groups[k], i)
		}
	}
	drop := map[string]bool{}
	for _, idx := range groups {
		if len(idx) < 2 {
			continue
		}
		var present []int
		for _, i := range idx {
			if !g.Nodes[i].Absent {
				present = append(present, i)
			}
		}
		if len(present) > 1 {
			continue
		}
		target := slices.MaxFunc(idx, func(a, b int) int {
			na, nb := g.Nodes[a], g.Nodes[b]
			return cmp.Or(cmp.Compare(boolInt(!na.Absent), boolInt(!nb.Absent)), na.LastSeen.Compare(nb.LastSeen))
		})
		t := &g.Nodes[target]
		for _, i := range idx {
			if i == target {
				continue
			}
			o := g.Nodes[i]
			for _, m := range append(slices.Clone(o.MACs), o.OtherMACs...) {
				if !slices.Contains(t.MACs, m) && !slices.Contains(t.OtherMACs, m) {
					t.OtherMACs = append(t.OtherMACs, m)
				}
			}
			if !o.FirstSeen.IsZero() && (t.FirstSeen.IsZero() || o.FirstSeen.Before(t.FirstSeen)) {
				t.FirstSeen = o.FirstSeen
			}
			if o.LastSeen.After(t.LastSeen) && t.Absent {
				t.LastSeen = o.LastSeen
			}
			t.New = false // it was here before, under another MAC
			drop[o.ID] = true
		}
		slices.Sort(t.OtherMACs)
	}
	if len(drop) == 0 {
		return
	}
	g.Nodes = slices.DeleteFunc(g.Nodes, func(n Node) bool { return drop[n.ID] })
	g.Edges = slices.DeleteFunc(g.Edges, func(e Edge) bool { return drop[e.Source] || drop[e.Target] })
}

// genericNames that many devices share by default can't link MACs.
var genericDeviceNames = map[string]bool{
	"iphone": true, "ipad": true, "android": true, "mac": true, "macbook": true, "macbook-pro": true,
	"macbook-air": true, "galaxy": true, "localhost": true, "unknown": true, "phone": true, "laptop": true,
	"desktop": true, "pc": true, "watch": true, "apple-watch": true, "espressif": true,
}

func rotationKey(n Node) string {
	if n.Infra || n.Role == RoleVM || n.Role == RoleContainer || len(n.MACs) == 0 || unnamed(n.Label) {
		return ""
	}
	for _, m := range append(slices.Clone(n.MACs), n.OtherMACs...) {
		if !obs.IsLocallyAdministered(m) {
			return ""
		}
	}
	k := strings.ToLower(strings.TrimSpace(n.Label))
	if genericDeviceNames[k] {
		return ""
	}
	return k
}

// vendorLabel matches labelOf's fallback for nameless devices: "Ubiquiti 5e:5c:f7".
var vendorLabel = regexp.MustCompile(`^\S+ [0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$`)

// unnamed reports labels that are only an address.
func unnamed(label string) bool {
	if label == "" || vendorLabel.MatchString(label) {
		return true
	}
	if _, err := netip.ParseAddr(label); err == nil {
		return true
	}
	_, err := net.ParseMAC(label)
	return err == nil
}

func sortNodes(g *Graph) {
	slices.SortStableFunc(g.Nodes, func(x, y Node) int {
		return cmp.Or(cmp.Compare(x.Depth, y.Depth), strings.Compare(x.Label, y.Label))
	})
}
