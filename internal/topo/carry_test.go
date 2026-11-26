package topo

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
)

var tNow = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func nodeByLabel(g *Graph, label string) *Node {
	for i := range g.Nodes {
		if g.Nodes[i].Label == label {
			return &g.Nodes[i]
		}
	}
	return nil
}

func TestCarryOver(t *testing.T) {
	prev := &Graph{ScanStarted: tNow.Add(-time.Hour), Nodes: []Node{
		{ID: "n-sw", Label: "switch", Role: RoleSwitch, Infra: true, MACs: []string{"00:00:00:00:00:01"}, LastSeen: tNow.Add(-time.Hour)},
		{ID: "n-tv", Label: "tv", Role: RoleClient, MACs: []string{"00:00:00:00:00:02"}, Parent: "n-sw",
			Location: "switch port 3", LastSeen: tNow.Add(-2 * time.Hour), Power: PowerOn, New: true},
		{ID: "n-old", Label: "ancient", Role: RoleClient, MACs: []string{"00:00:00:00:00:03"}, LastSeen: tNow.Add(-40 * 24 * time.Hour)},
		{ID: "n-vm", Label: "deleted-vm", Role: RoleVM, MACs: []string{"bc:24:11:00:00:04"}, LastSeen: tNow.Add(-time.Hour)},
		{ID: "n-ip", Label: "10.20.23.228", Role: RoleClient, MACs: []string{"00:00:00:00:00:05"}, LastSeen: tNow.Add(-time.Hour)},
		{ID: "n-moved", Label: "laptop", Role: RoleClient, MACs: []string{"00:00:00:00:00:06"}, LastSeen: tNow.Add(-time.Hour)},
	}, Edges: []Edge{
		{ID: "e1", Source: "n-sw", Target: "n-tv", Kind: KindWired, SourcePort: "3"},
		{ID: "e2", Source: "n-sw", Target: "n-ip", Kind: KindWired},
	}}
	g := &Graph{Nodes: []Node{
		{ID: "n-sw", Label: "switch", Role: RoleSwitch, Infra: true, MACs: []string{"00:00:00:00:00:01"}},
		// Same device, now known by another primary MAC.
		{ID: "n-laptop2", Label: "laptop", Role: RoleClient, MACs: []string{"00:00:00:00:00:07", "00:00:00:00:00:06"}},
	}}
	CarryOver(g, prev, tNow, 30*24*time.Hour)

	tv := nodeByLabel(g, "tv")
	if tv == nil || !tv.Absent || tv.Power != PowerOff || tv.PowerState != NotSeen || tv.New ||
		tv.Location != "last seen: switch port 3" || !tv.LastSeen.Equal(tNow.Add(-2*time.Hour)) || tv.Parent != "n-sw" {
		t.Fatalf("carried tv: %+v", tv)
	}
	for _, gone := range []string{"ancient", "deleted-vm", "10.20.23.228"} {
		if nodeByLabel(g, gone) != nil {
			t.Errorf("%s should not be carried", gone)
		}
	}
	if n := len(g.Nodes); n != 3 {
		t.Errorf("nodes: %d %+v", n, g.Nodes)
	}
	if len(g.Edges) != 1 || g.Edges[0].Target != "n-tv" || !g.Edges[0].Absent || g.Edges[0].SourcePort != "3" {
		t.Errorf("edges: %+v", g.Edges)
	}

	// Carrying again keeps the original last-seen and doesn't stack prefixes.
	g2 := &Graph{Nodes: []Node{{ID: "n-sw", Label: "switch", Role: RoleSwitch, Infra: true, MACs: []string{"00:00:00:00:00:01"}}}}
	CarryOver(g2, g, tNow.Add(time.Hour), 30*24*time.Hour)
	if tv := nodeByLabel(g2, "tv"); tv == nil || tv.Location != "last seen: switch port 3" || !tv.LastSeen.Equal(tNow.Add(-2*time.Hour)) {
		t.Errorf("second carry: %+v", tv)
	}
}

func TestLinkRotatedMACs(t *testing.T) {
	priv := func(n int) string { return "da:00:00:00:00:0" + string(rune('0'+n)) }
	g := &Graph{Nodes: []Node{
		{ID: "a", Label: "Sam-s-S23-Ultra", Role: RoleClient, MACs: []string{priv(1)}, FirstSeen: tNow.Add(-time.Hour), New: true},
		{ID: "b", Label: "Sam-s-S23-Ultra", Role: RoleClient, MACs: []string{priv(2)}, Absent: true, FirstSeen: tNow.Add(-90 * 24 * time.Hour)},
		{ID: "c", Label: "sam-s-s23-ultra", Role: RoleClient, MACs: []string{priv(3)}, Absent: true, OtherMACs: []string{priv(4)}},
		// Two present devices with the same name are two devices.
		{ID: "d", Label: "Alex-s-S25", Role: RoleClient, MACs: []string{priv(5)}},
		{ID: "e", Label: "Alex-s-S25", Role: RoleClient, MACs: []string{priv(6)}},
		// Generic names never link.
		{ID: "f", Label: "iPhone", Role: RoleClient, MACs: []string{priv(7)}},
		{ID: "g", Label: "iPhone", Role: RoleClient, MACs: []string{priv(8)}, Absent: true},
		// A global (burned-in) MAC is not a rotation.
		{ID: "h", Label: "CONSOLE", Role: RoleClient, MACs: []string{"50:41:89:c3:b5:40"}},
		{ID: "i", Label: "CONSOLE", Role: RoleClient, MACs: []string{"88:5b:3c:d8:8f:32"}, Absent: true},
	}, Edges: []Edge{{ID: "x", Source: "ap", Target: "b"}, {ID: "y", Source: "ap", Target: "a"}}}
	linkRotated(g)

	ids := []string{}
	for _, n := range g.Nodes {
		ids = append(ids, n.ID)
	}
	if strings.Join(ids, ",") != "a,d,e,f,g,h,i" {
		t.Fatalf("remaining nodes: %v", ids)
	}
	a := g.Nodes[0]
	if !slices.Equal(a.OtherMACs, []string{priv(2), priv(3), priv(4)}) || a.New || !a.FirstSeen.Equal(tNow.Add(-90*24*time.Hour)) {
		t.Errorf("merged phone: %+v", a)
	}
	if len(g.Edges) != 1 || g.Edges[0].ID != "y" {
		t.Errorf("edges of merged nodes must go: %+v", g.Edges)
	}

	// All absent: the most recently seen one keeps the rest.
	g = &Graph{Nodes: []Node{
		{ID: "old", Label: "Alex-s-S23", Role: RoleClient, MACs: []string{priv(1)}, Absent: true, LastSeen: tNow.Add(-48 * time.Hour)},
		{ID: "new", Label: "Alex-s-S23", Role: RoleClient, MACs: []string{priv(2)}, Absent: true, LastSeen: tNow.Add(-time.Hour)},
	}}
	linkRotated(g)
	if len(g.Nodes) != 1 || g.Nodes[0].ID != "new" || !slices.Equal(g.Nodes[0].OtherMACs, []string{priv(1)}) {
		t.Errorf("all absent: %+v", g.Nodes)
	}
}

func TestUnnamed(t *testing.T) {
	for label, want := range map[string]bool{
		"": true, "10.20.23.228": true, "da:3b:42:cb:0a:e6": true, "Ubiquiti 5e:5c:f7": true,
		"tv": false, "Alex-s-S25": false, "Télé – Salon": false,
	} {
		if got := unnamed(label); got != want {
			t.Errorf("unnamed(%q) = %v", label, got)
		}
	}
}

func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func TestUniFiHistoryAliasesAndSSDP(t *testing.T) {
	ap := "e8:c5:bc:4a:e8:0e"
	res := &obs.Result{
		StartedAt: tNow, Subnets: []string{"10.20.20.0/22"},
		Sweep: []obs.SweepHost{
			{IP: "10.20.23.89", MAC: ap},
			{IP: "10.20.23.173", MAC: "da:00:00:00:00:01"},
			{IP: "10.20.23.149", MAC: "00:09:b0:00:00:13", Vendor: "D&M Holdings Inc."},
			{IP: "10.20.23.66", MAC: "00:11:22:33:44:20"},
		},
		UniFi: obs.UniFiList{{Flavor: "legacy",
			Devices: []json.RawMessage{raw(map[string]any{"mac": ap, "ip": "10.20.23.89", "name": "Office", "type": "uap", "model": "UAP6MP"})},
			Clients: []json.RawMessage{
				raw(map[string]any{"mac": "da:00:00:00:00:01", "ip": "10.20.23.173", "hostname": "Alex-s-S25", "is_wired": false, "ap_mac": ap,
					"first_seen": tNow.Add(-24 * time.Hour).Unix(), "last_seen": tNow.Unix()}),
				raw(map[string]any{"mac": "00:09:b0:00:00:13", "ip": "10.20.23.149", "hostname": "avr-den", "is_wired": false, "ap_mac": ap}),
				raw(map[string]any{"mac": "00:11:22:33:44:20", "ip": "10.20.23.66", "hostname": "nas-thing", "is_wired": false, "ap_mac": ap}),
			},
			Known: []json.RawMessage{
				raw(map[string]any{"mac": "00:11:22:33:44:20", "name": "Den NAS", "first_seen": tNow.Add(-5 * 365 * 24 * time.Hour).Unix()}),
			},
			History: []json.RawMessage{
				// The same phone under an older private MAC.
				raw(map[string]any{"mac": "c2:9e:9b:0f:a9:14", "hostname": "Alex-s-S25", "type": "WIRELESS", "last_uplink_mac": ap,
					"first_seen": tNow.Add(-60 * 24 * time.Hour).Unix(), "last_seen": tNow.Add(-20 * 24 * time.Hour).Unix(), "last_ip": "10.20.23.66"}),
				// A watch that is off now.
				raw(map[string]any{"mac": "d2:cc:0a:83:b5:25", "hostname": "SM-R960", "type": "WIRELESS", "last_uplink_mac": ap,
					"last_seen": tNow.Add(-3 * time.Hour).Unix()}),
				// Nameless and absent: noise.
				raw(map[string]any{"mac": "92:23:b5:a2:ee:26", "type": "WIRED", "last_uplink_mac": ap}),
				// Connected right now: history doesn't override it.
				raw(map[string]any{"mac": "00:11:22:33:44:20", "hostname": "stale", "type": "WIRED"}),
			},
		}},
		SSDP: []obs.SSDPDevice{{IP: "10.20.23.149", FriendlyName: "Denon AVR-X1700H 5A3C1F", Manufacturer: "D&M Holdings",
			ModelName: "AVR-X1700H", DeviceType: "urn:schemas-upnp-org:device:MediaRenderer:2", Server: "Linux/3.19.0 UPnP/1.0 GUPnP/0.20.13"}},
	}
	g := Build(1, res, History{})

	phone := nodeByLabel(g, "Alex-s-S25")
	if phone == nil || phone.Absent || !slices.Equal(phone.OtherMACs, []string{"c2:9e:9b:0f:a9:14"}) ||
		!phone.FirstSeen.Equal(tNow.Add(-60*24*time.Hour)) {
		t.Errorf("phone with an earlier private MAC: %+v", phone)
	}
	watch := nodeByLabel(g, "SM-R960")
	if watch == nil || !watch.Absent || watch.Power != PowerOff || watch.Location != "last seen: Wi-Fi via Office" ||
		!watch.LastSeen.Equal(tNow.Add(-3*time.Hour)) || len(watch.IPs) != 0 {
		t.Errorf("absent watch: %+v", watch)
	}
	for _, n := range g.Nodes {
		if slices.Contains(n.MACs, "92:23:b5:a2:ee:26") {
			t.Errorf("nameless absent MAC shown: %+v", n)
		}
		for _, e := range g.Edges {
			if (e.Source == n.ID || e.Target == n.ID) && n.Absent != e.Absent && !n.Infra {
				t.Errorf("edge %+v absent flag doesn't match %s", e, n.Label)
			}
		}
	}
	nas := nodeByLabel(g, "Den NAS")
	if nas == nil || nas.Absent || !nas.FirstSeen.Equal(tNow.Add(-5*365*24*time.Hour)) {
		t.Errorf("alias and controller first-seen: %+v", nas)
	}
	avr := nodeByLabel(g, "Denon AVR-X1700H 5A3C1F")
	if avr == nil || avr.Icon != IconMedia || avr.OSSource != "ssdp" || avr.Model != "D&M Holdings AVR-X1700H" {
		t.Errorf("SSDP receiver: %+v", avr)
	}
}

func TestSSDPOS(t *testing.T) {
	cases := []struct {
		d    obs.SSDPDevice
		icon string
		name string
	}{
		{obs.SSDPDevice{FriendlyName: "CONSOLE", Manufacturer: "Microsoft Corporation", ModelName: "Xbox Series S", Server: "Microsoft-Windows/10.0 UPnP/1.0"}, IconGaming, "Game console (Microsoft Corporation Xbox Series S)"},
		{obs.SSDPDevice{Manufacturer: "LG Electronics.", ModelName: "LG Smart TV", Server: "Linux/i686 UPnP/1,0 DLNADOC/1.50 LGE WebOS TV/Version 0.9"}, IconMedia, "LG webOS TV (LG Smart TV)"},
		{obs.SSDPDevice{Manufacturer: "Example Media", ModelName: "StreamBox", DeviceType: "urn:dial-multiscreen-org:device:dial:1", Server: "Linux/5.15.170-android14-11, UPnP/1.0, Chromecast/1.6.18"}, IconMedia, "Android TV (Example Media StreamBox)"},
		{obs.SSDPDevice{Manufacturer: "Synology Inc", ModelName: "DS920+"}, IconNAS, "NAS (Synology Inc DS920+)"},
		{obs.SSDPDevice{Manufacturer: "MikroTik", ModelName: "CCR2004", DeviceType: "urn:schemas-upnp-org:device:InternetGatewayDevice:1"}, "", ""},
	}
	for _, c := range cases {
		g := ssdpOS(&c.d)
		if g.icon != c.icon || g.name != c.name {
			t.Errorf("%+v: got %q %q", c.d, g.icon, g.name)
		}
	}
	if m := ssdpModel(&obs.SSDPDevice{Manufacturer: "LG Electronics.", ModelName: "LG Smart TV"}); m != "LG Smart TV" {
		t.Errorf("maker not repeated: %q", m)
	}
}

func TestLocalVariantsFoldIntoHost(t *testing.T) {
	res := &obs.Result{Subnets: []string{"10.0.0.0/24"}, Sweep: []obs.SweepHost{
		{IP: "10.0.0.2", MAC: "d8:3b:42:cb:0a:e6"},
		{IP: "10.0.0.9", MAC: "d8:3b:42:d2:ee:4f"}, // another box, different prefix
	}, UniFi: obs.UniFiList{{Flavor: "legacy", Clients: []json.RawMessage{
		raw(map[string]any{"mac": "da:3b:42:cb:0a:e6", "is_wired": true}), // exact variant
		raw(map[string]any{"mac": "da:3b:42:cb:0a:f3", "is_wired": true}), // second port of the same NIC
		raw(map[string]any{"mac": "da:3b:42:d2:ee:d1", "is_wired": true}), // prefix shared by no burned-in MAC... except 10.0.0.9's
		raw(map[string]any{"mac": "da:a1:19:00:00:01", "is_wired": false}),
	}}}}
	g := Build(1, res, History{})
	owner := map[string]string{}
	for _, n := range g.Nodes {
		for _, m := range n.MACs {
			owner[m] = n.ID
		}
	}
	if owner["da:3b:42:cb:0a:e6"] != owner["d8:3b:42:cb:0a:e6"] || owner["da:3b:42:cb:0a:f3"] != owner["d8:3b:42:cb:0a:e6"] {
		t.Errorf("variants not folded into the host: %v", owner)
	}
	if owner["da:3b:42:d2:ee:d1"] != owner["d8:3b:42:d2:ee:4f"] {
		t.Errorf("prefix variant: %v", owner)
	}
	if owner["da:a1:19:00:00:01"] == owner["d8:3b:42:cb:0a:e6"] {
		t.Error("unrelated private MAC folded")
	}
}

func TestGlobalVariant(t *testing.T) {
	if g := globalVariant("da:3b:42:cb:0a:e6"); g != "d8:3b:42:cb:0a:e6" {
		t.Errorf("got %q", g)
	}
	if g := globalVariant("nope"); g != "" {
		t.Errorf("got %q", g)
	}
}
