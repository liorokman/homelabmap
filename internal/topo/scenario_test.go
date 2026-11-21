package topo

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
)

// MACs in the scenario: a small home network.
const (
	macGW       = "b8:c4:9c:b0:47:a5"
	macCore    = "74:74:83:44:34:68"
	macAcc      = "04:31:23:7f:f1:22"
	macHV      = "d8:3b:42:cb:0a:e6"
	macHVTap   = "fe:12:34:56:78:9a" // host side of a VM tap: must not join hv1's identity
	macLite     = "0c:2e:17:e4:27:a0"
	macHallway  = "38:25:ad:ca:03:6d"
	macDen   = "84:78:48:86:b4:99"
	macCosmos   = "bc:24:11:00:00:28"
	macMon      = "bc:24:11:00:00:10"
	macMacvlan  = "00:16:3e:00:00:77" // something else on hv1's bridge, unknown to PVE
	macDesktop  = "00:d8:61:00:00:05" // on core gi5
	macLaptop   = "00:d8:61:00:00:02" // directly on the gateway's ether2
	macTV       = "00:04:1f:00:00:03" // behind the Lite 8
	macPhone    = "da:a1:19:00:00:01" // randomized Wi-Fi MAC on Hallway
	macTransit  = "00:11:22:99:99:99" // only ever on uplinks: switch-internal noise
	macHVLACP  = "da:3b:42:cb:0a:e6" // hv1's bond/LACP MAC, FDB-only on hv1's port
	ipGW        = "10.20.20.1"
	ipHV       = "10.20.20.98"
	ipCore     = "10.20.20.195"
	ipMon       = "10.20.20.112"
	ipDesktop   = "10.20.22.66"
	ipLaptop    = "10.20.22.163"
	ipTV        = "10.20.22.20"
	ipPhone     = "10.20.22.228"
	ipHallway   = "10.20.23.29"
	ipDen    = "10.20.23.66"
	ipCosmos    = "10.20.23.80"
	ipAcc       = "10.20.23.94"
	ipLite      = "10.20.23.191"
	ipMacvlan   = "10.20.22.7"
	ifCorePo1  = 1000
	ifAccLagHV = 66
	ifAccLagUp  = 67
)

func ifs(names map[int]string, agg map[int]int) []obs.Interface {
	var out []obs.Interface
	for idx, n := range names {
		out = append(out, obs.Interface{Index: idx, Name: n, Up: true, AggIndex: agg[idx]})
	}
	slices.SortFunc(out, func(a, b obs.Interface) int { return a.Index - b.Index })
	return out
}

func fdb(port int, macs ...string) []obs.FDBEntry {
	var out []obs.FDBEntry
	for _, m := range macs {
		out = append(out, obs.FDBEntry{MAC: m, IfIndex: port, VLAN: 1})
	}
	return out
}

func scenario(withUniFi bool) *obs.Result {
	lan := []string{macCore, macAcc, macHV, macLite, macHallway, macDen, macCosmos, macMon,
		macMacvlan, macDesktop, macTV, macPhone}

	gw := obs.SNMPDevice{
		IP: ipGW, SysName: "CCR2004", SysDescr: "RouterOS CCR2004-16G-2S+ 7.15.3 (stable)",
		SysObjectID: "1.3.6.1.4.1.14988.1", Forwarding: true, BridgeMAC: macGW,
		Interfaces: ifs(map[int]string{2: "ether2", 10: "sfp-sfpplus2"}, nil),
		LLDP: []obs.LLDPNeighbor{{LocalPortNum: 10, ChassisSubtype: 4, ChassisID: macCore, PortSubtype: 5,
			PortID: "gi24", SysName: "core", Caps: []string{"bridge"}, MgmtAddrs: []string{ipCore}}},
		FDB: append(fdb(10, lan...), fdb(2, macLaptop)...),
	}
	for ip, mac := range map[string]string{ipHV: macHV, ipCore: macCore, ipMon: macMon, ipDesktop: macDesktop,
		ipLaptop: macLaptop, ipTV: macTV, ipPhone: macPhone, ipHallway: macHallway, ipDen: macDen,
		ipCosmos: macCosmos, ipAcc: macAcc, ipLite: macLite, ipMacvlan: macMacvlan} {
		gw.ARP = append(gw.ARP, obs.ARPEntry{IP: ip, MAC: mac})
	}
	// The USW-24's UniFi fallback address and a Docker bridge must not be shown.
	gw.ARP = append(gw.ARP, obs.ARPEntry{IP: "192.0.2.20", MAC: macAcc}, obs.ARPEntry{IP: "172.17.0.1", MAC: macDesktop})
	slices.SortFunc(gw.ARP, func(a, b obs.ARPEntry) int { return strings.Compare(a.IP, b.IP) })

	core := obs.SNMPDevice{
		IP: ipCore, SysName: "core", SysDescr: "16-Port Gigabit Smart Switch",
		SysObjectID: "1.3.6.1.4.1.9.6.1.1004.16.1", Forwarding: true, BridgeMAC: macCore,
		Interfaces: ifs(map[int]string{5: "GigabitEthernet5", 19: "GigabitEthernet19", 20: "GigabitEthernet20",
			24: "GigabitEthernet24", ifCorePo1: "Port-Channel1"}, map[int]int{19: ifCorePo1, 20: ifCorePo1}),
		LLDP: []obs.LLDPNeighbor{
			// The Cisco small-business switch SNMP bugs: truncated address on one row, none on the others.
			{LocalPortNum: 19, ChassisSubtype: 4, ChassisID: macAcc, PortSubtype: 7, PortID: "Port 16",
				SysName: "USW24PoE", Caps: []string{"bridge"}, MgmtAddrs: []string{"invalid:1.3.10.20.23"}},
			{LocalPortNum: 20, ChassisSubtype: 4, ChassisID: macAcc, PortSubtype: 7, PortID: "Port 15",
				SysName: "USW24PoE", Caps: []string{"bridge"}},
			{LocalPortNum: 24, ChassisSubtype: 4, ChassisID: macGW, PortSubtype: 5, PortID: "sfp-sfpplus2",
				SysName: "CCR2004", Caps: []string{"bridge", "router"}},
		},
		CDP: []obs.CDPNeighbor{{IfIndex: 24, DeviceID: "CCR2004", Address: ipGW, Port: "bridge/sfp-sfpplus2", Platform: "MikroTik"}},
		FDB: append(append(fdb(ifCorePo1, macAcc, macHV, macLite, macHallway, macDen, macCosmos, macMon,
			macMacvlan, macTV, macPhone, macTransit), fdb(5, macDesktop)...), fdb(24, macGW, macLaptop)...),
	}

	accNames := map[int]string{ifAccLagHV: "3/1", ifAccLagUp: "3/2"}
	var accLocal []obs.LLDPLocalPort
	for i := 1; i <= 24; i++ {
		accNames[i] = fmt.Sprintf("0/%d", i)
		accLocal = append(accLocal, obs.LLDPLocalPort{Num: i, IDSubtype: 7, ID: fmt.Sprintf("Port %d", i)})
	}
	hvNbr := func(port int, nic string) obs.LLDPNeighbor {
		return obs.LLDPNeighbor{LocalPortNum: port, ChassisSubtype: 4, ChassisID: macHV, PortSubtype: 5, PortID: nic,
			PortDesc: nic, SysName: "hv1.home.arpa", SysDesc: "Debian GNU/Linux 13 (trixie) Linux 6.8.12-4-pve",
			Caps: []string{"bridge", "wlan-ap"}, MgmtAddrs: []string{ipHV}}
	}
	acc := obs.SNMPDevice{
		IP: ipAcc, SysName: "USW24PoE", SysDescr: "USW-24-PoE, 6.6.61.15220, Linux 3.6.5",
		SysObjectID: "1.3.6.1.4.1.4413", BridgeMAC: macAcc,
		Interfaces: ifs(accNames, map[int]int{5: ifAccLagHV, 6: ifAccLagHV, 15: ifAccLagUp, 16: ifAccLagUp}),
		LLDPLocal:  accLocal,
		LLDP: []obs.LLDPNeighbor{
			hvNbr(5, "eno2"), hvNbr(6, "eno1"),
			{LocalPortNum: 3, ChassisSubtype: 4, ChassisID: macHallway, PortSubtype: 3, PortID: macHallway,
				PortDesc: "eth0", SysName: "Hallway", Caps: []string{"bridge", "wlan-ap"}, MgmtAddrs: []string{ipHallway}},
			{LocalPortNum: 7, ChassisSubtype: 4, ChassisID: macLite, PortSubtype: 3, PortID: macLite,
				PortDesc: "eth0", SysName: "USWLite8", Caps: []string{"bridge"}, MgmtAddrs: []string{ipLite}},
			{LocalPortNum: 15, ChassisSubtype: 4, ChassisID: macCore, PortSubtype: 7, PortID: "gi20",
				SysName: "core", Caps: []string{"bridge"}, MgmtAddrs: []string{ipCore}},
			{LocalPortNum: 16, ChassisSubtype: 4, ChassisID: macCore, PortSubtype: 7, PortID: "gi19",
				SysName: "core", Caps: []string{"bridge"}, MgmtAddrs: []string{ipCore}},
		},
		FDB: append(append(append(
			fdb(ifAccLagHV, macHV, macHVLACP, macCosmos, macMon, macMacvlan),
			fdb(3, macHallway, macPhone)...),
			fdb(7, macLite, macDen, macTV)...),
			fdb(ifAccLagUp, macGW, macDesktop, macLaptop)...),
	}

	hv1 := obs.SNMPDevice{
		IP: ipHV, SysName: "hv1", SysDescr: "Linux hv1 6.8.12-4-pve #2 SMP PREEMPT_DYNAMIC PMX",
		SysObjectID: "1.3.6.1.4.1.8072.3.2.10",
		Interfaces: []obs.Interface{
			{Index: 2, Name: "vmbr0", MAC: macHV, Up: true},
			{Index: 9, Name: "tap100i0", MAC: macHVTap, Up: true},
		},
	}
	lite := obs.SNMPDevice{IP: ipLite, SysName: "USWLite8", SysDescr: "USW-Lite-8 6.5.59.14762", SysObjectID: "1.3.6.1.4.1.8072.3.2.10",
		Interfaces: []obs.Interface{{Index: 2, Name: "eth0", MAC: macLite}}}
	hallway := obs.SNMPDevice{IP: ipHallway, SysName: "Hallway", SysDescr: "U6-Pro 8.0.24.15211", SysObjectID: "1.3.6.1.4.1.41112",
		Interfaces: []obs.Interface{{Index: 2, Name: "br0", MAC: macHallway}}}
	den := obs.SNMPDevice{IP: ipDen, SysName: "Den", SysDescr: "U6-Pro 8.0.24.15211", SysObjectID: "1.3.6.1.4.1.41112",
		Interfaces: []obs.Interface{{Index: 2, Name: "br0", MAC: macDen}}}

	res := &obs.Result{
		JobID: 1, Subnets: []string{"10.20.20.0/22"},
		StartedAt:  time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC),
		FinishedAt: time.Date(2026, 11, 21, 10, 2, 0, 0, time.UTC),
		Self:       obs.Self{Hostname: "cosmos", Interfaces: []obs.SelfIface{{Name: "eth0", MAC: macCosmos, IPs: []string{ipCosmos}}}},
		Sweep: []obs.SweepHost{
			{IP: ipGW, MAC: macGW, Vendor: "Routerboard.com"},
			{IP: ipDesktop, MAC: macDesktop, Vendor: "Micro-Star INTL"},
			{IP: ipLaptop, MAC: macLaptop, Vendor: "Micro-Star INTL"},
			{IP: ipTV, MAC: macTV, Vendor: "Sony"},
			{IP: ipPhone, MAC: macPhone},
			{IP: ipMacvlan, MAC: macMacvlan, Vendor: "Xensource"},
			{IP: ipCosmos}, // the scanner itself: no MAC from nmap
		},
		SNMP: []obs.SNMPDevice{gw, core, acc, hv1, lite, hallway, den},
		PVE: &obs.PVE{Nodes: []obs.PVENode{{Name: "hv1", IP: ipHV, Status: "online", Guests: []obs.PVEGuest{
			{VMID: 100, Name: "cosmos", Type: "qemu", Status: "running", OSType: "l26",
				NICs: []obs.PVENIC{{Name: "net0", MAC: macCosmos, Bridge: "vmbr0"}}, IPs: []string{ipCosmos}},
			{VMID: 101, Name: "monitor", Type: "lxc", Status: "running", OSType: "debian",
				NICs: []obs.PVENIC{{Name: "eth0", MAC: macMon, Bridge: "vmbr0"}}, IPs: []string{ipMon}},
		}}}},
		OSScans: []obs.OSScan{{IP: ipDesktop, MAC: macDesktop, Matched: true, Name: "Microsoft Windows 10 1709 - 21H2",
			Accuracy: 97, Family: "Windows", Type: "general purpose", OpenPorts: []string{"135/tcp msrpc"}}},
		DNS: map[string]string{ipDesktop: "desktop-ab12cd3.home.arpa", ipHV: "hv1.home.arpa"},
	}
	if withUniFi {
		raw := func(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
		res.UniFi = &obs.UniFi{
			Flavor: "legacy",
			Devices: []json.RawMessage{
				raw(map[string]any{"mac": macAcc, "ip": ipAcc, "name": "USW-24", "model": "US24P250", "type": "usw", "version": "6.6.61"}),
				raw(map[string]any{"mac": macLite, "ip": ipLite, "name": "USW Lite 8", "model": "USL8LP", "type": "usw",
					"uplink": map[string]any{"uplink_mac": macAcc, "uplink_remote_port": 7, "port_idx": 1, "type": "wire"}}),
				raw(map[string]any{"mac": macHallway, "ip": ipHallway, "name": "Hallway", "model": "UAP6MP", "type": "uap",
					"uplink": map[string]any{"uplink_mac": macAcc, "uplink_remote_port": 3, "type": "wire"}}),
				raw(map[string]any{"mac": macDen, "ip": ipDen, "name": "Den", "model": "UAP6MP", "type": "uap",
					"uplink": map[string]any{"uplink_mac": macLite, "uplink_remote_port": 4, "type": "wire"}}),
			},
			Clients: []json.RawMessage{
				raw(map[string]any{"mac": macPhone, "ip": ipPhone, "hostname": "Pixel-8", "is_wired": false, "ap_mac": macHallway, "essid": "Home"}),
				raw(map[string]any{"mac": macTV, "ip": ipTV, "hostname": "BRAVIA-XR", "is_wired": true, "sw_mac": macLite, "sw_port": 6}),
			},
		}
	}
	return res
}

type graphView struct {
	t     *testing.T
	g     *Graph
	byMAC map[string]Node
	byID  map[string]Node
}

func view(t *testing.T, g *Graph) graphView {
	v := graphView{t: t, g: g, byMAC: map[string]Node{}, byID: map[string]Node{}}
	for _, n := range g.Nodes {
		v.byID[n.ID] = n
		for _, m := range n.MACs {
			v.byMAC[m] = n
		}
	}
	return v
}

func (v graphView) node(mac string) Node {
	v.t.Helper()
	n, ok := v.byMAC[mac]
	if !ok {
		v.t.Fatalf("no node with MAC %s", mac)
	}
	return n
}

// edges returns the edges between two nodes, in either direction.
func (v graphView) edges(a, b string) []Edge {
	na, nb := v.node(a), v.node(b)
	var out []Edge
	for _, e := range v.g.Edges {
		if (e.Source == na.ID && e.Target == nb.ID) || (e.Source == nb.ID && e.Target == na.ID) {
			out = append(out, e)
		}
	}
	return out
}

// portsOf renders an edge's ports as seen from node a: "aPort<->bPort".
func (v graphView) portsOf(e Edge, a string) string {
	if e.Source == v.node(a).ID {
		return e.SourcePort + "<->" + e.TargetPort
	}
	return e.TargetPort + "<->" + e.SourcePort
}

func TestScenarioInfrastructure(t *testing.T) {
	for _, withUniFi := range []bool{false, true} {
		t.Run(fmt.Sprintf("unifi=%v", withUniFi), func(t *testing.T) {
			v := view(t, Build(1, scenario(withUniFi), History{}))

			roles := map[string]string{
				macGW: RoleRouter, macCore: RoleSwitch, macAcc: RoleSwitch, macLite: RoleSwitch,
				macHallway: RoleAP, macDen: RoleAP, macHV: RoleHypervisor, macCosmos: RoleVM, macMon: RoleContainer,
			}
			for mac, want := range roles {
				if got := v.node(mac).Role; got != want {
					t.Errorf("%s (%s): role %q, want %q", v.node(mac).Label, mac, got, want)
				}
			}
			if d := v.node(macGW).Depth; d != 0 {
				t.Errorf("gateway depth %d", d)
			}

			// gi19/gi20 must match GigabitEthernet19/20 despite the switch's
			// short LLDP names; the LAG shows as two cables.
			var got []string
			for _, e := range v.edges(macAcc, macCore) {
				if e.Kind != KindInfra {
					t.Errorf("USW-24<->core edge kind %q", e.Kind)
				}
				got = append(got, v.portsOf(e, macAcc))
			}
			slices.Sort(got)
			if want := []string{"0/15<->gi20", "0/16<->gi19"}; !slices.Equal(got, want) {
				t.Errorf("USW-24<->core ports %v, want %v", got, want)
			}

			// LLDP and CDP report the same cable once.
			gwc := v.edges(macCore, macGW)
			if len(gwc) != 1 || v.portsOf(gwc[0], macCore) != "gi24<->sfp-sfpplus2" ||
				!slices.Equal(gwc[0].Sources, []string{"cdp", "lldp"}) {
				t.Errorf("core<->gateway: %+v", gwc)
			}
			if gwc[0].Source != v.node(macGW).ID {
				t.Error("edge should point away from the gateway")
			}

			// hv1 hangs off the USW-24 by both bond members; a tap MAC on
			// hv1's ifTable must not become part of hv1.
			if n := len(v.edges(macAcc, macHV)); n != 2 {
				t.Errorf("USW-24<->hv1: %d edges, want 2", n)
			}
			if _, ok := v.byMAC[macHVTap]; ok {
				t.Error("tap interface MAC leaked into the graph")
			}

			found := false
			for _, w := range v.g.Warnings {
				found = found || strings.Contains(w, "invalid LLDP management address") && strings.Contains(w, "1.3.10.20.23")
			}
			if !found {
				t.Errorf("Cisco small-business switch bad address not reported in warnings: %v", v.g.Warnings)
			}

			if _, ok := v.byMAC[macTransit]; ok {
				t.Error("transit-only MAC should be hidden")
			}
			// hv1's bond MAC is hv1's own MAC with the local bit set: it is
			// folded into hv1 rather than becoming a device of its own.
			if n, ok := v.byMAC[macHVLACP]; ok && n.Label != "hv1" {
				t.Errorf("hv1's LACP MAC became device %q", n.Label)
			}
			if ips := v.node(macAcc).IPs; !slices.Equal(ips, []string{ipAcc}) {
				t.Errorf("USW-24 IPs %v: foreign fallback address leaked", ips)
			}

			for _, e := range v.g.Edges {
				if v.byID[e.Source].Depth > v.byID[e.Target].Depth {
					t.Errorf("edge %s->%s points toward the gateway", v.byID[e.Source].Label, v.byID[e.Target].Label)
				}
			}
		})
	}
}

func TestScenarioEdgePlacement(t *testing.T) {
	v := view(t, Build(1, scenario(false), History{}))

	check := func(mac, parentMAC, kind, port string) {
		t.Helper()
		es := v.edges(parentMAC, mac)
		if len(es) != 1 {
			t.Fatalf("%s<->%s: %d edges, want 1", v.node(parentMAC).Label, v.node(mac).Label, len(es))
		}
		e := es[0]
		if e.Kind != kind || e.Source != v.node(parentMAC).ID || e.SourcePort != port {
			t.Errorf("%s: got %s from %s port %q, want %s from %s port %q", v.node(mac).Label,
				e.Kind, v.byID[e.Source].Label, e.SourcePort, kind, v.node(parentMAC).Label, port)
		}
	}

	check(macDesktop, macCore, KindWired, "gi5") // access port on the core
	check(macLaptop, macGW, KindWired, "ether2")  // access port on the gateway
	check(macCosmos, macHV, KindVirtual, "")     // PVE guest, also the scanner host
	check(macMon, macHV, KindVirtual, "")        // LXC
	check(macMacvlan, macHV, KindInferred, "")   // on hv1's port, unknown to PVE
	check(macTV, macLite, KindInferred, "")       // Lite 8 has no MAC table
	check(macDen, macLite, KindInferred, "")   // AP behind the Lite 8
	check(macPhone, macHallway, KindInferred, "") // Wi-Fi client, without UniFi data

	if c := v.node(macCosmos); c.Parent != v.node(macHV).ID || c.Location != "VM on hv1" {
		t.Errorf("cosmos: parent %q location %q", c.Parent, c.Location)
	}
	if l := v.node(macDesktop).Location; l != "core port gi5" {
		t.Errorf("desktop location %q", l)
	}
}

func TestScenarioEdgePlacementWithUniFi(t *testing.T) {
	v := view(t, Build(1, scenario(true), History{}))

	phone := v.edges(macHallway, macPhone)
	if len(phone) != 1 || phone[0].Kind != KindWireless {
		t.Fatalf("phone: %+v", phone)
	}
	if l := v.node(macPhone).Location; l != "Wi-Fi via Hallway (Home)" {
		t.Errorf("phone location %q", l)
	}
	tv := v.edges(macLite, macTV)
	if len(tv) != 1 || tv[0].Kind != KindWired || tv[0].SourcePort != "port 6" {
		t.Errorf("tv: %+v", tv)
	}
	lr := v.edges(macLite, macDen)
	if len(lr) != 1 || lr[0].Kind != KindInfra || lr[0].SourcePort != "port 4" {
		t.Errorf("den room AP uplink: %+v", lr)
	}
	// UniFi's name for the Lite 8 wins over its SNMP sysName.
	if l := v.node(macLite).Label; l != "USW Lite 8" {
		t.Errorf("lite label %q", l)
	}
}

func TestScenarioOSAndIcons(t *testing.T) {
	v := view(t, Build(1, scenario(true), History{}))
	tests := []struct {
		mac, icon, osContains, source string
	}{
		{macDesktop, IconWindows, "Windows 10", "nmap (97%)"},
		{macHV, IconProxmox, "Proxmox VE", "pve"},
		{macMon, IconDebian, "Debian", "pve"},
		{macCosmos, IconLinux, "Linux", "pve"},
		{macPhone, IconAndroid, "Android", "name"},
		{macTV, IconMedia, "Media", "name"},
		{macCore, IconSwitch, "Cisco", "snmp"},
		{macGW, IconRouter, "MikroTik", "snmp"},
		{macHallway, IconAP, "UniFi", "unifi"},
	}
	for _, tt := range tests {
		n := v.node(tt.mac)
		if n.Icon != tt.icon || !strings.Contains(n.OS, tt.osContains) || n.OSSource != tt.source {
			t.Errorf("%s: icon %q os %q (%s); want icon %q, os containing %q (%s)",
				n.Label, n.Icon, n.OS, n.OSSource, tt.icon, tt.osContains, tt.source)
		}
	}
	d := v.node(macDesktop)
	if !slices.Equal(d.DNS, []string{"desktop-ab12cd3.home.arpa"}) || !slices.Equal(d.IPs, []string{ipDesktop}) ||
		d.MACs[0] != macDesktop || d.Vendor != "Micro-Star INTL" || len(d.OpenPorts) != 1 {
		t.Errorf("desktop details: %+v", d)
	}
}

func TestScenarioWithoutPVE(t *testing.T) {
	res := scenario(false)
	res.PVE = nil
	v := view(t, Build(1, res, History{}))
	hv1 := v.node(macHV)
	if hv1.Role != RoleHypervisor || hv1.Icon != IconProxmox {
		t.Errorf("hv1 without PVE data: role %q icon %q", hv1.Role, hv1.Icon)
	}
	// Guests are still placed behind hv1, just inferred instead of reported.
	if es := v.edges(macHV, macCosmos); len(es) != 1 || es[0].Kind != KindInferred {
		t.Errorf("cosmos without PVE: %+v", es)
	}
	if r := v.node(macMacvlan).Role; r != RoleVM {
		t.Errorf("unknown device behind a hypervisor: role %q, want vm", r)
	}
}

func TestScenarioNewDevices(t *testing.T) {
	res := scenario(false)
	hist := History{
		Since:     res.StartedAt.Add(-30 * 24 * time.Hour),
		FirstSeen: map[string]time.Time{},
	}
	for _, m := range []string{macGW, macCore, macAcc, macHV, macDesktop} {
		hist.FirstSeen[m] = hist.Since
	}
	hist.FirstSeen[macTV] = res.StartedAt.Add(-2 * time.Hour)
	v := view(t, Build(1, res, hist))
	if !v.node(macTV).New {
		t.Error("device first seen 2h ago should be new")
	}
	if v.node(macDesktop).New {
		t.Error("old device marked new")
	}

	// Without a day of history nothing is "new".
	v = view(t, Build(1, res, History{Since: res.StartedAt}))
	if v.node(macTV).New {
		t.Error("first-day scan should not mark anything new")
	}
}

func TestBuildIsStable(t *testing.T) {
	a, _ := json.Marshal(Build(1, scenario(true), History{}))
	for range 20 {
		b, _ := json.Marshal(Build(1, scenario(true), History{}))
		if string(a) != string(b) {
			t.Fatal("Build output differs between runs (map iteration order leak)")
		}
	}
}
