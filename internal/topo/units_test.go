package topo

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
)

func TestShortIfAndNormPort(t *testing.T) {
	tests := []struct{ in, short, norm string }{
		{"GigabitEthernet19", "gi19", "gi19"},
		{"TenGigabitEthernet1/0/1", "te1/0/1", "te1/0/1"},
		{"Port-Channel1", "po1", "po1"},
		{"FastEthernet0/1", "fa0/1", "fa0/1"},
		{"Port 15", "Port 15", "port15"},
		{"sfp-sfpplus2", "sfp-sfpplus2", "sfp-sfpplus2"},
	}
	for _, tt := range tests {
		if got := shortIf(tt.in); got != tt.short {
			t.Errorf("shortIf(%q) = %q, want %q", tt.in, got, tt.short)
		}
		if got := normPort(tt.in); got != tt.norm {
			t.Errorf("normPort(%q) = %q, want %q", tt.in, got, tt.norm)
		}
	}
}

func TestResolvePort(t *testing.T) {
	core := &entity{snmp: []*obs.SNMPDevice{{Interfaces: []obs.Interface{
		{Index: 19, Name: "GigabitEthernet19"}, {Index: 24, Name: "GigabitEthernet24", Alias: "uplink"},
	}}}}
	acc := &entity{snmp: []*obs.SNMPDevice{{
		Interfaces: []obs.Interface{{Index: 15, Name: "0/15"}},
		LLDPLocal:  []obs.LLDPLocalPort{{Num: 15, IDSubtype: 7, ID: "Port 15", Desc: "SFP 2"}},
	}}}
	gw := &entity{snmp: []*obs.SNMPDevice{{Interfaces: []obs.Interface{{Index: 10, Name: "sfp-sfpplus2"}}}}}
	noSNMP := &entity{}

	tests := []struct {
		name    string
		e       *entity
		cands   []string
		label   string
		ifIndex int
	}{
		{"short name to long ifName", core, []string{"gi19"}, "gi19", 19},
		{"by alias", core, []string{"uplink"}, "gi24", 24},
		{"LLDP local port id", acc, []string{"Port 15"}, "0/15", 15},
		{"LLDP local port desc", acc, []string{"SFP 2"}, "0/15", 15},
		{"CDP bridge/ prefix", gw, []string{"bridge/sfp-sfpplus2"}, "sfp-sfpplus2", 10},
		{"no SNMP: name over MAC", noSNMP, []string{"38:25:ad:ca:03:6d", "eth0"}, "eth0", 0},
		{"no SNMP: only MAC", noSNMP, []string{"38:25:ad:ca:03:6d"}, "38:25:ad:ca:03:6d", 0},
		{"unknown port on SNMP device", core, []string{"gi99"}, "gi99", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			label, idx := resolvePort(tt.e, tt.cands...)
			if label != tt.label || idx != tt.ifIndex {
				t.Errorf("got %q/%d, want %q/%d", label, idx, tt.label, tt.ifIndex)
			}
		})
	}
}

func TestParseUniFiIntegrationFlavor(t *testing.T) {
	u := &obs.UniFi{
		Flavor: "integration",
		Devices: []json.RawMessage{
			json.RawMessage(`{"id":"d1","macAddress":"04:31:23:7F:F1:22","ipAddress":"10.20.23.94","name":"USW-24","model":"USW 24 PoE","features":["switching"],"firmwareVersion":"6.6.61"}`),
			json.RawMessage(`{"id":"d2","macAddress":"38:25:ad:ca:03:6d","name":"Hallway","model":"U6 Pro","features":["accessPoint"],"uplink":{"deviceId":"d1"}}`),
		},
		Clients: []json.RawMessage{
			json.RawMessage(`{"type":"WIRELESS","id":"c1","name":"Pixel-8","macAddress":"da:a1:19:00:00:01","ipAddress":"10.20.22.228","uplinkDeviceId":"d2"}`),
			json.RawMessage(`{"type":"VPN","id":"c2","name":"road warrior"}`),
		},
	}
	devs, clients := parseUniFi(u)
	if len(devs) != 2 || devs[0].Type != "usw" || devs[1].Type != "uap" || devs[1].UplinkID != "d1" || devs[0].Version != "6.6.61" {
		t.Errorf("devices: %+v", devs)
	}
	if len(clients) != 1 {
		t.Fatalf("clients without a MAC must be dropped: %+v", clients)
	}
	c := clients[0]
	if c.MAC != "da:a1:19:00:00:01" || c.Wired || !c.WiredKnown || c.UplinkID != "d2" {
		t.Errorf("client: %+v", c)
	}
}

func TestUniTypeFromModel(t *testing.T) {
	for model, want := range map[string]string{"UDM-Pro": "ugw", "UCG-Ultra": "ugw", "USW-Lite-8": "usw", "US24P250": "usw", "U6-Pro": "uap", "UAP-AC-Pro": "uap", "": ""} {
		if got := uniTypeFromModel(model); got != want {
			t.Errorf("uniTypeFromModel(%q) = %q, want %q", model, got, want)
		}
	}
}

func TestSNMPOS(t *testing.T) {
	tests := []struct {
		descr, oid string
		pveNode    bool
		name, icon string
	}{
		{"Linux hv1 6.8.12-4-pve #2 SMP", "1.3.6.1.4.1.8072.3.2.10", true, "Proxmox VE (Linux 6.8.12-4-pve)", IconProxmox},
		{"Linux monitor 6.8.12-4-pve #2 SMP", "1.3.6.1.4.1.8072.3.2.10", false, "Linux (Proxmox kernel 6.8.12-4-pve)", IconLinux},
		{"Linux web 6.1.0-18-amd64 #1 SMP", "1.3.6.1.4.1.8072.3.2.10", false, "Linux 6.1.0-18-amd64", IconLinux},
		{"USW-24-PoE, 6.6.61.15220, Linux 3.6.5", "1.3.6.1.4.1.4413", false, "UniFi USW-24-PoE (firmware 6.6.61.15220)", ""},
		{"U6-Pro 8.0.24.15211", "1.3.6.1.4.1.41112", false, "UniFi U6-Pro (firmware 8.0.24.15211)", ""},
		{"Hardware: Intel64 - Software: Windows Version 6.3", "1.3.6.1.4.1.311.1.1.3.1.1", false, "Hardware: Intel64 - Software: Windows Version 6.3", IconWindows},
	}
	for _, tt := range tests {
		e := &entity{}
		if tt.pveNode {
			e.pveNode = &obs.PVENode{Name: "hv1"}
		}
		g := snmpOS(e, &obs.SNMPDevice{SysDescr: tt.descr, SysObjectID: tt.oid})
		if g.name != tt.name || g.icon != tt.icon {
			t.Errorf("snmpOS(%q) = %q/%q, want %q/%q", tt.descr, g.name, g.icon, tt.name, tt.icon)
		}
	}
}

func TestNmapOS(t *testing.T) {
	g := nmapOS(obs.OSScan{Matched: true, Name: "Apple iOS 16", Accuracy: 92, Family: "iOS", Type: "phone"})
	if g.icon != IconApple || g.score != 65 {
		t.Errorf("iOS phone: %+v", g)
	}
	g = nmapOS(obs.OSScan{Matched: true, Name: "HP LaserJet", Accuracy: 99, Type: "printer"})
	if g.icon != IconPrinter || g.score != 75 {
		t.Errorf("printer: %+v", g)
	}
	if g := nmapOS(obs.OSScan{Matched: false}); g.score != 0 {
		t.Errorf("unmatched scan must not vote: %+v", g)
	}
}

func TestIdentifyOSPrecedence(t *testing.T) {
	b := &builder{osScans: map[string]obs.OSScan{
		"00:00:00:00:00:01": {MAC: "00:00:00:00:00:01", Matched: true, Name: "Linux 5.x", Accuracy: 96, Family: "Linux"},
	}, res: &obs.Result{}}
	// A PVE guest type beats nmap; nmap beats a hostname hint.
	e := &entity{macs: map[string]bool{"00:00:00:00:00:01": true}, ips: map[string]bool{},
		guest: &obs.PVEGuest{Type: "qemu", OSType: "win11"}, ucli: &uniClient{Name: "raspberrypi"}}
	if g := b.identifyOS(e); g.name != "Windows 11" || g.source != "pve" {
		t.Errorf("guest type should win: %+v", g)
	}
	e.guest = nil
	if g := b.identifyOS(e); g.name != "Linux 5.x" {
		t.Errorf("nmap should beat hostname: %+v", g)
	}
	// A randomized MAC means "phone or laptop" only for Wi-Fi devices; behind
	// a hypervisor it is just a VM with a random MAC.
	e2 := &entity{macs: map[string]bool{"da:a1:19:00:00:01": true}, ips: map[string]bool{}, connection: KindWireless}
	if g := b.identifyOS(e2); g.icon != IconPhone {
		t.Errorf("private MAC on Wi-Fi: %+v", g)
	}
	e2.connection, e2.behind = KindInferred, &entity{role: RoleHypervisor}
	if g := b.identifyOS(e2); g.score != 0 {
		t.Errorf("private MAC behind a hypervisor must not guess: %+v", g)
	}
}

func TestHostnameRulesSamsung(t *testing.T) {
	b := &builder{osScans: map[string]obs.OSScan{}, res: &obs.Result{}}
	for _, name := range []string{"Alex-s-S23", "Sam-s-S23-Ultra", "kim-s-S25-FE", "Alex-s-Tab-S9", "h-Robin-sl-Tab-S6-Lite", "Galaxy-A54-5G", "Alex-s-S23.home.arpa"} {
		e := &entity{macs: map[string]bool{}, ips: map[string]bool{}, ucli: &uniClient{Name: name}}
		if g := b.identifyOS(e); g.icon != IconAndroid {
			t.Errorf("%s: %+v", name, g)
		}
	}
	for _, name := range []string{"storage", "smtp", "backup", "PatLaptop"} {
		e := &entity{macs: map[string]bool{}, ips: map[string]bool{}, ucli: &uniClient{Name: name}}
		if g := b.identifyOS(e); g.icon == IconAndroid {
			t.Errorf("%s misdetected as Android", name)
		}
	}
	e := &entity{macs: map[string]bool{}, ips: map[string]bool{}, ucli: &uniClient{Name: "roborock-vacuum-a15"}}
	if g := b.identifyOS(e); g.icon != IconIoT {
		t.Errorf("roborock-vacuum-a15: %+v", g)
	}
}

func TestNoSelfNoGhostNode(t *testing.T) {
	g := Build(1, &obs.Result{Sweep: []obs.SweepHost{{IP: "10.0.0.5", MAC: "00:00:5e:00:00:05"}}}, History{})
	if len(g.Nodes) != 1 || g.Nodes[0].Label == "" {
		t.Errorf("want exactly the swept host, got %+v", g.Nodes)
	}
}

func TestUniOffline(t *testing.T) {
	for raw, want := range map[string]bool{
		`1`: false, `0`: true, `4`: false, // classic: connected, disconnected, upgrading
		`"ONLINE"`: false, `"OFFLINE"`: true, `"PENDING_ADOPTION"`: false, // integration
		``: false, `null`: false,
	} {
		if got := uniOffline(json.RawMessage(raw)); got != want {
			t.Errorf("uniOffline(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestPower(t *testing.T) {
	res := &obs.Result{
		Sweep: []obs.SweepHost{
			{IP: "10.0.0.2", MAC: "02:00:00:00:00:02"}, // hv1
			{IP: "10.0.0.10", MAC: "bc:24:11:00:00:10"},
			{IP: "10.0.0.20", MAC: "00:11:22:33:44:55"},
		},
		PVE: &obs.PVE{Nodes: []obs.PVENode{{Name: "hv1", IP: "10.0.0.2", Status: "online", Guests: []obs.PVEGuest{
			{VMID: 100, Name: "up", Type: "qemu", Status: "running", NICs: []obs.PVENIC{{Name: "net0", MAC: "bc:24:11:00:00:10", Bridge: "vmbr0"}}, IPs: []string{"10.0.0.10"}},
			{VMID: 101, Name: "down", Type: "lxc", Status: "stopped", NICs: []obs.PVENIC{{Name: "eth0", MAC: "bc:24:11:00:00:11", Bridge: "vmbr0"}}},
			{VMID: 102, Name: "sleepy", Type: "qemu", Status: "paused", NICs: []obs.PVENIC{{Name: "net0", MAC: "bc:24:11:00:00:12", Bridge: "vmbr0"}}},
		}}}},
		SNMP: []obs.SNMPDevice{{IP: "10.0.0.1", SysName: "gw", Forwarding: true,
			ARP: []obs.ARPEntry{{IP: "10.0.0.30", MAC: "00:aa:bb:cc:dd:ee"}}}},
	}
	g := Build(1, res, History{})
	want := map[string][2]string{
		"up": {PowerOn, "running"}, "down": {PowerOff, "stopped"}, "sleepy": {PowerOff, "paused"},
		"hv1": {PowerOn, "online"}, "10.0.0.20": {PowerOn, ""},
	}
	got := map[string][2]string{}
	for _, n := range g.Nodes {
		got[n.Label] = [2]string{n.Power, n.PowerState}
	}
	for label, w := range want {
		if got[label] != w {
			t.Errorf("%s: power %v, want %v (all: %v)", label, got[label], w, got)
		}
	}
	if p, ok := got["10.0.0.30"]; ok && p[0] != "" {
		t.Errorf("ARP-only host must have unknown power, got %v", p)
	}
}

func TestParseUniFiOfflineDevice(t *testing.T) {
	u := &obs.UniFi{Flavor: "legacy", Devices: []json.RawMessage{
		json.RawMessage(`{"mac":"38:25:ad:ca:03:6d","name":"Hallway","type":"uap","state":0}`),
		json.RawMessage(`{"mac":"38:25:ad:ca:03:c6","name":"Den","type":"uap","state":1}`),
	}}
	devs, _ := parseUniFi(u)
	if len(devs) != 2 || !devs[0].Offline || devs[1].Offline {
		t.Errorf("offline flags: %+v", devs)
	}
}

func TestPassiveHistoryOnNodes(t *testing.T) {
	mac := "00:11:22:33:44:55"
	seen := time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)
	g := Build(1, &obs.Result{Sweep: []obs.SweepHost{{IP: "10.0.0.20", MAC: mac}}}, History{
		IPv6:     map[string][]string{mac: {"fe80::1", "2001:db8::1", "fe80::1"}},
		LastSeen: map[string]time.Time{mac: seen},
	})
	if len(g.Nodes) != 1 {
		t.Fatalf("nodes: %+v", g.Nodes)
	}
	n := g.Nodes[0]
	if strings.Join(n.IPv6, ",") != "2001:db8::1,fe80::1" || !n.LastSeen.Equal(seen) {
		t.Errorf("ipv6 %v last seen %v", n.IPv6, n.LastSeen)
	}
}
