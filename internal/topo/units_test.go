package topo

import (
	"encoding/json"
	"testing"

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
