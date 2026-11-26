package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
)

// The demo network is entirely fictional: 10.42.0.0/24, documentation-range
// and made-up MACs, invented names.

const subnet = "10.42.0.0/24"

func ip(n int) string { return fmt.Sprintf("10.42.0.%d", n) }

// mac returns a made-up MAC; private ones have the locally administered bit set.
func mac(n int) string  { return fmt.Sprintf("00:00:5e:00:53:%02x", n) }
func pmac(n int) string { return fmt.Sprintf("da:42:7e:00:01:%02x", n) }
func vmac(n int) string { return fmt.Sprintf("bc:24:11:00:00:%02x", n) }

func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

type host struct {
	n        int    // address and MAC suffix
	mac      string // overrides mac(n)
	name     string
	vendor   string
	ap       int // Wi-Fi client of this AP (MAC suffix)
	swPort   int // wired client on the UniFi switch, this port
	essid    string
	dns      string
	lastSeen time.Duration // >0: absent, seen this long ago
}

func (h host) m() string {
	if h.mac != "" {
		return h.mac
	}
	return mac(h.n)
}

const (
	gw, core, usw = 1, 2, 3
	apHall, apOff = 4, 5
	apGarden      = 6
	pve, printer  = 10, 40
	vmApps, vmNAS = 20, 21
	desktop       = 50
)

func clients() []host {
	return []host{
		{n: pve, name: "pve1", vendor: "Example Systems", swPort: 5, dns: "pve1.home.arpa"},
		{n: 60, name: "Den-TV", vendor: "LG Electronics", swPort: 7},
		{n: 61, name: "PS5", vendor: "Sony Interactive Entertainment", swPort: 8},
		{n: 70, mac: pmac(1), name: "Sams-iPhone", ap: apHall, essid: "Home"},
		{n: 71, mac: pmac(2), name: "Galaxy-S24", ap: apHall, essid: "Home"},
		{n: 72, name: "roborock-vacuum-s7", vendor: "Beijing Roborock", ap: apHall, essid: "IoT"},
		{n: 73, name: "shelly-plug-patio", vendor: "Allterco Robotics", ap: apHall, essid: "IoT"},
		{n: 74, mac: pmac(3), name: "Robins-MacBook-Air", ap: apOff, essid: "Home", dns: "robins-macbook-air.home.arpa"},
		{n: 75, mac: pmac(4), name: "Pixel-8", ap: apOff, essid: "Home"},
		{n: 76, name: "doorbell-cam", vendor: "Example Cameras", ap: apGarden, essid: "IoT"},
		{n: 77, name: "esp32-sprinkler", vendor: "Espressif", ap: apGarden, essid: "IoT"},
		{n: 78, mac: pmac(5), name: "Guest-iPad", ap: apHall, essid: "Guest", lastSeen: 3 * 24 * time.Hour},
		{n: 79, name: "old-laptop", vendor: "Example Computers", swPort: 9, lastSeen: 10 * 24 * time.Hour},
	}
}

func demoResult(jobID int64, started, finished time.Time) *obs.Result {
	res := &obs.Result{
		JobID: jobID, Scanner: "homelabmap demo", StartedAt: started, FinishedAt: finished,
		Subnets: []string{subnet},
		Self:    obs.Self{Hostname: "apps", Interfaces: []obs.SelfIface{{Name: "eth0", MAC: vmac(vmApps), IPs: []string{ip(vmApps)}}}},
		DNS:     map[string]string{ip(desktop): "desktop.home.arpa", ip(vmNAS): "nas.home.arpa", ip(gw): "gateway.home.arpa"},
	}
	sweep := func(n int, m, vendor string) {
		res.Sweep = append(res.Sweep, obs.SweepHost{IP: ip(n), MAC: m, Vendor: vendor})
	}
	sweep(gw, mac(gw), "Routerboard.com")
	sweep(core, mac(core), "Cisco Systems")
	sweep(usw, mac(usw), "Ubiquiti")
	sweep(apHall, mac(apHall), "Ubiquiti")
	sweep(apOff, mac(apOff), "Ubiquiti")
	sweep(apGarden, mac(apGarden), "Ubiquiti")
	sweep(printer, mac(printer), "Example Printers")
	sweep(desktop, mac(desktop), "Example Computers")
	for _, h := range clients() {
		if h.lastSeen == 0 {
			sweep(h.n, h.m(), h.vendor)
			if h.dns != "" {
				res.DNS[ip(h.n)] = h.dns
			}
		}
	}

	// SNMP: the router and the core switch speak LLDP to each other; the
	// core switch's MAC table places the desktop and printer.
	var arp []obs.ARPEntry
	for _, s := range res.Sweep {
		arp = append(arp, obs.ARPEntry{IP: s.IP, MAC: s.MAC, IfIndex: 2})
	}
	for _, n := range []int{vmApps, vmNAS, 22, 30, 31, 32} {
		arp = append(arp, obs.ARPEntry{IP: ip(n), MAC: vmac(n), IfIndex: 2})
	}
	res.SNMP = []obs.SNMPDevice{
		{
			IP: ip(gw), SysName: "gateway", SysDescr: "RouterOS RB760iGS 7.15 (stable)", SysObjectID: "1.3.6.1.4.1.14988.1",
			Forwarding: true, BridgeMAC: mac(gw), LLDPChassisID: mac(gw),
			Interfaces: []obs.Interface{{Index: 1, Name: "ether1-wan", Up: true}, {Index: 2, Name: "ether2", Up: true}},
			LLDP: []obs.LLDPNeighbor{{LocalPortNum: 2, ChassisSubtype: 4, ChassisID: mac(core), PortSubtype: 5, PortID: "gi1",
				SysName: "core-sw", Caps: []string{"bridge"}, MgmtAddrs: []string{ip(core)}}},
			ARP: arp,
		},
		{
			IP: ip(core), SysName: "core-sw", SysDescr: "8-Port Gigabit Smart Switch", SysObjectID: "1.3.6.1.4.1.9.6.1.1",
			Forwarding: true, BridgeMAC: mac(core), LLDPChassisID: mac(core),
			Interfaces: []obs.Interface{
				{Index: 1, Name: "gi1", Up: true}, {Index: 2, Name: "gi2", Up: true},
				{Index: 3, Name: "gi3", Up: true}, {Index: 8, Name: "gi8", Up: true},
			},
			LLDP: []obs.LLDPNeighbor{
				{LocalPortNum: 1, ChassisSubtype: 4, ChassisID: mac(gw), PortSubtype: 5, PortID: "ether2", SysName: "gateway",
					Caps: []string{"bridge", "router"}, MgmtAddrs: []string{ip(gw)}},
				{LocalPortNum: 8, ChassisSubtype: 4, ChassisID: mac(usw), PortSubtype: 7, PortID: "Port 24", SysName: "Lab Switch",
					Caps: []string{"bridge"}, MgmtAddrs: []string{ip(usw)}},
			},
			FDB: []obs.FDBEntry{{MAC: mac(gw), IfIndex: 1}, {MAC: mac(desktop), IfIndex: 2}, {MAC: mac(printer), IfIndex: 3}},
		},
		{IP: ip(printer), SysName: "printer", SysDescr: "Example LaserJet 400 series", SysObjectID: "1.3.6.1.4.1.11.2.3.9.1", IsPrinter: true},
	}

	res.UniFi = obs.UniFiList{*demoUniFi(started)}
	res.PVE = demoPVE()
	res.Cosmos = obs.CosmosList{*demoCosmos(started)}
	res.SSDP = []obs.SSDPDevice{
		{IP: ip(60), FriendlyName: "Den TV", Manufacturer: "LG Electronics", ModelName: "Smart TV",
			DeviceType: "urn:schemas-upnp-org:device:MediaRenderer:1", Server: "Linux/4.4 UPnP/1.0 WebOS TV/1.0"},
		{IP: ip(61), FriendlyName: "PS5", Manufacturer: "Sony Interactive Entertainment", ModelName: "PlayStation 5"},
	}
	res.OSScans = []obs.OSScan{
		{IP: ip(desktop), MAC: mac(desktop), Matched: true, Name: "Microsoft Windows 11 21H2", Accuracy: 98, Family: "Windows",
			Type: "general purpose", OpenPorts: []string{"135/tcp msrpc", "445/tcp microsoft-ds"}, ScannedAt: started},
		{IP: ip(vmNAS), MAC: vmac(vmNAS), Matched: true, Name: "Linux 6.1 - 6.6", Accuracy: 96, Family: "Linux",
			OpenPorts: []string{"22/tcp ssh", "445/tcp microsoft-ds", "2049/tcp nfs"}, ScannedAt: started},
	}
	return res
}

func demoUniFi(now time.Time) *obs.UniFi {
	u := &obs.UniFi{Flavor: "legacy"}
	dev := func(n int, name, model, typ string, uplink map[string]any) {
		d := map[string]any{"mac": mac(n), "ip": ip(n), "name": name, "model": model, "type": typ, "version": "7.1.0", "state": 1}
		if uplink != nil {
			d["uplink"] = uplink
		}
		u.Devices = append(u.Devices, raw(d))
	}
	dev(usw, "Lab Switch", "US24P250", "usw", nil)
	dev(apHall, "Hallway AP", "U6P", "uap", map[string]any{"uplink_mac": mac(usw), "uplink_remote_port": 2, "type": "wire"})
	dev(apOff, "Office AP", "U6P", "uap", map[string]any{"uplink_mac": mac(usw), "uplink_remote_port": 3, "type": "wire"})
	dev(apGarden, "Garden AP", "UMA6", "uap", map[string]any{"uplink_mac": mac(apHall), "type": "wireless"})

	for _, h := range clients() {
		c := map[string]any{"mac": h.m(), "hostname": h.name, "oui": h.vendor, "first_seen": now.Add(-90 * 24 * time.Hour).Unix()}
		if h.ap != 0 {
			c["is_wired"], c["ap_mac"], c["essid"] = false, mac(h.ap), h.essid
		} else {
			c["is_wired"], c["sw_mac"], c["sw_port"] = true, mac(usw), h.swPort
		}
		if h.lastSeen > 0 {
			c["last_seen"] = now.Add(-h.lastSeen).Unix()
			c["last_uplink_mac"] = c["ap_mac"]
			if h.ap == 0 {
				c["last_uplink_mac"], c["type"] = mac(usw), "WIRED"
			}
			u.History = append(u.History, raw(c))
			continue
		}
		c["ip"], c["last_seen"] = ip(h.n), now.Unix()
		u.Clients = append(u.Clients, raw(c))
	}
	u.Known = append(u.Known, raw(map[string]any{"mac": mac(61), "name": "PlayStation"}))
	return u
}

func demoPVE() *obs.PVE {
	guest := func(id int, name, typ, status, ostype string, n int) obs.PVEGuest {
		g := obs.PVEGuest{VMID: id, Name: name, Type: typ, Status: status, OSType: ostype,
			NICs: []obs.PVENIC{{Name: "net0", MAC: vmac(n), Bridge: "vmbr0"}}}
		if status == "running" {
			g.IPs = []string{ip(n)}
		}
		return g
	}
	return &obs.PVE{Nodes: []obs.PVENode{{Name: "pve1", IP: ip(pve), Status: "online", Guests: []obs.PVEGuest{
		guest(100, "apps", "qemu", "running", "l26", vmApps),
		guest(101, "nas", "qemu", "running", "l26", vmNAS),
		guest(102, "homeassistant", "qemu", "running", "l26", 22),
		guest(103, "win11-lab", "qemu", "stopped", "win11", 23),
		guest(200, "pihole", "lxc", "running", "debian", 30),
		guest(201, "monitoring", "lxc", "running", "ubuntu", 31),
		guest(202, "unifi-controller", "lxc", "running", "debian", 32),
		guest(203, "scratch", "lxc", "stopped", "alpine", 33),
	}}}}
}

func demoCosmos(now time.Time) *obs.Cosmos {
	ct := func(name, image, stack, state string) obs.CosmosContainer {
		c := obs.CosmosContainer{Name: name, Image: image, Stack: stack, State: state, NetworkMode: "bridge",
			Status: "Up 6 days", Created: now.Add(-30 * 24 * time.Hour)}
		if state != "running" {
			c.Status = "Exited (0) 2 days ago"
		}
		return c
	}
	media := []obs.CosmosContainer{
		ct("jellyfin", "jellyfin/jellyfin:10.10", "media", "running"),
		ct("sonarr", "linuxserver/sonarr:4", "media", "running"),
		ct("radarr", "linuxserver/radarr:5", "media", "running"),
	}
	media[0].Ports = []obs.DockerPort{{PrivatePort: 8096, PublicPort: 8096, Type: "tcp"}}
	obsv := []obs.CosmosContainer{
		ct("grafana", "grafana/grafana:11", "observability", "running"),
		ct("prometheus", "prom/prometheus:v3", "observability", "running"),
	}
	return &obs.Cosmos{
		URL: "https://apps.home.arpa", HostIPs: []string{ip(vmApps)},
		Containers: append(append(media, obsv...),
			ct("vaultwarden", "vaultwarden/server:1.32", "", "running"),
			ct("backup-job", "restic/restic:0.17", "", "exited")),
		Routes: []obs.CosmosRoute{
			{Name: "jellyfin", Host: "media.example.net", Target: "http://jellyfin:8096", Mode: "SERVAPP"},
			{Name: "grafana", Host: "grafana.example.net", Target: "http://grafana:3000", Mode: "SERVAPP"},
			{Name: "vault", Host: "vault.example.net", Target: "http://vaultwarden:80", Mode: "SERVAPP"},
			{Name: "files", Host: "files.example.net", Target: "http://" + ip(vmNAS) + ":80", Mode: "PROXY"},
		},
	}
}

func demoSightings(now time.Time) []obs.Sighting {
	var out []obs.Sighting
	for i, h := range clients() {
		if h.lastSeen == 0 {
			out = append(out, obs.Sighting{MAC: h.m(), IP: ip(h.n), Via: "arp", At: now.Add(-time.Duration(i) * time.Minute)})
		}
	}
	out = append(out,
		obs.Sighting{MAC: pmac(1), IP: "fe80::d842:7eff:fe00:101", Via: "ndp", At: now},
		obs.Sighting{MAC: mac(desktop), IP: "fd00:42::50", Via: "ndp", At: now},
	)
	// The desktop uses IPv6 privacy extensions: a new temporary address
	// every day.
	for i := range 5 {
		out = append(out, obs.Sighting{MAC: mac(desktop), IP: fmt.Sprintf("2001:db8:42:0:%x:%x:%x:%x", 0x1a2b+i*0x111, 0x3c4d+i*0x37, 0x5e6f-i*0x91, 0x7a8b+i*0x13), Via: "ndp", At: now.Add(-time.Duration(i) * 24 * time.Hour)})
	}
	return out
}
