package topo

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/liorokman/homelabmap/internal/obs"
)

// Icon keys understood by the UI.
const (
	IconRouter        = "router"
	IconSwitch        = "switch"
	IconAP            = "ap"
	IconProxmox       = "proxmox"
	IconLinux         = "linux"
	IconDebian        = "debian"
	IconUbuntu        = "ubuntu"
	IconAlpine        = "alpine"
	IconRaspberryPi   = "raspberrypi"
	IconWindows       = "windows"
	IconApple         = "apple"
	IconAndroid       = "android"
	IconFreeBSD       = "freebsd"
	IconHomeAssistant = "homeassistant"
	IconPrinter       = "printer"
	IconMedia         = "media"
	IconIoT           = "iot"
	IconPhone         = "phone"
	IconNAS           = "nas"
	IconServer        = "server"
	IconCamera        = "camera"
	IconGaming        = "gaming"
	IconUnknown       = "unknown"
	IconDocker        = "docker"
	IconStack         = "stack"
)

type osGuess struct {
	name, icon, source string
	score              int
}

func better(a, b osGuess) osGuess {
	if b.score > a.score {
		return b
	}
	return a
}

// iconForOS picks a logo from an OS description.
func iconForOS(s string) string {
	l := strings.ToLower(s)
	switch {
	case strings.Contains(l, "proxmox"):
		return IconProxmox
	case strings.Contains(l, "home assistant"):
		return IconHomeAssistant
	case strings.Contains(l, "raspbian"), strings.Contains(l, "raspberry"):
		return IconRaspberryPi
	case strings.Contains(l, "debian"):
		return IconDebian
	case strings.Contains(l, "ubuntu"):
		return IconUbuntu
	case strings.Contains(l, "alpine"):
		return IconAlpine
	case strings.Contains(l, "android"):
		return IconAndroid
	case strings.Contains(l, "windows"):
		return IconWindows
	case strings.Contains(l, "macos"), strings.Contains(l, "mac os"), strings.Contains(l, "ios"),
		strings.Contains(l, "ipados"), strings.Contains(l, "apple"), strings.Contains(l, "darwin"):
		return IconApple
	case strings.Contains(l, "freebsd"), strings.Contains(l, "truenas core"), strings.Contains(l, "pfsense"), strings.Contains(l, "opnsense"):
		return IconFreeBSD
	case strings.Contains(l, "linux"):
		return IconLinux
	}
	return ""
}

var pveOSTypes = map[string]string{
	"l26": "Linux", "l24": "Linux 2.4", "win11": "Windows 11", "win10": "Windows 10", "win8": "Windows 8",
	"win7": "Windows 7", "wvista": "Windows Vista", "wxp": "Windows XP", "w2k8": "Windows Server 2008",
	"w2k3": "Windows Server 2003", "w2k": "Windows 2000", "solaris": "Solaris",
	"debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine Linux", "centos": "CentOS", "fedora": "Fedora",
	"archlinux": "Arch Linux", "opensuse": "openSUSE", "gentoo": "Gentoo", "nixos": "NixOS", "devuan": "Devuan",
}

var reLinuxDescr = regexp.MustCompile(`^Linux \S+ (\S+)`)

func snmpOS(e *entity, d *obs.SNMPDevice) osGuess {
	descr := strings.TrimSpace(d.SysDescr)
	if descr == "" {
		return osGuess{}
	}
	g := osGuess{source: "snmp", score: 85}
	switch {
	case strings.Contains(descr, "RouterOS"):
		g.name = "MikroTik " + firstLine(descr)
	case reUniFiSwitch.MatchString(descr) || reUniFiAP.MatchString(descr) || reUniFiGW.MatchString(descr):
		parts := strings.Split(descr, ",")
		g.name = "UniFi " + strings.TrimSpace(parts[0])
		if len(parts) > 1 {
			g.name += " (firmware " + strings.TrimSpace(parts[1]) + ")"
		} else if f := strings.Fields(descr); len(f) > 1 {
			g.name = "UniFi " + f[0] + " (firmware " + f[1] + ")"
		}
	case strings.HasPrefix(descr, "Linux"):
		g.name, g.icon = "Linux", IconLinux
		if m := reLinuxDescr.FindStringSubmatch(descr); m != nil {
			g.name = "Linux " + m[1]
			if strings.HasSuffix(m[1], "-pve") {
				if e.isPVEHost() {
					g.name, g.icon = "Proxmox VE (Linux "+m[1]+")", IconProxmox
				} else {
					g.name = "Linux (Proxmox kernel " + m[1] + ")"
				}
			}
		}
	case strings.Contains(descr, "Windows"):
		g.name, g.icon = firstLine(descr), IconWindows
	case strings.Contains(descr, "Darwin"):
		g.name, g.icon = "macOS ("+firstLine(descr)+")", IconApple
	case strings.Contains(descr, "FreeBSD"):
		g.name, g.icon = firstLine(descr), IconFreeBSD
	case enterprise(d.SysObjectID) == 9:
		g.name = "Cisco " + firstLine(descr)
	default:
		g.name = firstLine(descr)
		g.score = 60
	}
	if g.icon == "" {
		g.icon = iconForOS(g.name)
	}
	return g
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return s
}

func nmapOS(s obs.OSScan) osGuess {
	if !s.Matched || s.Name == "" {
		return osGuess{}
	}
	g := osGuess{name: s.Name, source: fmt.Sprintf("nmap (%d%%)", s.Accuracy)}
	switch {
	case s.Accuracy >= 95:
		g.score = 75
	case s.Accuracy >= 88:
		g.score = 65
	default:
		g.score = 45
	}
	fam := strings.ToLower(s.Family)
	switch strings.ToLower(s.Type) {
	case "printer":
		g.icon = IconPrinter
	case "media device":
		g.icon = IconMedia
	case "game console":
		g.icon = IconGaming
	case "webcam", "security-misc":
		g.icon = IconCamera
	case "storage-misc":
		g.icon = IconNAS
	case "phone":
		g.icon = IconPhone
		switch fam {
		case "ios":
			g.icon = IconApple
		case "android":
			g.icon = IconAndroid
		}
	}
	if g.icon == "" {
		g.icon = iconForOS(s.Name + " " + s.Family)
	}
	if g.icon == "" && (fam == "embedded" || strings.ToLower(s.Type) == "specialized") {
		g.icon = IconIoT
	}
	return g
}

type nameRule struct {
	re   *regexp.Regexp
	name string
	icon string
}

var hostnameRules = []nameRule{
	{regexp.MustCompile(`(?i)iphone|ipad`), "iOS", IconApple},
	{regexp.MustCompile(`(?i)macbook|imac|mac-?mini|mac-?studio|\bmbp\b|-mbp|mbp-|^mac([-.]|$)`), "macOS", IconApple},
	{regexp.MustCompile(`(?i)apple-?tv|appletv`), "tvOS", IconMedia},
	// Before the Samsung rule: "roborock-vacuum-a15" is not a Galaxy A15.
	{regexp.MustCompile(`(?i)roborock|roomba|vacuum|dreame|ecovacs|deebot`), "Robot vacuum", IconIoT},
	{regexp.MustCompile(`(?i)android|galaxy|pixel|oneplus|redmi|poco|xiaomi|huawei|oppo|vivo|\bsm-[a-z]\d`), "Android", IconAndroid},
	// Samsung default names: "Alex-s-S23", "Sam-s-S23-Ultra", "Tab-S9", "A54".
	{regexp.MustCompile(`(?i)(^|[-_ ])(s\d{2}(-?(ultra|fe|plus)|\+)?|tab-?[as]\d+(-lite)?|a\d{2}s?)([-_ .]|$)`), "Android", IconAndroid},
	{regexp.MustCompile(`(?i)^(desktop|laptop)-[a-z0-9]{7}$|^win-|windows`), "Windows", IconWindows},
	{regexp.MustCompile(`(?i)raspberrypi|raspberry`), "Linux (Raspberry Pi)", IconRaspberryPi},
	{regexp.MustCompile(`(?i)homeassistant|home-assistant|hassio`), "Home Assistant OS", IconHomeAssistant},
	{regexp.MustCompile(`(?i)printer|^brn[0-9a-f]{12}|^npi[0-9a-f]{6}|laserjet|officejet|deskjet|epson|canon`), "Printer", IconPrinter},
	{regexp.MustCompile(`(?i)chromecast|roku|sonos|bravia|webos|tizen|smart-?tv|\btv\b|firetv|fire-tv|shield`), "Media device", IconMedia},
	{regexp.MustCompile(`(?i)^esp[-_]|tasmota|shelly|tuya|sonoff|wled|\bhue\b|nest|echo|alexa|tapo|kasa|wiz|broadlink|zigbee`), "IoT device", IconIoT},
	{regexp.MustCompile(`(?i)ps4|ps5|playstation|xbox|nintendo`), "Game console", IconGaming},
	{regexp.MustCompile(`(?i)camera|\bcam\d*\b|reolink|hikvision|dahua|doorbell|ipcam`), "Camera", IconCamera},
	{regexp.MustCompile(`(?i)\bnas\b|synology|diskstation|qnap|truenas|unraid`), "NAS", IconNAS},
}

var vendorRules = []nameRule{
	{regexp.MustCompile(`(?i)proxmox`), "Virtual machine (Proxmox)", IconServer},
	{regexp.MustCompile(`(?i)raspberry`), "Linux (Raspberry Pi)", IconRaspberryPi},
	{regexp.MustCompile(`(?i)\bapple\b`), "Apple device", IconApple},
	{regexp.MustCompile(`(?i)espressif|tuya|shelly|sonoff|itead|signify|philips lighting|lumi united|gaoshengda|broadlink|ezviz`), "IoT device", IconIoT},
	{regexp.MustCompile(`(?i)sonos|roku|chromecast`), "Media device", IconMedia},
	{regexp.MustCompile(`(?i)brother|canon|seiko epson|kyocera|lexmark|xerox|ricoh`), "Printer", IconPrinter},
	{regexp.MustCompile(`(?i)synology|qnap`), "NAS", IconNAS},
	{regexp.MustCompile(`(?i)nintendo|sony interactive`), "Game console", IconGaming},
	{regexp.MustCompile(`(?i)hikvision|dahua|reolink|axis comm`), "Camera", IconCamera},
	{regexp.MustCompile(`(?i)amazon technologies|google`), "Smart home device", IconIoT},
}

// identifyOS combines every hint and keeps the strongest.
func (b *builder) identifyOS(e *entity) osGuess {
	var g osGuess
	if e.pveNode != nil {
		g = better(g, osGuess{name: "Proxmox VE", icon: IconProxmox, source: "pve", score: 95})
	}
	if u := e.udev; u != nil {
		name := "UniFi " + u.Model
		if u.Version != "" {
			name += " (firmware " + u.Version + ")"
		}
		g = better(g, osGuess{name: name, source: "unifi", score: 95})
	}
	if gu := e.guest; gu != nil && gu.OSType != "" {
		name := pveOSTypes[gu.OSType]
		if name == "" {
			name = gu.OSType
		}
		icon := iconForOS(name)
		if icon == "" && gu.Type == "lxc" {
			icon = IconLinux
		}
		g = better(g, osGuess{name: name, icon: icon, source: "pve", score: 90})
	}
	if d := e.dev(); d != nil {
		g = better(g, snmpOS(e, d))
	}
	for _, m := range e.sortedMACs() {
		if s, ok := b.osScans[m]; ok {
			g = better(g, nmapOS(s))
		}
	}
	if e.ssdp != nil {
		g = better(g, ssdpOS(e.ssdp))
	}
	for _, n := range b.namesOf(e) {
		for _, r := range hostnameRules {
			if r.re.MatchString(n) {
				g = better(g, osGuess{name: r.name, icon: r.icon, source: "name", score: 50})
				break
			}
		}
	}
	if v := b.vendorOf(e); v != "" {
		for _, r := range vendorRules {
			if r.re.MatchString(v) {
				g = better(g, osGuess{name: r.name, icon: r.icon, source: "vendor", score: 30})
				break
			}
		}
	}
	viaWiFi := e.connection == KindWireless || (e.behind != nil && e.behind.role == RoleAP)
	if g.score == 0 && viaWiFi && len(e.macs) > 0 {
		private := true
		for _, m := range e.sortedMACs() {
			private = private && obs.IsLocallyAdministered(m)
		}
		if private {
			g = osGuess{name: "Phone or laptop (private Wi-Fi address)", icon: IconPhone, source: "mac", score: 20}
		}
	}
	return g
}

// ssdpOS classifies UPnP devices. Appliances describe themselves well
// (maker, model, device type), better than nmap's generic "Linux" for the
// same box, so these score above nmap but below SNMP and the controllers.
func ssdpOS(d *obs.SSDPDevice) osGuess {
	const score = 80
	hay := strings.ToLower(strings.Join([]string{d.FriendlyName, d.Manufacturer, d.ModelName, d.ModelDescription}, " "))
	server := strings.ToLower(d.Server)
	types := strings.ToLower(d.DeviceType + " " + strings.Join(d.Types, " "))
	model := ssdpModel(d)
	switch {
	case strings.Contains(hay, "xbox"), strings.Contains(hay, "playstation"), strings.Contains(hay, "nintendo"):
		return osGuess{name: "Game console (" + model + ")", icon: IconGaming, source: "ssdp", score: score}
	case strings.Contains(hay, "synology"), strings.Contains(hay, "qnap"), strings.Contains(hay, "diskstation"), strings.Contains(hay, "truenas"):
		return osGuess{name: "NAS (" + model + ")", icon: IconNAS, source: "ssdp", score: score}
	case strings.Contains(types, "printer"):
		return osGuess{name: "Printer (" + model + ")", icon: IconPrinter, source: "ssdp", score: score}
	case strings.Contains(hay, "hue bridge"), strings.Contains(hay, "homey"), strings.Contains(hay, "smartthings"):
		return osGuess{name: "Smart-home hub (" + model + ")", icon: IconIoT, source: "ssdp", score: score}
	case strings.Contains(server, "webos"):
		return osGuess{name: "LG webOS TV (" + model + ")", icon: IconMedia, source: "ssdp", score: score}
	case strings.Contains(server, "tizen"):
		return osGuess{name: "Samsung Tizen TV (" + model + ")", icon: IconMedia, source: "ssdp", score: score}
	case strings.Contains(server, "android"), strings.Contains(server, "chromecast"):
		return osGuess{name: "Android TV (" + model + ")", icon: IconMedia, source: "ssdp", score: score}
	case strings.Contains(types, "mediarenderer"), strings.Contains(types, "dial-multiscreen"), strings.Contains(hay, "sonos"):
		return osGuess{name: "Media device (" + model + ")", icon: IconMedia, source: "ssdp", score: score}
	}
	return osGuess{}
}
