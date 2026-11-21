package topo

import (
	"regexp"
	"slices"
	"strings"
)

var (
	reUniFiSwitch = regexp.MustCompile(`(?i)^(USW|US-\d|US8|US16|US24|US48|USL|USM|USF)`)
	reUniFiAP     = regexp.MustCompile(`(?i)^(UAP|U6|U7|UAL|UK-|UWB|E7|UAC|U-LTE|UMA|UBB)`)
	reUniFiGW     = regexp.MustCompile(`(?i)^(UDM|UXG|UCG|USG|UDR|UDW|UX\b)`)
)

func (b *builder) assignRoles() {
	for _, e := range b.ents {
		e.role = b.roleOf(e)
		e.infra = isInfraRole(e.role)
	}
}

func (b *builder) roleOf(e *entity) string {
	if e.guest != nil {
		if e.guest.Type == "lxc" {
			return RoleContainer
		}
		return RoleVM
	}
	if e.udev != nil {
		switch strings.ToLower(e.udev.Type) {
		case "usw":
			return RoleSwitch
		case "uap":
			return RoleAP
		case "ugw", "udm", "uxg", "usg":
			return RoleRouter
		}
	}
	if e.isPVEHost() {
		return RoleHypervisor
	}
	if d := e.dev(); d != nil {
		if d.IsPrinter {
			return RolePrinter
		}
		descr := d.SysDescr
		switch {
		case reUniFiGW.MatchString(descr):
			return RoleRouter
		case reUniFiSwitch.MatchString(descr):
			return RoleSwitch
		case reUniFiAP.MatchString(descr):
			return RoleAP
		}
		ent := enterprise(d.SysObjectID)
		switch ent {
		case 14988: // MikroTik: CRS/CSS are switches, everything else routes
			if strings.Contains(descr, "CRS") || strings.Contains(descr, "CSS") {
				return RoleSwitch
			}
			return RoleRouter
		case 9:
			if strings.Contains(strings.ToLower(descr), "switch") {
				return RoleSwitch
			}
			return RoleRouter
		case 41112:
			return RoleAP
		case entNetSNMP:
			return RoleServer
		}
		if networkEnterprises[ent] {
			if d.Forwarding && len(d.FDB) == 0 {
				return RoleRouter
			}
			return RoleSwitch
		}
		if len(d.FDB) > 0 {
			return RoleSwitch
		}
		return RoleServer
	}
	// Seen only as an LLDP/CDP neighbour: trust the model string first,
	// capabilities second (Linux hosts with bridges advertise "bridge").
	for _, n := range e.lldpRefs {
		switch {
		case reUniFiGW.MatchString(n.SysDesc):
			return RoleRouter
		case reUniFiSwitch.MatchString(n.SysDesc):
			return RoleSwitch
		case reUniFiAP.MatchString(n.SysDesc):
			return RoleAP
		}
		if strings.Contains(strings.ToLower(n.SysDesc), "linux") {
			continue
		}
		switch {
		case slices.Contains(n.Caps, "router"):
			return RoleRouter
		case slices.Contains(n.Caps, "wlan-ap"):
			return RoleAP
		case slices.Contains(n.Caps, "bridge") && !slices.Contains(n.Caps, "station"):
			return RoleSwitch
		}
	}
	if e.self {
		return RoleServer
	}
	return RoleClient
}

// pickGateway chooses the router everything hangs from.
func (b *builder) pickGateway() *entity {
	var best *entity
	score := func(e *entity) int {
		s := 0
		if d := e.dev(); d != nil {
			s += len(d.ARP)
		}
		if e.udev != nil {
			s += 1000
		}
		return s
	}
	for _, e := range b.ents {
		if e.role == RoleRouter && (best == nil || score(e) > score(best)) {
			best = e
		}
	}
	return best
}
