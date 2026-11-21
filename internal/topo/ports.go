package topo

import (
	"fmt"
	"strings"

	"github.com/liorokman/homelabmap/internal/obs"
)

var ifAbbrev = []struct{ long, short string }{
	{"hundredgigabitethernet", "hu"},
	{"hundredgige", "hu"},
	{"fortygigabitethernet", "fo"},
	{"twentyfivegigabitethernet", "twe"},
	{"twentyfivegige", "twe"},
	{"tengigabitethernet", "te"},
	{"gigabitethernet", "gi"},
	{"fastethernet", "fa"},
	{"port-channel", "po"},
	{"bridge-aggregation", "bagg"},
}

// shortIf abbreviates long interface names: GigabitEthernet19 -> gi19.
func shortIf(s string) string {
	l := strings.ToLower(s)
	for _, a := range ifAbbrev {
		if strings.HasPrefix(l, a.long) {
			return a.short + strings.TrimSpace(s[len(a.long):])
		}
	}
	return s
}

// normPort makes port names comparable across vendors' spellings.
func normPort(s string) string {
	s = strings.ToLower(shortIf(strings.TrimSpace(s)))
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
}

func findIf(d *obs.SNMPDevice, idx int) *obs.Interface {
	if d == nil {
		return nil
	}
	for i := range d.Interfaces {
		if d.Interfaces[i].Index == idx {
			return &d.Interfaces[i]
		}
	}
	return nil
}

// portLabel is the display name for an ifIndex on a device.
func portLabel(d *obs.SNMPDevice, idx int) string {
	if idx == 0 {
		return ""
	}
	if i := findIf(d, idx); i != nil {
		switch {
		case i.Name != "":
			return shortIf(i.Name)
		case i.Descr != "":
			return shortIf(i.Descr)
		}
	}
	return fmt.Sprintf("if%d", idx)
}

// aggOf maps a LAG member port to its aggregate ifIndex.
func aggOf(d *obs.SNMPDevice, idx int) int {
	if i := findIf(d, idx); i != nil && i.AggIndex != 0 {
		return i.AggIndex
	}
	return idx
}

// lldpLocalIf maps an LLDP local port number to an ifIndex. The standard
// says nothing about how they relate, so match names first and fall back to
// equality, which is what most agents do.
func lldpLocalIf(d *obs.SNMPDevice, num int) int {
	if d == nil {
		return 0
	}
	for _, lp := range d.LLDPLocal {
		if lp.Num != num {
			continue
		}
		for _, cand := range []string{lp.ID, lp.Desc} {
			if cand == "" {
				continue
			}
			nc := normPort(cand)
			for _, i := range d.Interfaces {
				if (i.Name != "" && normPort(i.Name) == nc) || (i.Descr != "" && normPort(i.Descr) == nc) {
					return i.Index
				}
			}
		}
	}
	if findIf(d, num) != nil {
		return num
	}
	return 0
}

// resolvePort finds which of e's ports a neighbour's port string refers to.
// It returns the display label and the ifIndex (0 if e has no SNMP view).
func resolvePort(e *entity, cands ...string) (string, int) {
	d := e.dev()
	var clean []string
	for _, c := range cands {
		if c = strings.TrimSpace(c); c != "" {
			clean = append(clean, c)
			// "bridge/sfp-sfpplus2" (RouterOS via CDP) -> "sfp-sfpplus2"
			if i := strings.LastIndexByte(c, '/'); i > 0 && !strings.ContainsAny(c[:i], "0123456789") {
				clean = append(clean, c[i+1:])
			}
		}
	}
	if d != nil {
		for _, c := range clean {
			nc := normPort(c)
			for _, i := range d.Interfaces {
				if (i.Name != "" && normPort(i.Name) == nc) || (i.Descr != "" && normPort(i.Descr) == nc) {
					return portLabel(d, i.Index), i.Index
				}
			}
			for _, lp := range d.LLDPLocal {
				if (lp.ID != "" && normPort(lp.ID) == nc) || (lp.Desc != "" && normPort(lp.Desc) == nc) {
					if idx := lldpLocalIf(d, lp.Num); idx != 0 {
						return portLabel(d, idx), idx
					}
				}
			}
			for _, i := range d.Interfaces {
				if i.Alias != "" && normPort(i.Alias) == nc {
					return portLabel(d, i.Index), i.Index
				}
			}
		}
	}
	// No SNMP view: show what the neighbour said, preferring names over MACs.
	for _, c := range clean {
		if obs.NormMAC(c) == "" {
			return c, 0
		}
	}
	if len(clean) > 0 {
		return clean[0], 0
	}
	return "", 0
}

// uniPortLabel names UniFi port N, using SNMP names when we have them.
func uniPortLabel(e *entity, n int) (string, int) {
	if n <= 0 {
		return "", 0
	}
	if d := e.dev(); d != nil {
		if idx := lldpLocalIf(d, n); idx != 0 {
			return portLabel(d, idx), idx
		}
	}
	return fmt.Sprintf("port %d", n), 0
}
