package topo

import (
	"cmp"
	"slices"
)

type sighting struct {
	dev  *entity
	port int // ifIndex, LAG members folded into the aggregate
}

// indexFDB builds MAC -> where network gear has learned it.
func (b *builder) indexFDB() {
	b.fdb = map[string][]sighting{}
	b.portCount = map[*entity]map[int]int{}
	b.hasFDB = map[*entity]bool{}
	for _, e := range b.ents {
		if !e.infra {
			continue
		}
		for _, d := range e.snmp {
			if len(d.FDB) == 0 {
				continue
			}
			b.hasFDB[e] = true
			if b.portCount[e] == nil {
				b.portCount[e] = map[int]int{}
			}
			seen := map[string]bool{}
			for _, f := range d.FDB {
				p := aggOf(d, f.IfIndex)
				k := f.MAC + "@" + portLabel(d, p)
				if seen[k] {
					continue
				}
				seen[k] = true
				b.fdb[f.MAC] = append(b.fdb[f.MAC], sighting{dev: e, port: p})
				b.portCount[e][p]++
			}
		}
	}
}

// placeGuests hangs VMs and containers inside their hypervisor.
func (b *builder) placeGuests() {
	for _, e := range b.ents {
		if e.guest == nil {
			continue
		}
		node := b.byKey["pve:"+e.guestNode]
		if node == nil || node == e {
			continue
		}
		b.addLink(node, 0, "", e, 0, "", KindVirtual, "pve", prioUniFi)
		e.parent = node
		e.connection = KindVirtual
		kind := "VM"
		if e.guest.Type == "lxc" {
			kind = "container"
		}
		e.location = kind + " on " + b.labels[node]
	}
}

// place decides where an entity without a reported link is attached.
func (b *builder) place(e *entity, gw *entity) {
	// 1. The controller knows which AP a Wi-Fi client is on.
	if c := e.ucli; c != nil && c.WiredKnown && !c.Wired {
		ap := b.entityByMAC(c.APMAC)
		if ap == nil && c.UplinkID != "" {
			ap = b.byKey["unifi:"+c.UplinkID]
		}
		if ap != nil && ap != e {
			b.addLink(ap, 0, "", e, 0, "", KindWireless, "unifi", prioUniFi)
			e.connection = KindWireless
			e.location = "Wi-Fi via " + b.labels[ap]
			if c.ESSID != "" {
				e.location += " (" + c.ESSID + ")"
			}
			return
		}
	}

	// 2. Learned on an access port: that is where it is plugged in. If
	// several switches see it on access ports (stale entries), trust the
	// quietest port, then the deepest switch.
	var access, uplink []sighting
	for _, m := range e.sortedMACs() {
		for _, s := range b.fdb[m] {
			if s.dev == e {
				continue
			}
			if _, up := b.uplinks[s.dev][s.port]; up {
				uplink = append(uplink, s)
			} else {
				access = append(access, s)
			}
		}
	}
	if len(access) > 0 {
		best := slices.MinFunc(access, func(x, y sighting) int {
			return cmp.Or(
				cmp.Compare(b.portCount[x.dev][x.port], b.portCount[y.dev][y.port]),
				cmp.Compare(y.dev.depth, x.dev.depth),
			)
		})
		if h := b.hostPorts[best.dev][best.port]; h != nil && h != e {
			// LACP and bridge MACs of the host itself: no IP, no name.
			if e.fdbOnly() {
				e.hidden = true
				return
			}
			e.behind = h
			b.addLink(h, 0, "", e, 0, "", KindInferred, "fdb", prioFDB)
			e.connection = KindInferred
			e.location = "behind " + b.labels[h] + " (inferred)"
			return
		}
		d := best.dev.dev()
		port := portLabel(d, best.port)
		b.addLink(best.dev, best.port, port, e, 0, "", KindWired, "fdb", prioFDB)
		e.connection = KindWired
		e.location = b.labels[best.dev] + " port " + port
		return
	}

	// 3. The controller's view of wired clients (covers UniFi switches
	// without a usable SNMP MAC table, such as the USW Lite 8).
	if c := e.ucli; c != nil {
		sw := b.entityByMAC(c.SwMAC)
		if sw == nil && c.UplinkID != "" {
			sw = b.byKey["unifi:"+c.UplinkID]
		}
		if sw != nil && sw != e {
			port, idx := uniPortLabel(sw, c.SwPort)
			b.addLink(sw, idx, port, e, 0, "", KindWired, "unifi", prioUniFi)
			e.connection = KindWired
			e.location = b.labels[sw]
			if port != "" {
				e.location += " " + port
			}
			return
		}
	}

	// 4. Only seen on uplinks: it sits behind a device that can't tell us
	// about its own ports. Pick the deepest such device.
	var behind *entity
	for _, s := range uplink {
		n := b.uplinks[s.dev][s.port]
		if n == nil || n == e || b.hasFDB[n] {
			continue
		}
		if behind == nil || n.depth > behind.depth {
			behind = n
		}
	}
	if behind != nil {
		e.behind = behind
		b.addLink(behind, 0, "", e, 0, "", KindInferred, "fdb", prioGuess)
		e.connection = KindInferred
		e.location = "behind " + b.labels[behind] + " (inferred)"
		return
	}

	// 5. Alive but unplaceable: show it, honestly marked.
	if len(e.ips) > 0 || len(e.sweep) > 0 || e.ucli != nil || e.self || len(e.snmp) > 0 {
		if gw != nil && gw != e {
			b.addLink(gw, 0, "", e, 0, "", KindUnknown, "arp", prioGuess)
		}
		e.connection = KindUnknown
		e.location = "location unknown"
		return
	}

	// A MAC that only ever shows up on uplinks with no other trace is
	// switch-internal or transit noise.
	e.hidden = true
}
