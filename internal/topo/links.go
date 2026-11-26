package topo

import (
	"fmt"
	"slices"
)

type link struct {
	a, b         *entity
	aIf, bIf     int
	aPort, bPort string
	kind         string
	prio         int
	sources      map[string]bool
}

// Source priorities: a cable reported by LLDP/CDP beats a controller's
// opinion, which beats a deduction from MAC tables.
const (
	prioGuess = iota
	prioFDB
	prioUniFi
	prioLLDP
)

func portsCompatible(x string, xi int, y string, yi int) bool {
	if xi != 0 && yi != 0 {
		return xi == yi
	}
	return x == "" || y == "" || normPort(x) == normPort(y)
}

// samePort is true when both sides name the same known interface.
func samePort(xi, yi int) bool { return xi != 0 && xi == yi }

// addLink records a connection, merging it with an existing one between the
// same two entities when the ports don't contradict each other. A port takes
// one cable, so the same known interface at either end is also the same
// link, whatever the other end is called: then the more trusted source's
// name for that end wins.
func (b *builder) addLink(a *entity, aIf int, aPort string, c *entity, cIf int, cPort, kind, src string, prio int) {
	if a == nil || c == nil || a == c {
		return
	}
	for _, l := range b.links {
		var lIf, rIf int
		var lp, rp string
		switch {
		case l.a == a && l.b == c:
			lIf, lp, rIf, rp = aIf, aPort, cIf, cPort
		case l.a == c && l.b == a:
			lIf, lp, rIf, rp = cIf, cPort, aIf, aPort
		default:
			continue
		}
		aOK := portsCompatible(l.aPort, l.aIf, lp, lIf)
		bOK := portsCompatible(l.bPort, l.bIf, rp, rIf)
		same := (aOK && bOK) || (aOK && samePort(l.aIf, lIf)) || (bOK && samePort(l.bIf, rIf))
		if !same {
			continue
		}
		if prio > l.prio {
			if !aOK {
				l.aPort, l.aIf = lp, lIf
			}
			if !bOK {
				l.bPort, l.bIf = rp, rIf
			}
		}
		if l.aPort == "" {
			l.aPort, l.aIf = lp, lIf
		}
		if l.bPort == "" {
			l.bPort, l.bIf = rp, rIf
		}
		if l.aIf == 0 {
			l.aIf = lIf
		}
		if l.bIf == 0 {
			l.bIf = rIf
		}
		l.sources[src] = true
		if prio > l.prio {
			l.prio, l.kind = prio, kind
		}
		return
	}
	b.links = append(b.links, &link{a: a, b: c, aIf: aIf, bIf: cIf, aPort: aPort, bPort: cPort,
		kind: kind, prio: prio, sources: map[string]bool{src: true}})
}

// discoveryLinks adds every link a protocol or controller reported.
func (b *builder) discoveryLinks() {
	for _, a := range b.ents {
		for _, d := range a.snmp {
			for j := range d.LLDP {
				n := &d.LLDP[j]
				c := b.byKey[b.lldpKey(n)]
				if c == nil || c == a {
					continue
				}
				aIf := lldpLocalIf(d, n.LocalPortNum)
				aPort := portLabel(d, aIf)
				if aPort == "" {
					aPort = fmt.Sprintf("port %d", n.LocalPortNum)
				}
				cPort, cIf := resolvePort(c, n.PortID, n.PortDesc)
				b.addLink(a, aIf, aPort, c, cIf, cPort, KindWired, "lldp", prioLLDP)
			}
			for j := range d.CDP {
				n := &d.CDP[j]
				var c *entity
				if m := b.ipMAC[n.Address]; m != "" {
					c = b.entityByMAC(m)
				}
				if c == nil {
					c = b.byKey["name:"+normName(n.DeviceID)]
				}
				if c == nil || c == a {
					continue
				}
				cPort, cIf := resolvePort(c, n.Port)
				b.addLink(a, n.IfIndex, portLabel(d, n.IfIndex), c, cIf, cPort, KindWired, "cdp", prioLLDP)
			}
		}
		if u := a.udev; u != nil {
			p := b.entityByMAC(u.UplinkMAC)
			if p == nil && u.UplinkID != "" {
				p = b.byKey["unifi:"+u.UplinkID]
			}
			if p != nil && p != a {
				kind := KindWired
				if u.UplinkWireless {
					kind = KindWireless
				}
				aPort, aIf := uniPortLabel(a, u.LocalPort)
				pPort, pIf := uniPortLabel(p, u.UplinkRemotePort)
				b.addLink(p, pIf, pPort, a, aIf, aPort, kind, "unifi", prioUniFi)
			}
		}
	}
}

// indexPorts records which switch ports lead to other network devices
// (uplinks) and which lead to a known host (e.g. a hypervisor).
func (b *builder) indexPorts() {
	b.uplinks = map[*entity]map[int]*entity{}
	b.hostPorts = map[*entity]map[int]*entity{}
	mark := func(m map[*entity]map[int]*entity, dev *entity, idx int, other *entity) {
		if idx == 0 {
			return
		}
		if m[dev] == nil {
			m[dev] = map[int]*entity{}
		}
		m[dev][idx] = other
		if d := dev.dev(); d != nil {
			m[dev][aggOf(d, idx)] = other
		}
	}
	for _, l := range b.links {
		if l.kind == KindWireless || l.kind == KindVirtual {
			continue
		}
		switch {
		case l.a.infra && l.b.infra:
			mark(b.uplinks, l.a, l.aIf, l.b)
			mark(b.uplinks, l.b, l.bIf, l.a)
		case l.a.infra:
			mark(b.hostPorts, l.a, l.aIf, l.b)
		case l.b.infra:
			mark(b.hostPorts, l.b, l.bIf, l.a)
		}
	}
}

// computeDepths sets hop counts from the gateway over current links.
func (b *builder) computeDepths(gw *entity) {
	for _, e := range b.ents {
		e.depth = -1
	}
	if gw == nil {
		return
	}
	adj := map[*entity][]*entity{}
	for _, l := range b.links {
		adj[l.a] = append(adj[l.a], l.b)
		adj[l.b] = append(adj[l.b], l.a)
	}
	gw.depth = 0
	queue := []*entity{gw}
	for len(queue) > 0 {
		e := queue[0]
		queue = queue[1:]
		// Visit network gear first so hosts hang under the deepest switch.
		next := slices.Clone(adj[e])
		slices.SortStableFunc(next, func(x, y *entity) int {
			if x.infra == y.infra {
				return 0
			}
			if x.infra {
				return -1
			}
			return 1
		})
		for _, n := range next {
			if n.depth < 0 {
				n.depth = e.depth + 1
				queue = append(queue, n)
			}
		}
	}
}

func (b *builder) linkedToInfra(e *entity) bool {
	for _, l := range b.links {
		if (l.a == e && l.b.infra) || (l.b == e && l.a.infra) {
			return true
		}
	}
	return false
}
