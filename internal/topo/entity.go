package topo

import (
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/liorokman/homelabmap/internal/obs"
)

// entity is one physical or virtual device, merged from every source that
// mentioned one of its MACs (or, for sources without MACs, its name).
type entity struct {
	id      int
	keys    []string
	macs    map[string]bool
	ips     map[string]bool
	sources map[string]bool

	snmp      []*obs.SNMPDevice
	udev      *uniDev
	ucli      *uniClient
	pveNode   *obs.PVENode
	guest     *obs.PVEGuest
	guestNode string
	sweep     []obs.SweepHost
	ssdp      *obs.SSDPDevice
	lldpRefs  []*obs.LLDPNeighbor
	cdpRefs   []*obs.CDPNeighbor
	self      bool
	selfName  string

	role   string
	infra  bool
	depth  int
	hidden bool
	nodeID string

	// placement result
	location   string
	connection string
	parent     *entity
	behind     *entity // device it was inferred to sit behind
}

// fdbOnly reports a MAC nobody else knows anything about.
func (e *entity) fdbOnly() bool {
	return len(e.ips) == 0 && len(e.sources) == 1 && e.sources["fdb"]
}

// isPVEHost recognises a Proxmox host from SNMP: a -pve kernel plus Linux
// bridges. Containers share the kernel string but have no vmbr interfaces.
func (e *entity) isPVEHost() bool {
	if e.pveNode != nil {
		return true
	}
	d := e.dev()
	if d == nil || !strings.Contains(d.SysDescr, "-pve") {
		return false
	}
	for _, i := range d.Interfaces {
		if strings.HasPrefix(i.Name, "vmbr") {
			return true
		}
	}
	return false
}

// power says whether the device is on and how that was learned. Explicit
// reports (PVE, UniFi) win over "it answered this scan".
func (e *entity) power() (state, detail string) {
	switch {
	case e.guest != nil && e.guest.Status != "":
		if e.guest.Status == "running" {
			return PowerOn, e.guest.Status
		}
		return PowerOff, e.guest.Status
	case e.pveNode != nil && e.pveNode.Status != "":
		if e.pveNode.Status == "online" {
			return PowerOn, e.pveNode.Status
		}
		return PowerOff, e.pveNode.Status
	case e.udev != nil:
		if e.udev.Offline {
			return PowerOff, "disconnected"
		}
		return PowerOn, ""
	case e.self || len(e.sweep) > 0 || len(e.snmp) > 0 || e.ssdp != nil || (e.ucli != nil && !e.ucli.Offline):
		return PowerOn, ""
	case e.ucli != nil && e.ucli.Offline && len(e.ips) == 0:
		// Only the controller's history knows it: it isn't here now. (An
		// ARP entry would mean it was around very recently: unknown.)
		return PowerOff, NotSeen
	}
	return "", ""
}

// absent reports a device known only from history.
func (e *entity) absent() bool {
	_, detail := e.power()
	return detail == NotSeen
}

func (e *entity) addSource(s string) { e.sources[s] = true }

// sortedMACs gives deterministic iteration over the entity's MACs.
func (e *entity) sortedMACs() []string { return slices.Sorted(maps.Keys(e.macs)) }

func (e *entity) addIP(ip string) {
	if a, err := netip.ParseAddr(ip); err == nil && a.Is4() && !a.IsUnspecified() && !a.IsLoopback() {
		e.ips[a.String()] = true
	}
}

// dev returns the richest SNMP view of this entity (most interfaces).
func (e *entity) dev() *obs.SNMPDevice {
	var best *obs.SNMPDevice
	for _, d := range e.snmp {
		if best == nil || len(d.Interfaces)+len(d.FDB) > len(best.Interfaces)+len(best.FDB) {
			best = d
		}
	}
	return best
}

// record is one observation with the identity keys it vouches for.
type record struct {
	keys  []string
	apply func(*entity)
}

// unionFind over string keys.
type unionFind map[string]string

func (u unionFind) find(k string) string {
	if _, ok := u[k]; !ok {
		u[k] = k
		return k
	}
	root := k
	for u[root] != root {
		root = u[root]
	}
	for u[k] != root {
		next := u[k]
		u[k] = root
		k = next
	}
	return root
}

func (u unionFind) union(a, b string) {
	ra, rb := u.find(a), u.find(b)
	if ra != rb {
		u[rb] = ra
	}
}

func macKey(m string) string { return "m:" + m }

// normName reduces a device name for matching: lowercase, no domain.
func normName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if _, err := netip.ParseAddr(s); err == nil {
		return s
	}
	if i := strings.IndexByte(s, '.'); i > 0 {
		s = s[:i]
	}
	return s
}

var genericNames = map[string]bool{"": true, "localhost": true, "openwrt": true, "ubnt": true, "unifi": true, "router": true, "switch": true}

// virtualIfPrefixes are host interfaces whose MACs belong to guests,
// containers or tunnels, never to the host's own identity.
var virtualIfPrefixes = []string{"veth", "tap", "fwpr", "fwln", "fwbr", "docker", "br-", "virbr", "cni", "flannel", "cali", "vnet", "kube", "tun", "wg", "lo", "dummy", "macvtap"}

func isVirtualIf(name string) bool {
	n := strings.ToLower(name)
	for _, p := range virtualIfPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// enterprise returns the IANA enterprise number of a sysObjectID.
func enterprise(oid string) int {
	rest, ok := strings.CutPrefix(strings.TrimPrefix(oid, "."), "1.3.6.1.4.1.")
	if !ok {
		return 0
	}
	n, _ := strconv.Atoi(strings.SplitN(rest, ".", 2)[0])
	return n
}

const entNetSNMP = 8072

// networkEnterprises are vendors whose SNMP agents are network gear.
var networkEnterprises = map[int]bool{
	9: true, 14988: true, 4413: true, 41112: true, 2636: true, 25506: true, 4526: true,
	171: true, 11863: true, 12356: true, 30065: true, 1916: true, 2011: true, 6527: true,
	3955: true, 890: true, 674: true, 6486: true, 207: true, 5624: true, 8886: true,
}

func (b *builder) inSubnets(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, p := range b.subnets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// buildIPMAC maps IP -> MAC for this scan, most trusted source first.
func (b *builder) buildIPMAC() {
	prio := map[string]int{}
	set := func(ip, mac string, p int) {
		if ip == "" || mac == "" {
			return
		}
		if cur, ok := prio[ip]; ok && cur >= p {
			return
		}
		prio[ip] = p
		b.ipMAC[ip] = mac
	}
	for _, i := range b.res.Self.Interfaces {
		for _, ip := range i.IPs {
			set(ip, i.MAC, 4)
		}
	}
	for _, h := range b.res.Sweep {
		set(h.IP, h.MAC, 3)
	}
	for _, c := range b.uclis {
		if !c.Offline {
			set(c.IP, c.MAC, 2)
		}
	}
	for _, d := range b.udevs {
		set(d.IP, d.MAC, 2)
	}
	for i := range b.res.SNMP {
		d := &b.res.SNMP[i]
		router := d.Forwarding && networkEnterprises[enterprise(d.SysObjectID)]
		for _, a := range d.ARP {
			switch {
			case router:
				set(a.IP, a.MAC, 2)
			case b.inSubnets(a.IP):
				set(a.IP, a.MAC, 1)
			}
		}
	}
	if b.res.PVE != nil {
		for _, n := range b.res.PVE.Nodes {
			for _, g := range n.Guests {
				if len(g.NICs) == 1 {
					for _, ip := range g.IPs {
						set(ip, g.NICs[0].MAC, 2)
					}
				}
			}
		}
	}
}

// buildEntities runs union-find over every observation.
func (b *builder) buildEntities() {
	var recs []record
	add := func(r record) {
		r.keys = slices.DeleteFunc(r.keys, func(k string) bool { return k == "" || k == "m:" })
		if len(r.keys) > 0 {
			recs = append(recs, r)
		}
	}
	ipKey := func(ip string) string {
		if m := b.ipMAC[ip]; m != "" {
			return macKey(m)
		}
		return ""
	}

	// Scanner host (absent when the scanner couldn't list its interfaces).
	if len(b.res.Self.Interfaces) > 0 {
		keys := []string{"self"}
		for _, i := range b.res.Self.Interfaces {
			keys = append(keys, macKey(i.MAC))
		}
		add(record{keys: keys, apply: func(e *entity) {
			e.self = true
			e.selfName = b.res.Self.Hostname
			e.addSource("scanner")
			for _, i := range b.res.Self.Interfaces {
				for _, ip := range i.IPs {
					e.addIP(ip)
				}
			}
		}})
	}

	for _, h := range b.res.Sweep {
		k := macKey(h.MAC)
		if h.MAC == "" {
			k = ipKey(h.IP)
		}
		if k == "" {
			k = "ip:" + h.IP
		}
		add(record{keys: []string{k}, apply: func(e *entity) {
			e.sweep = append(e.sweep, h)
			e.addIP(h.IP)
			e.addSource("sweep")
		}})
	}

	for i := range b.res.SNMP {
		d := &b.res.SNMP[i]
		linuxHost := enterprise(d.SysObjectID) == entNetSNMP
		keys := []string{"snmp:" + d.IP, ipKey(d.IP), macKey(d.BridgeMAC), macKey(d.LLDPChassisID)}
		for _, itf := range d.Interfaces {
			if itf.MAC == "" || isVirtualIf(itf.Name) || isVirtualIf(itf.Descr) {
				continue
			}
			if linuxHost && obs.IsLocallyAdministered(itf.MAC) {
				continue
			}
			keys = append(keys, macKey(itf.MAC))
		}
		add(record{keys: keys, apply: func(e *entity) {
			e.snmp = append(e.snmp, d)
			e.addIP(d.IP)
			e.addSource("snmp")
		}})

		router := d.Forwarding && networkEnterprises[enterprise(d.SysObjectID)]
		for _, a := range d.ARP {
			if !router && !b.inSubnets(a.IP) {
				continue
			}
			add(record{keys: []string{macKey(a.MAC)}, apply: func(e *entity) {
				e.addIP(a.IP)
				e.addSource("arp")
			}})
		}
		if networkEnterprises[enterprise(d.SysObjectID)] {
			for _, f := range d.FDB {
				add(record{keys: []string{macKey(f.MAC)}, apply: func(e *entity) { e.addSource("fdb") }})
			}
		}
		for j := range d.LLDP {
			n := &d.LLDP[j]
			keys := []string{b.lldpKey(n)}
			for _, a := range n.MgmtAddrs {
				if strings.HasPrefix(a, "invalid:") {
					b.warn("%s (%s) reported an invalid LLDP management address for %q on local port %d: %s",
						d.SysName, d.IP, n.SysName, n.LocalPortNum, strings.TrimPrefix(a, "invalid:"))
					continue
				}
				keys = append(keys, ipKey(a))
			}
			add(record{keys: keys, apply: func(e *entity) {
				e.lldpRefs = append(e.lldpRefs, n)
				e.addSource("lldp")
				for _, a := range n.MgmtAddrs {
					if !strings.HasPrefix(a, "invalid:") {
						e.addIP(a)
					}
				}
			}})
		}
		for j := range d.CDP {
			n := &d.CDP[j]
			k := ipKey(n.Address)
			if k == "" {
				k = "name:" + normName(n.DeviceID)
			}
			add(record{keys: []string{k}, apply: func(e *entity) {
				e.cdpRefs = append(e.cdpRefs, n)
				e.addIP(n.Address)
				e.addSource("cdp")
			}})
		}
	}

	for i := range b.udevs {
		d := &b.udevs[i]
		keys := []string{macKey(d.MAC), ipKey(d.IP)}
		if d.ID != "" {
			keys = append(keys, "unifi:"+d.ID)
		}
		add(record{keys: keys, apply: func(e *entity) {
			e.udev = d
			e.addIP(d.IP)
			e.addSource("unifi")
		}})
	}
	for i := range b.uclis {
		c := &b.uclis[i]
		if c.Offline && c.Name == "" && c.Hostname == "" && b.known[c.MAC].Alias == "" {
			continue // an unnamed device that isn't here: noise, not information
		}
		add(record{keys: []string{macKey(c.MAC)}, apply: func(e *entity) {
			e.ucli = c
			if c.Offline {
				e.addSource("unifi-history")
				return
			}
			e.addIP(c.IP)
			e.addSource("unifi")
		}})
	}
	for i := range b.res.SSDP {
		d := &b.res.SSDP[i]
		k := ipKey(d.IP)
		if k == "" {
			k = "ip:" + d.IP
		}
		add(record{keys: []string{k}, apply: func(e *entity) {
			e.ssdp = d
			e.addIP(d.IP)
			e.addSource("ssdp")
		}})
	}

	if b.res.PVE != nil {
		for i := range b.res.PVE.Nodes {
			n := &b.res.PVE.Nodes[i]
			add(record{keys: []string{"pve:" + n.Name, ipKey(n.IP)}, apply: func(e *entity) {
				e.pveNode = n
				e.addIP(n.IP)
				e.addSource("pve")
			}})
			for j := range n.Guests {
				g := &n.Guests[j]
				keys := []string{"guest:" + n.Name + "/" + strconv.Itoa(g.VMID)}
				for _, nic := range g.NICs {
					keys = append(keys, macKey(nic.MAC))
				}
				add(record{keys: keys, apply: func(e *entity) {
					e.guest = g
					e.guestNode = n.Name
					for _, ip := range g.IPs {
						e.addIP(ip)
					}
					e.addSource("pve")
				}})
			}
		}
	}

	// Union every record's keys.
	uf := unionFind{}
	for _, r := range recs {
		for _, k := range r.keys[1:] {
			uf.union(r.keys[0], k)
		}
		uf.find(r.keys[0])
	}

	// MACs seen only in other devices' tables (MAC tables, controller
	// lists), never answering themselves, can be a host's secondary
	// addresses: bond members (whose MAC a bond hides) and addresses that
	// bonds and bridges derive from the NIC by setting the local bit. Such a
	// MAC joins the one answering device with a burned-in MAC that matches
	// it in the first five bytes (after clearing the local bit). Devices
	// that answered themselves are never folded into another.
	b.foldSecondaryMACs(uf)

	// Name-only neighbours (no MAC, no address) join the one device that
	// answered SNMP or UniFi under that name, if exactly one did.
	hasMAC := map[string]bool{}
	for k := range uf {
		if strings.HasPrefix(k, "m:") {
			hasMAC[uf.find(k)] = true
		}
	}
	named := map[string][]string{}
	for i := range b.res.SNMP {
		n := normName(b.res.SNMP[i].SysName)
		if !genericNames[n] {
			named[n] = append(named[n], uf.find("snmp:"+b.res.SNMP[i].IP))
		}
	}
	for _, d := range b.udevs {
		n := normName(d.Name)
		if !genericNames[n] && d.MAC != "" {
			named[n] = append(named[n], uf.find(macKey(d.MAC)))
		}
	}
	for k := range uf {
		name, ok := strings.CutPrefix(k, "name:")
		if !ok || hasMAC[uf.find(k)] {
			continue
		}
		if roots := slices.Compact(slices.Sorted(slices.Values(named[name]))); len(roots) == 1 {
			uf.union(roots[0], k)
		}
	}

	// Materialise.
	byRoot := map[string]*entity{}
	for _, r := range recs {
		root := uf.find(r.keys[0])
		e := byRoot[root]
		if e == nil {
			e = &entity{id: len(b.ents), macs: map[string]bool{}, ips: map[string]bool{}, sources: map[string]bool{}}
			byRoot[root] = e
			b.ents = append(b.ents, e)
		}
		r.apply(e)
	}
	for k := range uf {
		e := byRoot[uf.find(k)]
		if e == nil {
			continue
		}
		e.keys = append(e.keys, k)
		b.byKey[k] = e
		if m, ok := strings.CutPrefix(k, "m:"); ok {
			e.macs[m] = true
		}
	}
	for _, e := range b.ents {
		slices.Sort(e.keys)
	}
}

func (b *builder) lldpKey(n *obs.LLDPNeighbor) string {
	if n.ChassisSubtype == 4 {
		if m := obs.NormMAC(n.ChassisID); m != "" {
			return macKey(m)
		}
	}
	if name := normName(n.SysName); !genericNames[name] {
		return "name:" + name
	}
	return "lldp:" + n.ChassisID
}

func (b *builder) entityByMAC(mac string) *entity {
	if mac == "" {
		return nil
	}
	return b.byKey[macKey(mac)]
}

// globalVariant clears the locally-administered bit: da:3b:… -> d8:3b:….
func globalVariant(mac string) string {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return ""
	}
	hw[0] &^= 0x02
	return hw.String()
}

// foldSecondaryMACs implements the rule described in buildEntities.
func (b *builder) foldSecondaryMACs(uf unionFind) {
	strong := map[string]bool{}
	for _, h := range b.res.Sweep {
		strong[macKey(h.MAC)] = true
	}
	for _, i := range b.res.Self.Interfaces {
		strong[macKey(i.MAC)] = true
	}
	for _, d := range b.res.SNMP {
		strong[macKey(d.BridgeMAC)] = true
		for _, itf := range d.Interfaces {
			strong[macKey(itf.MAC)] = true
		}
	}
	delete(strong, macKey(""))
	strongRoot := map[string]bool{}
	byPrefix := map[string]map[string]bool{}
	for k := range strong {
		if _, ok := uf[k]; !ok {
			continue
		}
		root := uf.find(k)
		strongRoot[root] = true
		m := strings.TrimPrefix(k, "m:")
		if len(m) == 17 && !obs.IsLocallyAdministered(m) {
			if byPrefix[m[:14]] == nil {
				byPrefix[m[:14]] = map[string]bool{}
			}
			byPrefix[m[:14]][root] = true
		}
	}
	// Sets with an identity of their own (a PVE guest, an SNMP agent, a
	// UniFi device, ...) are devices in their own right, not addresses.
	anchored := map[string]bool{}
	for k := range uf {
		if !strings.HasPrefix(k, "m:") {
			anchored[uf.find(k)] = true
		}
	}
	for _, k := range slices.Sorted(maps.Keys(uf)) {
		m, ok := strings.CutPrefix(k, "m:")
		if !ok || strongRoot[uf.find(k)] || anchored[uf.find(k)] {
			continue
		}
		g := globalVariant(m)
		if g == "" {
			continue
		}
		if roots := byPrefix[g[:14]]; len(roots) == 1 {
			for root := range roots {
				uf.union(root, k)
			}
		}
	}
}
