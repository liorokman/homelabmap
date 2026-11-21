package topo

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
)

type builder struct {
	res     *obs.Result
	hist    History
	subnets []netip.Prefix
	osScans map[string]obs.OSScan

	ipMAC map[string]string
	udevs []uniDev
	uclis []uniClient // connected clients, then offline ones from history
	known map[string]uniKnown

	ents   []*entity
	byKey  map[string]*entity
	labels map[*entity]string
	links  []*link

	uplinks   map[*entity]map[int]*entity
	hostPorts map[*entity]map[int]*entity
	fdb       map[string][]sighting
	portCount map[*entity]map[int]int
	hasFDB    map[*entity]bool

	warnings []string
}

func (b *builder) warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if !slices.Contains(b.warnings, msg) {
		b.warnings = append(b.warnings, msg)
	}
}

// Build infers the topology for one scan.
func Build(scanID int64, res *obs.Result, hist History) *Graph {
	b := &builder{
		res:     res,
		hist:    hist,
		ipMAC:   map[string]string{},
		byKey:   map[string]*entity{},
		labels:  map[*entity]string{},
		osScans: map[string]obs.OSScan{},
	}
	for _, s := range res.Subnets {
		if p, err := netip.ParsePrefix(s); err == nil {
			b.subnets = append(b.subnets, p)
		}
	}
	maps.Copy(b.osScans, hist.OSScans)
	for _, s := range res.OSScans {
		b.osScans[s.MAC] = s
	}
	b.udevs, b.uclis = parseUniFi(res.UniFi)
	connected := map[string]bool{}
	for _, c := range b.uclis {
		connected[c.MAC] = true
	}
	b.uclis = append(b.uclis, parseUniFiHistory(res.UniFi, connected)...)
	b.known = parseUniFiKnown(res.UniFi)

	b.buildIPMAC()
	b.buildEntities()
	b.assignRoles()
	for _, e := range b.ents {
		b.labels[e] = b.labelOf(e)
	}
	gw := b.pickGateway()

	b.discoveryLinks()
	b.indexPorts()
	b.computeDepths(gw)
	b.indexFDB()
	b.placeGuests()

	// Network gear first (nearest the gateway first), so hosts can be
	// placed behind devices that were themselves just placed.
	order := slices.Clone(b.ents)
	slices.SortStableFunc(order, func(x, y *entity) int {
		if x.infra != y.infra {
			if x.infra {
				return -1
			}
			return 1
		}
		return cmp.Compare(depthKey(x), depthKey(y))
	})
	for _, e := range order {
		if e == gw || e.guest != nil && e.parent != nil {
			continue
		}
		if b.linkedToInfra(e) {
			e.connection, e.location = b.describeLinked(e)
			continue
		}
		b.place(e, gw)
		if e.infra {
			b.indexPorts()
			b.computeDepths(gw)
		}
	}
	b.computeDepths(gw)
	// Unknown devices behind a hypervisor's port are its guests.
	for _, e := range b.ents {
		if e.role == RoleClient && e.behind != nil && e.behind.role == RoleHypervisor {
			e.role = RoleVM
		}
	}
	for _, e := range res.Errors {
		b.warn("scanner: %s", e)
	}
	g := b.output(scanID, gw)
	linkRotated(g) // the controller's history can hold a phone's old MACs
	return g
}

func depthKey(e *entity) int {
	if e.depth < 0 {
		return 1 << 20
	}
	return e.depth
}

// describeLinked explains where a device with a reported link is attached.
func (b *builder) describeLinked(e *entity) (string, string) {
	var best *link
	for _, l := range b.links {
		other := l.b
		if l.b == e {
			other = l.a
		}
		if (l.a != e && l.b != e) || !other.infra {
			continue
		}
		if best == nil || depthKey(other) < depthKey(b.otherEnd(best, e)) || l.prio > best.prio {
			best = l
		}
	}
	if best == nil {
		return "", ""
	}
	other, port := best.a, best.aPort
	if best.a == e {
		other, port = best.b, best.bPort
	}
	loc := b.labels[other]
	if port != "" {
		loc += " port " + port
	}
	switch best.kind {
	case KindWireless:
		return KindWireless, "wireless uplink to " + b.labels[other]
	default:
		return KindWired, loc
	}
}

func (b *builder) otherEnd(l *link, e *entity) *entity {
	if l.a == e {
		return l.b
	}
	return l.a
}

// namesOf lists every name any source gave this entity, best first.
func (b *builder) namesOf(e *entity) []string {
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	if e.udev != nil {
		add(e.udev.Name)
	}
	for _, m := range e.sortedMACs() {
		add(b.known[m].Alias) // set by hand in UniFi: the best name there is
	}
	if e.guest != nil {
		add(e.guest.Name)
	}
	if e.pveNode != nil {
		add(e.pveNode.Name)
	}
	for _, d := range e.snmp {
		if !genericNames[normName(d.SysName)] {
			add(d.SysName)
		}
	}
	if e.ucli != nil {
		add(e.ucli.Name)
	}
	if e.ssdp != nil && !e.infra {
		add(e.ssdp.FriendlyName)
	}
	if e.ucli != nil {
		add(e.ucli.Hostname)
	}
	for _, n := range e.lldpRefs {
		add(n.SysName)
	}
	for _, n := range e.cdpRefs {
		add(n.DeviceID)
	}
	for _, ip := range b.sortedIPs(e) {
		add(b.res.DNS[ip])
	}
	for _, m := range e.sortedMACs() {
		add(b.known[m].Hostname)
	}
	if e.self {
		add(e.selfName)
	}
	return out
}

func (b *builder) labelOf(e *entity) string {
	if names := b.namesOf(e); len(names) > 0 {
		n := names[0]
		if _, err := netip.ParseAddr(n); err != nil {
			if i := strings.IndexByte(n, '.'); i > 0 {
				n = n[:i]
			}
		}
		return n
	}
	if v := b.vendorOf(e); v != "" {
		short := strings.Fields(v)[0]
		if m := b.primaryMAC(e); len(m) == 17 {
			return short + " " + m[9:]
		}
		return short
	}
	if ips := b.sortedIPs(e); len(ips) > 0 {
		return ips[0]
	}
	return b.primaryMAC(e)
}

func (b *builder) vendorOf(e *entity) string {
	for _, h := range e.sweep {
		if h.Vendor != "" {
			return h.Vendor
		}
	}
	if e.ucli != nil && e.ucli.OUI != "" {
		return e.ucli.OUI
	}
	if e.udev != nil {
		return "Ubiquiti"
	}
	if e.ssdp != nil && e.ssdp.Manufacturer != "" {
		return e.ssdp.Manufacturer
	}
	return ""
}

// sortedIPs puts addresses inside the scanned subnets first.
func (b *builder) sortedIPs(e *entity) []string {
	ips := slices.Collect(maps.Keys(e.ips))
	slices.SortFunc(ips, func(x, y string) int {
		ix, iy := b.inSubnets(x), b.inSubnets(y)
		if ix != iy {
			if ix {
				return -1
			}
			return 1
		}
		ax, _ := netip.ParseAddr(x)
		ay, _ := netip.ParseAddr(y)
		return ax.Compare(ay)
	})
	return ips
}

// displayIPs drops foreign addresses (Docker bridges, fallback IPs) when the
// device has at least one address on the scanned LAN.
func (b *builder) displayIPs(e *entity) []string {
	ips := b.sortedIPs(e)
	lan := slices.DeleteFunc(slices.Clone(ips), func(ip string) bool { return !b.inSubnets(ip) })
	if len(lan) > 0 {
		return lan
	}
	return ips
}

// primaryMAC is the address the device uses on the LAN, when known.
func (b *builder) primaryMAC(e *entity) string {
	for _, ip := range b.sortedIPs(e) {
		if m := b.ipMAC[ip]; m != "" && e.macs[m] {
			return m
		}
	}
	for _, h := range e.sweep {
		if h.MAC != "" {
			return h.MAC
		}
	}
	if e.udev != nil && e.udev.MAC != "" {
		return e.udev.MAC
	}
	if e.ucli != nil {
		return e.ucli.MAC
	}
	if d := e.dev(); d != nil {
		if d.BridgeMAC != "" && e.macs[d.BridgeMAC] {
			return d.BridgeMAC
		}
		if d.LLDPChassisID != "" && e.macs[d.LLDPChassisID] {
			return d.LLDPChassisID
		}
	}
	macs := slices.Sorted(maps.Keys(e.macs))
	if len(macs) > 0 {
		return macs[0]
	}
	return ""
}

func (b *builder) output(scanID int64, gw *entity) *Graph {
	g := &Graph{
		ScanID: scanID, Version: Version,
		ScanStarted: b.res.StartedAt, ScanEnded: b.res.FinishedAt,
		Warnings: b.warnings,
	}
	usedIDs := map[string]bool{}
	for _, e := range b.ents {
		if e.hidden {
			continue
		}
		pm := b.primaryMAC(e)
		id := "n-" + pm
		if pm == "" {
			id = "n-" + strings.NewReplacer(":", "-", "/", "-", " ", "_").Replace(e.keys[0])
		}
		for usedIDs[id] {
			id += "+"
		}
		usedIDs[id] = true
		e.nodeID = id
	}
	for _, e := range b.ents {
		if e.hidden {
			continue
		}
		g.Nodes = append(g.Nodes, b.node(e, gw))
	}
	slices.SortFunc(g.Nodes, func(x, y Node) int {
		return cmp.Or(cmp.Compare(x.Depth, y.Depth), strings.Compare(x.Label, y.Label))
	})

	for i, l := range b.links {
		if l.a.hidden || l.b.hidden {
			continue
		}
		src, dst, sp, dp := l.a, l.b, l.aPort, l.bPort
		// Point edges away from the gateway; guests always hang off their host.
		if src.parent == dst || (dst.parent != src && depthKey(dst) < depthKey(src)) {
			src, dst, sp, dp = dst, src, dp, sp
		}
		kind := l.kind
		if kind == KindWired && src.infra && dst.infra {
			kind = KindInfra
		}
		g.Edges = append(g.Edges, Edge{
			ID: fmt.Sprintf("e%d", i), Source: src.nodeID, Target: dst.nodeID, Kind: kind,
			SourcePort: sp, TargetPort: dp, Sources: slices.Sorted(maps.Keys(l.sources)),
			Absent: src.absent() || dst.absent(),
		})
	}
	return g
}

func (b *builder) node(e *entity, gw *entity) Node {
	osg := b.identifyOS(e)
	n := Node{
		ID:         e.nodeID,
		Label:      b.labels[e],
		Role:       e.role,
		Infra:      e.infra,
		OS:         osg.name,
		OSSource:   osg.source,
		IPs:        b.displayIPs(e),
		Vendor:     b.vendorOf(e),
		Location:   e.location,
		Connection: e.connection,
		Sources:    slices.Sorted(maps.Keys(e.sources)),
		Depth:      e.depth,
	}
	if e == gw {
		n.Location = "gateway"
	}
	if pm := b.primaryMAC(e); pm != "" {
		n.MACs = append(n.MACs, pm)
	}
	if !e.infra {
		for _, m := range slices.Sorted(maps.Keys(e.macs)) {
			if !slices.Contains(n.MACs, m) {
				n.MACs = append(n.MACs, m)
			}
		}
	}
	for _, ip := range n.IPs {
		if name := b.res.DNS[ip]; name != "" && !slices.Contains(n.DNS, name) {
			n.DNS = append(n.DNS, name)
		}
	}
	switch {
	case e.udev != nil:
		n.Model = e.udev.Model
	case e.infra && e.dev() != nil:
		n.Model = firstLine(e.dev().SysDescr)
	case e.ssdp != nil:
		n.Model = ssdpModel(e.ssdp)
	}
	if e.parent != nil {
		n.Parent = e.parent.nodeID
	}
	n.Power, n.PowerState = e.power()
	if e.absent() {
		n.Absent = true
		if n.Location != "" {
			n.Location = "last seen: " + n.Location
		}
	}
	for _, m := range e.sortedMACs() {
		if s, ok := b.osScans[m]; ok && len(s.OpenPorts) > 0 {
			n.OpenPorts = s.OpenPorts
			break
		}
	}

	// Icon: network gear by role, everything else by OS.
	switch {
	case e.infra:
		n.Icon = e.role
	case e.role == RolePrinter:
		n.Icon = IconPrinter
	case osg.icon != "":
		n.Icon = osg.icon
	case e.role == RoleHypervisor || e.role == RoleServer || e.role == RoleVM || e.role == RoleContainer:
		n.Icon = IconServer
	default:
		n.Icon = IconUnknown
	}

	n.IPv6, n.LastSeen = b.passive(e)
	later := func(t time.Time) {
		if t.After(n.LastSeen) {
			n.LastSeen = t
		}
	}
	if n.Power == PowerOn {
		later(b.res.StartedAt)
	}

	var first time.Time
	earlier := func(t time.Time) {
		if !t.IsZero() && (first.IsZero() || t.Before(first)) {
			first = t
		}
	}
	for m := range e.macs {
		earlier(b.hist.FirstSeen[m])
		// The controller's memory goes back further than homelabmap's.
		earlier(b.known[m].FirstSeen)
		later(b.known[m].LastSeen)
	}
	if e.ucli != nil {
		earlier(e.ucli.FirstSeen)
		later(e.ucli.LastSeen)
	}
	n.FirstSeen = first
	cutoff := b.res.StartedAt.Add(-24 * time.Hour)
	n.New = !b.hist.Since.IsZero() && b.hist.Since.Before(cutoff) && (first.IsZero() || first.After(cutoff))
	return n
}

// passive gathers what the listener heard for the entity's MACs: IPv6
// addresses (global ones first) and the latest time any MAC was seen.
func (b *builder) passive(e *entity) ([]string, time.Time) {
	var v6 []string
	var last time.Time
	for _, m := range e.sortedMACs() {
		for _, ip := range b.hist.IPv6[m] {
			if !slices.Contains(v6, ip) {
				v6 = append(v6, ip)
			}
		}
		if t := b.hist.LastSeen[m]; t.After(last) {
			last = t
		}
	}
	slices.SortStableFunc(v6, func(a, c string) int {
		return boolInt(strings.HasPrefix(a, "fe80:")) - boolInt(strings.HasPrefix(c, "fe80:"))
	})
	return v6, last
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ssdpModel is "Maker Model" without repeating the maker.
func ssdpModel(d *obs.SSDPDevice) string {
	model := strings.TrimSpace(d.ModelName + " " + d.ModelNumber)
	if d.ModelNumber != "" && strings.Contains(d.ModelName, d.ModelNumber) {
		model = d.ModelName
	}
	maker := strings.TrimSuffix(d.Manufacturer, ".")
	if maker == "" || strings.HasPrefix(strings.ToLower(model), strings.ToLower(strings.Fields(maker)[0])) {
		return model
	}
	return strings.TrimSpace(maker + " " + model)
}
