package scanner

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gosnmp/gosnmp"

	"github.com/liorokman/homelabmap/internal/obs"
)

const (
	oidSysDescr        = "1.3.6.1.2.1.1.1.0"
	oidSysObjectID     = "1.3.6.1.2.1.1.2.0"
	oidSysName         = "1.3.6.1.2.1.1.5.0"
	oidIPForwarding    = "1.3.6.1.2.1.4.1.0"
	oidBridgeAddress   = "1.3.6.1.2.1.17.1.1.0"
	oidLLDPLocChassis  = "1.0.8802.1.1.2.1.3.2.0"
	oidLLDPLocChassisT = "1.0.8802.1.1.2.1.3.1.0"

	oidPrinterName = "1.3.6.1.2.1.43.5.1.1.16"

	oidIfDescr     = "1.3.6.1.2.1.2.2.1.2"
	oidIfType      = "1.3.6.1.2.1.2.2.1.3"
	oidIfPhys      = "1.3.6.1.2.1.2.2.1.6"
	oidIfOper      = "1.3.6.1.2.1.2.2.1.8"
	oidIfName      = "1.3.6.1.2.1.31.1.1.1.1"
	oidIfHighSpeed = "1.3.6.1.2.1.31.1.1.1.15"
	oidIfAlias     = "1.3.6.1.2.1.31.1.1.1.18"
	oidLagAttached = "1.2.840.10006.300.43.1.2.1.1.13"

	oidLLDPLocPort = "1.0.8802.1.1.2.1.3.7.1" // .2 subtype .3 id .4 desc
	oidLLDPRem     = "1.0.8802.1.1.2.1.4.1.1" // columns 4..12
	oidLLDPRemMan  = "1.0.8802.1.1.2.1.4.2.1.3"

	oidCDPCache = "1.3.6.1.4.1.9.9.23.1.2.1.1" // .4 addr .6 devid .7 port .8 platform

	oidBasePortIf  = "1.3.6.1.2.1.17.1.4.1.2"
	oidQFdbPort    = "1.3.6.1.2.1.17.7.1.2.2.1.2"
	oidQFdbStatus  = "1.3.6.1.2.1.17.7.1.2.2.1.3"
	oidFdbPort     = "1.3.6.1.2.1.17.4.3.1.2"
	oidFdbStatus   = "1.3.6.1.2.1.17.4.3.1.3"
	oidARPPhys     = "1.3.6.1.2.1.4.22.1.2"
	oidARPType     = "1.3.6.1.2.1.4.22.1.4"
	fdbStatusSelf  = 4
	arpTypeInvalid = 2
)

func newSNMP(ctx context.Context, c SNMPConfig, ip string, timeout time.Duration, retries int) *gosnmp.GoSNMP {
	g := &gosnmp.GoSNMP{
		Context:            ctx,
		Target:             ip,
		Port:               161,
		Transport:          "udp",
		Timeout:            timeout,
		Retries:            retries,
		MaxRepetitions:     20,
		ExponentialTimeout: false,
		MaxOids:            gosnmp.MaxOids,
	}
	if c.Version == "3" {
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		usm := &gosnmp.UsmSecurityParameters{UserName: c.User}
		flags := gosnmp.NoAuthNoPriv
		if c.AuthPass != "" {
			flags = gosnmp.AuthNoPriv
			usm.AuthenticationPassphrase = c.AuthPass
			usm.AuthenticationProtocol = authProto(c.AuthProto)
			if c.PrivPass != "" {
				flags = gosnmp.AuthPriv
				usm.PrivacyPassphrase = c.PrivPass
				usm.PrivacyProtocol = privProto(c.PrivProto)
			}
		}
		g.MsgFlags = flags
		g.SecurityParameters = usm
	} else {
		g.Version = gosnmp.Version2c
		g.Community = c.Community
	}
	return g
}

func authProto(s string) gosnmp.SnmpV3AuthProtocol {
	switch strings.ToUpper(s) {
	case "MD5":
		return gosnmp.MD5
	case "SHA224":
		return gosnmp.SHA224
	case "SHA256":
		return gosnmp.SHA256
	case "SHA384":
		return gosnmp.SHA384
	case "SHA512":
		return gosnmp.SHA512
	default:
		return gosnmp.SHA
	}
}

func privProto(s string) gosnmp.SnmpV3PrivProtocol {
	switch strings.ToUpper(s) {
	case "DES":
		return gosnmp.DES
	case "AES192":
		return gosnmp.AES192
	case "AES256":
		return gosnmp.AES256
	default:
		return gosnmp.AES
	}
}

// snmpCollect probes every target and fully walks the ones that answer.
func snmpCollect(ctx context.Context, c SNMPConfig, targets []string, errs *errSink, log *slog.Logger) []obs.SNMPDevice {
	var (
		mu         sync.Mutex
		responders []string
		wg         sync.WaitGroup
		sem        = make(chan struct{}, max(c.Concurrency, 1))
	)
	for _, ip := range targets {
		wg.Go(func() {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			if snmpProbe(ctx, c, ip) {
				mu.Lock()
				responders = append(responders, ip)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	slices.Sort(responders)
	log.Debug("snmp probe done", "targets", len(targets), "responders", len(responders))

	out := make([]obs.SNMPDevice, len(responders))
	walkSem := make(chan struct{}, 6)
	for i, ip := range responders {
		wg.Go(func() {
			select {
			case walkSem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-walkSem }()
			start := time.Now()
			out[i] = snmpWalkDevice(ctx, c, ip)
			log.Debug("snmp walk", "ip", ip, "name", out[i].SysName, "took", time.Since(start).Round(time.Millisecond),
				"lldp", len(out[i].LLDP), "fdb", len(out[i].FDB), "arp", len(out[i].ARP))
			for _, e := range out[i].Errors {
				errs.add("snmp "+ip, fmt.Errorf("%s", e))
			}
		})
	}
	wg.Wait()
	return slices.DeleteFunc(out, func(d obs.SNMPDevice) bool { return d.IP == "" })
}

func snmpProbe(ctx context.Context, c SNMPConfig, ip string) bool {
	g := newSNMP(ctx, c, ip, c.Timeout, c.Retries)
	if err := g.Connect(); err != nil {
		return false
	}
	defer g.Conn.Close()
	r, err := g.Get([]string{oidSysObjectID})
	if err != nil || r == nil || len(r.Variables) == 0 {
		return false
	}
	t := r.Variables[0].Type
	return t != gosnmp.NoSuchObject && t != gosnmp.NoSuchInstance && t != gosnmp.Null
}

type walker struct {
	g   *gosnmp.GoSNMP
	dev *obs.SNMPDevice
}

// walk returns index-suffix -> PDU for one subtree. Errors are recorded on
// the device and an empty map is returned, so one bad table never aborts
// the rest of the device.
func (w *walker) walk(root string) map[string]gosnmp.SnmpPDU {
	pdus, err := w.g.BulkWalkAll(root)
	if err != nil {
		// Some agents mishandle GETBULK; retry with GETNEXT.
		pdus, err = w.g.WalkAll(root)
		if err != nil {
			w.dev.Errors = append(w.dev.Errors, fmt.Sprintf("walk %s: %v", root, err))
			return nil
		}
	}
	out := make(map[string]gosnmp.SnmpPDU, len(pdus))
	prefix := "." + root + "."
	for _, p := range pdus {
		if p.Type == gosnmp.NoSuchObject || p.Type == gosnmp.NoSuchInstance || p.Type == gosnmp.EndOfMibView {
			continue
		}
		if idx, ok := strings.CutPrefix(p.Name, prefix); ok {
			out[idx] = p
		}
	}
	return out
}

func snmpWalkDevice(ctx context.Context, c SNMPConfig, ip string) obs.SNMPDevice {
	dev := obs.SNMPDevice{IP: ip}
	g := newSNMP(ctx, c, ip, 3*time.Second, 2)
	if err := g.Connect(); err != nil {
		dev.Errors = append(dev.Errors, "connect: "+err.Error())
		return dev
	}
	defer g.Conn.Close()
	w := &walker{g: g, dev: &dev}

	// Scalars, fetched one by one: a missing object must not hide the others.
	for _, oid := range []string{oidSysDescr, oidSysObjectID, oidSysName, oidIPForwarding,
		oidBridgeAddress, oidLLDPLocChassisT, oidLLDPLocChassis} {
		r, err := g.Get([]string{oid})
		if err != nil || r == nil || len(r.Variables) == 0 {
			continue
		}
		p := r.Variables[0]
		if p.Type == gosnmp.NoSuchObject || p.Type == gosnmp.NoSuchInstance {
			continue
		}
		switch oid {
		case oidSysDescr:
			dev.SysDescr = pduString(p)
		case oidSysObjectID:
			dev.SysObjectID = strings.TrimPrefix(pduString(p), ".")
		case oidSysName:
			dev.SysName = pduString(p)
		case oidIPForwarding:
			dev.Forwarding = pduInt(p) == 1
		case oidBridgeAddress:
			dev.BridgeMAC = obs.MACFromBytes(pduBytes(p))
		case oidLLDPLocChassis:
			dev.LLDPChassisID = obs.MACFromBytes(pduBytes(p))
		}
	}
	if dev.SysObjectID == "" && dev.SysDescr == "" {
		dev.Errors = append(dev.Errors, "no system group")
		return dev
	}
	dev.IsPrinter = len(w.walk(oidPrinterName)) > 0

	collectInterfaces(w)
	collectLLDP(w)
	collectCDP(w)
	collectFDB(w)
	collectARP(w)
	return dev
}

func collectInterfaces(w *walker) {
	byIdx := map[int]*obs.Interface{}
	get := func(idx string) *obs.Interface {
		n, err := strconv.Atoi(idx)
		if err != nil {
			return nil
		}
		if byIdx[n] == nil {
			byIdx[n] = &obs.Interface{Index: n}
		}
		return byIdx[n]
	}
	for idx, p := range w.walk(oidIfDescr) {
		if i := get(idx); i != nil {
			i.Descr = pduString(p)
		}
	}
	for idx, p := range w.walk(oidIfName) {
		if i := get(idx); i != nil {
			i.Name = pduString(p)
		}
	}
	for idx, p := range w.walk(oidIfAlias) {
		if i := get(idx); i != nil {
			i.Alias = pduString(p)
		}
	}
	for idx, p := range w.walk(oidIfType) {
		if i := get(idx); i != nil {
			i.Type = int(pduInt(p))
		}
	}
	for idx, p := range w.walk(oidIfPhys) {
		if i := get(idx); i != nil {
			i.MAC = obs.MACFromBytes(pduBytes(p))
		}
	}
	for idx, p := range w.walk(oidIfOper) {
		if i := get(idx); i != nil {
			i.Up = pduInt(p) == 1
		}
	}
	for idx, p := range w.walk(oidIfHighSpeed) {
		if i := get(idx); i != nil {
			i.SpeedMbps = uint(pduInt(p))
		}
	}
	for idx, p := range w.walk(oidLagAttached) {
		if i := get(idx); i != nil {
			if agg := int(pduInt(p)); agg != 0 && agg != i.Index {
				i.AggIndex = agg
			}
		}
	}
	for _, i := range byIdx {
		w.dev.Interfaces = append(w.dev.Interfaces, *i)
	}
	slices.SortFunc(w.dev.Interfaces, func(a, b obs.Interface) int { return a.Index - b.Index })
}

func collectLLDP(w *walker) {
	// Local port table.
	loc := map[int]*obs.LLDPLocalPort{}
	locRaw := map[int][]byte{}
	for idx, p := range w.walk(oidLLDPLocPort) {
		col, rest, ok := strings.Cut(idx, ".")
		if !ok {
			continue
		}
		num, err := strconv.Atoi(rest)
		if err != nil {
			continue
		}
		lp := loc[num]
		if lp == nil {
			lp = &obs.LLDPLocalPort{Num: num}
			loc[num] = lp
		}
		switch col {
		case "2":
			lp.IDSubtype = int(pduInt(p))
		case "3":
			locRaw[num] = pduBytes(p)
		case "4":
			lp.Desc = pduString(p)
		}
	}
	for num, lp := range loc {
		lp.ID = formatLLDPID(lp.IDSubtype, locRaw[num], false)
		w.dev.LLDPLocal = append(w.dev.LLDPLocal, *lp)
	}
	slices.SortFunc(w.dev.LLDPLocal, func(a, b obs.LLDPLocalPort) int { return a.Num - b.Num })

	// Remote table: index is timeMark.localPortNum.remIndex.
	type remRaw struct {
		n                 obs.LLDPNeighbor
		chassis, portID   []byte
		chassisT, portIDT int
	}
	rem := map[string]*remRaw{}
	for idx, p := range w.walk(oidLLDPRem) {
		col, key, ok := strings.Cut(idx, ".")
		if !ok {
			continue
		}
		parts := strings.Split(key, ".")
		if len(parts) != 3 {
			continue
		}
		r := rem[key]
		if r == nil {
			lp, _ := strconv.Atoi(parts[1])
			r = &remRaw{n: obs.LLDPNeighbor{LocalPortNum: lp}}
			rem[key] = r
		}
		switch col {
		case "4":
			r.chassisT = int(pduInt(p))
		case "5":
			r.chassis = pduBytes(p)
		case "6":
			r.portIDT = int(pduInt(p))
		case "7":
			r.portID = pduBytes(p)
		case "8":
			r.n.PortDesc = pduString(p)
		case "9":
			r.n.SysName = pduString(p)
		case "10":
			r.n.SysDesc = pduString(p)
		case "12":
			r.n.Caps = decodeLLDPCaps(pduBytes(p))
		}
	}

	// Management addresses: index is timeMark.localPort.remIndex.subtype.len.addr...
	for idx := range w.walk(oidLLDPRemMan) {
		parts := strings.Split(idx, ".")
		if len(parts) < 5 {
			continue
		}
		r := rem[strings.Join(parts[:3], ".")]
		if r == nil {
			continue
		}
		r.n.MgmtAddrs = append(r.n.MgmtAddrs, decodeMgmtAddr(parts[3:]))
	}

	for _, r := range rem {
		r.n.ChassisSubtype, r.n.PortSubtype = r.chassisT, r.portIDT
		r.n.ChassisID = formatLLDPID(r.chassisT, r.chassis, true)
		r.n.PortID = formatLLDPID(r.portIDT, r.portID, false)
		w.dev.LLDP = append(w.dev.LLDP, r.n)
	}
	slices.SortFunc(w.dev.LLDP, func(a, b obs.LLDPNeighbor) int { return a.LocalPortNum - b.LocalPortNum })
}

// decodeMgmtAddr turns "subtype.len.b1.b2..." into an address. Agents get
// this wrong (some Cisco small-business switches send len=3 with three bytes), so anything that is
// not a well-formed address is returned with an "invalid:" prefix rather than
// guessed at.
func decodeMgmtAddr(parts []string) string {
	nums := make([]byte, 0, len(parts))
	for _, s := range parts {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 || n > 255 {
			return "invalid:" + strings.Join(parts, ".")
		}
		nums = append(nums, byte(n))
	}
	if len(nums) < 2 {
		return "invalid:" + strings.Join(parts, ".")
	}
	subtype, length, addr := nums[0], int(nums[1]), nums[2:]
	switch {
	case subtype == 1 && length == 4 && len(addr) == 4:
		return net.IP(addr).String()
	case subtype == 2 && length == 16 && len(addr) == 16:
		return net.IP(addr).String()
	}
	return "invalid:" + strings.Join(parts, ".")
}

// formatLLDPID renders chassis/port IDs according to their subtype.
// Chassis subtypes: 4=MAC, 5=network address. Port subtypes: 3=MAC, 4=network address.
func formatLLDPID(subtype int, b []byte, chassis bool) string {
	macType, netType := 3, 4
	if chassis {
		macType, netType = 4, 5
	}
	switch subtype {
	case macType:
		if m := obs.MACFromBytes(b); m != "" {
			return m
		}
	case netType:
		if len(b) == 5 && b[0] == 1 {
			return net.IP(b[1:]).String()
		}
	}
	if s, ok := printable(b); ok {
		return s
	}
	if m := obs.MACFromBytes(b); m != "" {
		return m
	}
	return hex.EncodeToString(b)
}

var lldpCapNames = []string{"other", "repeater", "bridge", "wlan-ap", "router", "telephone", "docsis", "station"}

// decodeLLDPCaps decodes the LLDP capabilities BITS value. Standard agents
// put bits 0-7 in the first octet (MSB first). Some UniFi switches send two
// octets with the meaningful one second; detect that by an empty first octet.
func decodeLLDPCaps(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	octet := b[0]
	if len(b) >= 2 && b[0] == 0 {
		octet = b[1]
	}
	var out []string
	for i, name := range lldpCapNames {
		if octet&(0x80>>i) != 0 {
			out = append(out, name)
		}
	}
	return out
}

func collectCDP(w *walker) {
	type row struct{ n obs.CDPNeighbor }
	rows := map[string]*row{}
	for idx, p := range w.walk(oidCDPCache) {
		col, key, ok := strings.Cut(idx, ".")
		if !ok {
			continue
		}
		r := rows[key]
		if r == nil {
			ifIdx, _, _ := strings.Cut(key, ".")
			n, _ := strconv.Atoi(ifIdx)
			r = &row{n: obs.CDPNeighbor{IfIndex: n}}
			rows[key] = r
		}
		switch col {
		case "4":
			if b := pduBytes(p); len(b) == 4 {
				r.n.Address = net.IP(b).String()
			}
		case "6":
			r.n.DeviceID = pduString(p)
		case "7":
			r.n.Port = pduString(p)
		case "8":
			r.n.Platform = pduString(p)
		}
	}
	for _, r := range rows {
		if r.n.DeviceID != "" || r.n.Address != "" {
			w.dev.CDP = append(w.dev.CDP, r.n)
		}
	}
	slices.SortFunc(w.dev.CDP, func(a, b obs.CDPNeighbor) int { return a.IfIndex - b.IfIndex })
}

func collectFDB(w *walker) {
	portIf := map[int]int{}
	for idx, p := range w.walk(oidBasePortIf) {
		if n, err := strconv.Atoi(idx); err == nil {
			portIf[n] = int(pduInt(p))
		}
	}
	toIf := func(port int) int {
		if i, ok := portIf[port]; ok {
			return i
		}
		return port
	}
	seen := map[string]bool{}
	add := func(mac string, vlan, port int) {
		if mac == "" || port == 0 || obs.IsMulticast(mac) {
			return
		}
		k := fmt.Sprintf("%s/%d", mac, vlan)
		if seen[k] {
			return
		}
		seen[k] = true
		w.dev.FDB = append(w.dev.FDB, obs.FDBEntry{MAC: mac, IfIndex: toIf(port), VLAN: vlan})
	}

	// Q-BRIDGE: index fdbId.m1.m2.m3.m4.m5.m6
	qStatus := w.walk(oidQFdbStatus)
	for idx, p := range w.walk(oidQFdbPort) {
		if s, ok := qStatus[idx]; ok && pduInt(s) == fdbStatusSelf {
			continue
		}
		if vlan, mac, ok := parseQFdbIndex(idx); ok {
			add(mac, vlan, int(pduInt(p)))
		}
	}
	if len(w.dev.FDB) > 0 {
		return
	}
	// Plain BRIDGE-MIB: index m1..m6
	status := w.walk(oidFdbStatus)
	for idx, p := range w.walk(oidFdbPort) {
		if s, ok := status[idx]; ok && pduInt(s) == fdbStatusSelf {
			continue
		}
		add(macFromOID(strings.Split(idx, ".")), 0, int(pduInt(p)))
	}
}

func collectARP(w *walker) {
	types := w.walk(oidARPType)
	for idx, p := range w.walk(oidARPPhys) {
		if t, ok := types[idx]; ok && pduInt(t) == arpTypeInvalid {
			continue
		}
		parts := strings.Split(idx, ".")
		if len(parts) != 5 {
			continue
		}
		mac := obs.MACFromBytes(pduBytes(p))
		if mac == "" {
			continue
		}
		ifIdx, _ := strconv.Atoi(parts[0])
		w.dev.ARP = append(w.dev.ARP, obs.ARPEntry{IP: strings.Join(parts[1:], "."), MAC: mac, IfIndex: ifIdx})
	}
	slices.SortFunc(w.dev.ARP, func(a, b obs.ARPEntry) int { return strings.Compare(a.IP, b.IP) })
}

// parseQFdbIndex decodes a dot1qTpFdbTable index "fdbId.m1.m2.m3.m4.m5.m6".
// Some agents (Cisco small-business switches) insert a length octet: "fdbId.6.m1...m6".
func parseQFdbIndex(idx string) (vlan int, mac string, ok bool) {
	parts := strings.Split(idx, ".")
	if len(parts) == 8 && parts[1] == "6" {
		parts = append(parts[:1], parts[2:]...)
	}
	if len(parts) != 7 {
		return 0, "", false
	}
	vlan, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, "", false
	}
	mac = macFromOID(parts[1:])
	return vlan, mac, mac != ""
}

func macFromOID(parts []string) string {
	if len(parts) != 6 {
		return ""
	}
	b := make([]byte, 6)
	for i, s := range parts {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 || n > 255 {
			return ""
		}
		b[i] = byte(n)
	}
	return obs.MACFromBytes(b)
}

func pduBytes(p gosnmp.SnmpPDU) []byte {
	switch v := p.Value.(type) {
	case []byte:
		return v
	case string:
		return []byte(v)
	}
	return nil
}

func pduString(p gosnmp.SnmpPDU) string {
	switch v := p.Value.(type) {
	case []byte:
		if s, ok := printable(v); ok {
			return s
		}
		return hex.EncodeToString(v)
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func pduInt(p gosnmp.SnmpPDU) int64 {
	if p.Value == nil {
		return 0
	}
	if _, ok := p.Value.([]byte); ok {
		return 0
	}
	return gosnmp.ToBigInt(p.Value).Int64()
}

// printable returns b as a string if it is readable text (trailing NULs trimmed).
func printable(b []byte) (string, bool) {
	s := strings.TrimRight(string(b), "\x00")
	if s == "" {
		return "", true
	}
	for _, r := range s {
		if r == unicode.ReplacementChar || (!unicode.IsPrint(r) && r != '\t') {
			return "", false
		}
	}
	return strings.TrimSpace(s), true
}
