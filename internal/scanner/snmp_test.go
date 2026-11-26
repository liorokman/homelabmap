package scanner

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// fakeAgent is an in-memory SNMP agent. Its data is fictional.
type fakeAgent struct {
	pdus     map[string]gosnmp.SnmpPDU
	bulkFail bool // agent that mishandles GETBULK
	walkFail bool
	getFail  bool
	closed   bool
}

func newAgent() *fakeAgent { return &fakeAgent{pdus: map[string]gosnmp.SnmpPDU{}} }

func (a *fakeAgent) set(oid string, t gosnmp.Asn1BER, v any) *fakeAgent {
	a.pdus["."+oid] = gosnmp.SnmpPDU{Name: "." + oid, Type: t, Value: v}
	return a
}
func (a *fakeAgent) str(oid, v string) *fakeAgent { return a.set(oid, gosnmp.OctetString, []byte(v)) }
func (a *fakeAgent) raw(oid string, b ...byte) *fakeAgent {
	return a.set(oid, gosnmp.OctetString, b)
}
func (a *fakeAgent) num(oid string, v int) *fakeAgent { return a.set(oid, gosnmp.Integer, v) }

func (a *fakeAgent) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	if a.getFail {
		return nil, errors.New("timeout")
	}
	pkt := &gosnmp.SnmpPacket{}
	for _, o := range oids {
		p, ok := a.pdus["."+o]
		if !ok {
			p = gosnmp.SnmpPDU{Name: "." + o, Type: gosnmp.NoSuchObject}
		}
		pkt.Variables = append(pkt.Variables, p)
	}
	return pkt, nil
}

func (a *fakeAgent) walk(root string) []gosnmp.SnmpPDU {
	var out []gosnmp.SnmpPDU
	for name, p := range a.pdus {
		if strings.HasPrefix(name, "."+root+".") {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(x, y gosnmp.SnmpPDU) int { return strings.Compare(x.Name, y.Name) })
	return out
}

func (a *fakeAgent) BulkWalkAll(root string) ([]gosnmp.SnmpPDU, error) {
	if a.bulkFail {
		return nil, errors.New("GETBULK not supported")
	}
	return a.walk(root), nil
}

func (a *fakeAgent) WalkAll(root string) ([]gosnmp.SnmpPDU, error) {
	if a.walkFail {
		return nil, errors.New("no response")
	}
	return a.walk(root), nil
}

func (a *fakeAgent) Close() error { a.closed = true; return nil }

// useAgents points dialSNMP at fake agents for the duration of a test.
func useAgents(t *testing.T, agents map[string]*fakeAgent) {
	t.Helper()
	orig := dialSNMP
	dialSNMP = func(_ context.Context, _ SNMPConfig, ip string, _ time.Duration, _ int) (snmpSession, error) {
		if a, ok := agents[ip]; ok {
			return a, nil
		}
		return nil, errors.New("connection refused")
	}
	t.Cleanup(func() { dialSNMP = orig })
}

// switchAgent is a fictional managed switch with every table homelabmap reads.
func switchAgent() *fakeAgent {
	a := newAgent().
		str(oidSysDescr, "Example Switch 24, firmware 1.2.3").
		set(oidSysObjectID, gosnmp.ObjectIdentifier, ".1.3.6.1.4.1.9.6.1.99").
		str(oidSysName, "sw1").
		num(oidIPForwarding, 2).
		raw(oidBridgeAddress, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x10).
		num(oidLLDPLocChassisT, 4).
		raw(oidLLDPLocChassis, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x10)
	// Interfaces 1 and 2 are members of LAG 100; 3 is an access port.
	for _, i := range []struct {
		idx                string
		descr, name, alias string
		speed, agg         int
	}{
		{"1", "Port 1", "gi1", "to-ap", 1000, 100},
		{"2", "Port 2", "gi2", "", 1000, 100},
		{"3", "Port 3", "gi3", "", -1, 3},
		{"100", "Port-channel 1", "Po1", "", 2000, 0},
	} {
		a.str(oidIfDescr+"."+i.idx, i.descr).str(oidIfName+"."+i.idx, i.name).
			num(oidIfType+"."+i.idx, 6).num(oidIfOper+"."+i.idx, 1).num(oidIfHighSpeed+"."+i.idx, i.speed)
		if i.alias != "" {
			a.str(oidIfAlias+"."+i.idx, i.alias)
		}
		if i.agg != 0 {
			a.num(oidLagAttached+"."+i.idx, i.agg)
		}
	}
	a.raw(oidIfPhys+".1", 0x00, 0x00, 0x5e, 0x00, 0x53, 0x11)
	a.str(oidIfDescr+".x", "bad index is skipped")

	// LLDP local ports: one with a locally assigned name, one with a MAC.
	a.num(oidLLDPLocPort+".2.1", 7).str(oidLLDPLocPort+".3.1", "gi1").str(oidLLDPLocPort+".4.1", "Port 1")
	a.num(oidLLDPLocPort+".2.3", 3).raw(oidLLDPLocPort+".3.3", 0x00, 0x00, 0x5e, 0x00, 0x53, 0x13)
	a.str(oidLLDPLocPort+".nodot", "ignored").str(oidLLDPLocPort+".3.x", "ignored")

	// One LLDP neighbour (an access point) on local port 1, with a good and a truncated address.
	rem := oidLLDPRem + "."
	a.num(rem+"4.0.1.1", 4).raw(rem+"5.0.1.1", 0x00, 0x00, 0x5e, 0x00, 0x53, 0x20).
		num(rem+"6.0.1.1", 7).str(rem+"7.0.1.1", "eth0").str(rem+"8.0.1.1", "uplink").
		str(rem+"9.0.1.1", "ap1").str(rem+"10.0.1.1", "Example AP").raw(rem+"12.0.1.1", 0x00, 0x30)
	a.str(rem+"9.0.1", "malformed key is skipped")
	man := oidLLDPRemMan + "."
	a.num(man+"0.1.1.1.4.192.0.2.20", 2).num(man+"0.1.1.1.3.192.0.2", 2).num(man+"9.9.9.1.4.192.0.2.21", 2).num(man+"0.1", 2)

	// CDP: the router on interface 3.
	cdp := oidCDPCache + "."
	a.raw(cdp+"4.3.1", 192, 0, 2, 1).str(cdp+"6.3.1", "gw1").str(cdp+"7.3.1", "ether1").str(cdp+"8.3.1", "ExampleOS")
	a.str(cdp+"6.nodot", "ignored").raw(cdp+"4.9.1", 1, 2) // no device id, bad address: dropped

	// Q-BRIDGE MAC table: bridge ports 1..3 map to ifIndex 1..3. One row
	// uses the length-octet index some agents send; self and multicast are skipped.
	for _, p := range []string{"1", "2", "3"} {
		a.num(oidBasePortIf+"."+p, int(p[0]-'0'))
	}
	q := func(idx string, port, status int) {
		a.num(oidQFdbPort+"."+idx, port).num(oidQFdbStatus+"."+idx, status)
	}
	q("1.0.0.94.0.83.32", 1, 3)    // 00:00:5e:00:53:20 learned on port 1
	q("1.6.0.0.94.0.83.33", 3, 3)  // length-octet form
	q("1.0.0.94.0.83.16", 3, 4)    // the switch itself
	q("1.1.0.94.0.0.251", 3, 3)    // multicast
	q("1.0.0.94.0.83.32.99", 1, 3) // malformed
	q("2.0.0.94.0.83.32", 0, 3)    // port 0: unknown

	// ARP: one dynamic, one invalid, one malformed.
	a.raw(oidARPPhys+".3.192.0.2.1", 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01).num(oidARPType+".3.192.0.2.1", 3)
	a.raw(oidARPPhys+".3.192.0.2.9", 0x00, 0x00, 0x5e, 0x00, 0x53, 0x09).num(oidARPType+".3.192.0.2.9", 2)
	a.raw(oidARPPhys+".3.192.0.2", 0x00, 0x00, 0x5e, 0x00, 0x53, 0x0a)
	a.raw(oidARPPhys+".3.192.0.2.10", 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	return a
}

func TestSNMPWalkDevice(t *testing.T) {
	sw := switchAgent()
	useAgents(t, map[string]*fakeAgent{"192.0.2.10": sw})
	d := snmpWalkDevice(context.Background(), SNMPConfig{}, "192.0.2.10")

	if d.SysName != "sw1" || d.SysObjectID != "1.3.6.1.4.1.9.6.1.99" || d.Forwarding ||
		d.BridgeMAC != "00:00:5e:00:53:10" || d.LLDPChassisID != "00:00:5e:00:53:10" || d.IsPrinter || !sw.closed {
		t.Errorf("system group: %+v", d)
	}
	if len(d.Interfaces) != 4 {
		t.Fatalf("interfaces: %+v", d.Interfaces)
	}
	i1, i3 := d.Interfaces[0], d.Interfaces[2]
	if i1.Name != "gi1" || i1.Alias != "to-ap" || i1.AggIndex != 100 || i1.MAC != "00:00:5e:00:53:11" || !i1.Up || i1.SpeedMbps != 1000 {
		t.Errorf("interface 1: %+v", i1)
	}
	if i3.AggIndex != 0 || i3.SpeedMbps != 0 {
		t.Errorf("interface 3 (own aggregate, negative speed): %+v", i3)
	}
	if len(d.LLDPLocal) != 2 || d.LLDPLocal[0].ID != "gi1" || d.LLDPLocal[0].Desc != "Port 1" || d.LLDPLocal[1].ID != "00:00:5e:00:53:13" {
		t.Errorf("LLDP local: %+v", d.LLDPLocal)
	}
	if len(d.LLDP) != 1 {
		t.Fatalf("LLDP: %+v", d.LLDP)
	}
	n := d.LLDP[0]
	if n.LocalPortNum != 1 || n.ChassisID != "00:00:5e:00:53:20" || n.PortID != "eth0" || n.SysName != "ap1" ||
		!slices.Equal(n.MgmtAddrs, []string{"192.0.2.20", "invalid:1.3.192.0.2"}) || !slices.Contains(n.Caps, "wlan-ap") {
		t.Errorf("LLDP neighbour: %+v", n)
	}
	if len(d.CDP) != 1 || d.CDP[0].Address != "192.0.2.1" || d.CDP[0].DeviceID != "gw1" || d.CDP[0].IfIndex != 3 {
		t.Errorf("CDP: %+v", d.CDP)
	}
	if len(d.FDB) != 2 || d.FDB[0].MAC != "00:00:5e:00:53:20" || d.FDB[0].IfIndex != 1 ||
		d.FDB[1].MAC != "00:00:5e:00:53:21" || d.FDB[1].IfIndex != 3 {
		t.Errorf("FDB: %+v", d.FDB)
	}
	if len(d.ARP) != 1 || d.ARP[0].IP != "192.0.2.1" || d.ARP[0].IfIndex != 3 {
		t.Errorf("ARP: %+v", d.ARP)
	}
	if len(d.Errors) != 0 {
		t.Errorf("errors: %v", d.Errors)
	}
}

func TestSNMPFallbacks(t *testing.T) {
	// GETBULK broken: GETNEXT is used instead; plain BRIDGE-MIB table.
	old := newAgent().str(oidSysDescr, "Old Switch").str(oidSysName, "old").
		num(oidFdbPort+".0.0.94.0.83.40", 2).num(oidFdbStatus+".0.0.94.0.83.40", 3).
		num(oidFdbPort+".0.0.94.0.83.41", 2).num(oidFdbStatus+".0.0.94.0.83.41", 4)
	old.bulkFail = true
	// A printer answers with the Printer-MIB.
	printer := newAgent().str(oidSysDescr, "Example LaserPrinter").str(oidPrinterName+".1.1", "Tray 1")
	// Answers, but without a system group.
	empty := newAgent().num(oidIPForwarding, 1)
	// Walks fail completely.
	broken := newAgent().str(oidSysDescr, "Broken")
	broken.bulkFail, broken.walkFail = true, true
	silent := newAgent()
	silent.getFail = true
	useAgents(t, map[string]*fakeAgent{"192.0.2.11": old, "192.0.2.12": printer, "192.0.2.13": empty, "192.0.2.14": broken, "192.0.2.15": silent})
	ctx := context.Background()

	if d := snmpWalkDevice(ctx, SNMPConfig{}, "192.0.2.11"); len(d.FDB) != 1 || d.FDB[0].MAC != "00:00:5e:00:53:28" || d.FDB[0].VLAN != 0 {
		t.Errorf("GETNEXT fallback / BRIDGE-MIB: %+v", d.FDB)
	}
	if d := snmpWalkDevice(ctx, SNMPConfig{}, "192.0.2.12"); !d.IsPrinter {
		t.Errorf("printer not recognised: %+v", d)
	}
	if d := snmpWalkDevice(ctx, SNMPConfig{}, "192.0.2.13"); !slices.Contains(d.Errors, "no system group") {
		t.Errorf("no system group: %+v", d.Errors)
	}
	if d := snmpWalkDevice(ctx, SNMPConfig{}, "192.0.2.14"); len(d.Errors) == 0 || !strings.HasPrefix(d.Errors[0], "walk ") {
		t.Errorf("walk errors not recorded: %+v", d.Errors)
	}
	if d := snmpWalkDevice(ctx, SNMPConfig{}, "192.0.2.15"); !slices.Contains(d.Errors, "no system group") {
		t.Errorf("silent agent: %+v", d.Errors)
	}
	if d := snmpWalkDevice(ctx, SNMPConfig{}, "192.0.2.99"); len(d.Errors) != 1 || !strings.HasPrefix(d.Errors[0], "connect:") {
		t.Errorf("unreachable: %+v", d.Errors)
	}
}

func TestSNMPCollect(t *testing.T) {
	noSys := newAgent() // answers nothing: not an SNMP device
	useAgents(t, map[string]*fakeAgent{"192.0.2.10": switchAgent(), "192.0.2.12": newAgent().str(oidSysObjectID, "x").str(oidSysDescr, "Example LaserPrinter"), "192.0.2.13": noSys})
	errs := &errSink{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	got := snmpCollect(context.Background(), SNMPConfig{Version: "2c", Community: "public", Concurrency: 2}, []string{"192.0.2.13", "192.0.2.12", "192.0.2.10", "192.0.2.99"}, errs, log)
	if len(got) != 2 || got[0].IP != "192.0.2.10" || got[1].IP != "192.0.2.12" {
		t.Fatalf("collected %+v", got)
	}
	if len(errs.errs) != 0 {
		t.Errorf("errors: %v", errs.errs)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := snmpCollect(ctx, SNMPConfig{Concurrency: 1}, []string{"192.0.2.10"}, errs, log); len(got) > 1 {
		t.Errorf("cancelled collect: %+v", got)
	}
}

func TestNewSNMPConfig(t *testing.T) {
	g := newSNMP(context.Background(), SNMPConfig{Version: "2c", Community: "c"}, "192.0.2.1", time.Second, 1)
	if g.Version != gosnmp.Version2c || g.Community != "c" || g.Target != "192.0.2.1" {
		t.Errorf("v2c: %+v", g)
	}
	for _, c := range []struct {
		cfg   SNMPConfig
		flags gosnmp.SnmpV3MsgFlags
		auth  gosnmp.SnmpV3AuthProtocol
		priv  gosnmp.SnmpV3PrivProtocol
	}{
		{SNMPConfig{Version: "3", User: "u"}, gosnmp.NoAuthNoPriv, 0, 0},
		{SNMPConfig{Version: "3", User: "u", AuthPass: "a", AuthProto: "sha256"}, gosnmp.AuthNoPriv, gosnmp.SHA256, 0},
		{SNMPConfig{Version: "3", User: "u", AuthPass: "a", AuthProto: "MD5", PrivPass: "p", PrivProto: "des"}, gosnmp.AuthPriv, gosnmp.MD5, gosnmp.DES},
		{SNMPConfig{Version: "3", User: "u", AuthPass: "a", AuthProto: "SHA512", PrivPass: "p", PrivProto: "AES256"}, gosnmp.AuthPriv, gosnmp.SHA512, gosnmp.AES256},
	} {
		g := newSNMP(context.Background(), c.cfg, "192.0.2.1", time.Second, 1)
		usm := g.SecurityParameters.(*gosnmp.UsmSecurityParameters)
		if g.Version != gosnmp.Version3 || g.MsgFlags != c.flags || (c.auth != 0 && usm.AuthenticationProtocol != c.auth) ||
			(c.priv != 0 && usm.PrivacyProtocol != c.priv) {
			t.Errorf("%+v: flags %v auth %v priv %v", c.cfg, g.MsgFlags, usm.AuthenticationProtocol, usm.PrivacyProtocol)
		}
	}
	for in, want := range map[string]gosnmp.SnmpV3AuthProtocol{"SHA224": gosnmp.SHA224, "SHA384": gosnmp.SHA384, "": gosnmp.SHA} {
		if got := authProto(in); got != want {
			t.Errorf("authProto(%q) = %v", in, got)
		}
	}
	for in, want := range map[string]gosnmp.SnmpV3PrivProtocol{"AES192": gosnmp.AES192, "": gosnmp.AES} {
		if got := privProto(in); got != want {
			t.Errorf("privProto(%q) = %v", in, got)
		}
	}
}

func TestPDUHelpers(t *testing.T) {
	if pduString(gosnmp.SnmpPDU{Value: "s"}) != "s" || pduString(gosnmp.SnmpPDU{}) != "" ||
		pduString(gosnmp.SnmpPDU{Value: 42}) != "42" || pduString(gosnmp.SnmpPDU{Value: []byte{0x01, 0xff}}) != "01ff" {
		t.Error("pduString")
	}
	if pduInt(gosnmp.SnmpPDU{}) != 0 || pduInt(gosnmp.SnmpPDU{Value: []byte{1}}) != 0 || pduInt(gosnmp.SnmpPDU{Value: uint(7)}) != 7 {
		t.Error("pduInt")
	}
	if string(pduBytes(gosnmp.SnmpPDU{Value: "ab"})) != "ab" || pduBytes(gosnmp.SnmpPDU{Value: 3}) != nil {
		t.Error("pduBytes")
	}
}
