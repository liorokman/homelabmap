package scanner

import (
	"encoding/xml"
	"slices"
	"testing"
	"time"
)

func TestDecodeMgmtAddr(t *testing.T) {
	tests := []struct {
		name  string
		parts []string
		want  string
	}{
		{"ipv4", []string{"1", "4", "10", "20", "20", "195"}, "10.20.20.195"},
		// Seen on a Cisco small-business switch: length 3, last octet missing.
		{"core-sb truncated", []string{"1", "3", "10", "20", "23"}, "invalid:1.3.10.20.23"},
		{"length says 4, three bytes", []string{"1", "4", "10", "20", "23"}, "invalid:1.4.10.20.23"},
		{"ipv6", []string{"2", "16", "254", "128", "0", "0", "0", "0", "0", "0", "186", "196", "156", "255", "254", "176", "71", "115"}, "fe80::bac4:9cff:feb0:4773"},
		{"octet out of range", []string{"1", "4", "300", "1", "1", "1"}, "invalid:1.4.300.1.1.1"},
		{"too short", []string{"1"}, "invalid:1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeMgmtAddr(tt.parts); got != tt.want {
				t.Errorf("decodeMgmtAddr(%v) = %q, want %q", tt.parts, got, tt.want)
			}
		})
	}
}

func TestDecodeLLDPCaps(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want []string
	}{
		{"core bridge", []byte{0x20}, []string{"bridge"}},
		{"routeros bridge+router", []byte{0x28}, []string{"bridge", "router"}},
		// UniFi USW-24 sends two octets with the real one second.
		{"unifi-sw shifted", []byte{0x00, 0x30}, []string{"bridge", "wlan-ap"}},
		{"station", []byte{0x01}, []string{"station"}},
		{"empty", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeLLDPCaps(tt.in); !slices.Equal(got, tt.want) {
				t.Errorf("decodeLLDPCaps(% x) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestFormatLLDPID(t *testing.T) {
	mac := []byte{0x04, 0x31, 0x23, 0x7f, 0xf1, 0x22}
	tests := []struct {
		name    string
		subtype int
		b       []byte
		chassis bool
		want    string
	}{
		{"chassis mac", 4, mac, true, "04:31:23:7f:f1:22"},
		{"chassis network address", 5, []byte{1, 10, 20, 20, 1}, true, "10.20.20.1"},
		{"port local name", 7, []byte("gi19"), false, "gi19"},
		{"port mac", 3, mac, false, "04:31:23:7f:f1:22"},
		{"port ifname", 5, []byte("sfp-sfpplus2"), false, "sfp-sfpplus2"},
		{"unknown subtype, raw mac bytes", 7, mac, false, "04:31:23:7f:f1:22"},
		{"unprintable, not a mac", 7, []byte{0x01, 0x02, 0x03}, false, "010203"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatLLDPID(tt.subtype, tt.b, tt.chassis); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseQFdbIndex(t *testing.T) {
	tests := []struct {
		name     string
		idx      string
		wantVLAN int
		wantMAC  string
		wantOK   bool
	}{
		{"standard", "0.164.39.34.163.0.41", 0, "a4:27:22:a3:00:29", true},
		// Some Cisco small-business switches insert a length octet before the MAC.
		{"core-sb length octet", "1.6.184.196.156.176.71.115", 1, "b8:c4:9c:b0:47:73", true},
		{"too short", "1.2.3", 0, "", false},
		{"broadcast mac rejected", "1.255.255.255.255.255.255", 0, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vlan, mac, ok := parseQFdbIndex(tt.idx)
			if ok != tt.wantOK || (ok && (vlan != tt.wantVLAN || mac != tt.wantMAC)) {
				t.Errorf("parseQFdbIndex(%q) = %d, %q, %v; want %d, %q, %v", tt.idx, vlan, mac, ok, tt.wantVLAN, tt.wantMAC, tt.wantOK)
			}
		})
	}
}

func TestPrintable(t *testing.T) {
	if s, ok := printable([]byte("USW24PoE\x00\x00")); !ok || s != "USW24PoE" {
		t.Errorf("trailing NULs: got %q, %v", s, ok)
	}
	if _, ok := printable([]byte{0x04, 0x31, 0x23}); ok {
		t.Error("binary bytes reported as printable")
	}
}

const sweepXML = `<?xml version="1.0"?>
<nmaprun>
 <host><status state="up"/><address addr="10.20.20.1" addrtype="ipv4"/><address addr="B8:C4:9C:B0:47:A5" addrtype="mac" vendor="Routerboard.com"/></host>
 <host><status state="up"/><address addr="10.20.23.80" addrtype="ipv4"/></host>
 <host><status state="down"/><address addr="10.20.20.15" addrtype="ipv4"/></host>
</nmaprun>`

func TestParseSweep(t *testing.T) {
	var run nmapRun
	if err := xml.Unmarshal([]byte(sweepXML), &run); err != nil {
		t.Fatal(err)
	}
	got := parseSweep(&run)
	if len(got) != 2 {
		t.Fatalf("want 2 live hosts, got %d: %+v", len(got), got)
	}
	if got[0].MAC != "b8:c4:9c:b0:47:a5" || got[0].Vendor != "Routerboard.com" {
		t.Errorf("router: %+v", got[0])
	}
	if got[1].IP != "10.20.23.80" || got[1].MAC != "" {
		t.Errorf("scanner host (no MAC): %+v", got[1])
	}
}

const osXML = `<?xml version="1.0"?>
<nmaprun>
 <host><status state="up"/><address addr="10.20.22.66" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="135"><state state="open"/><service name="msrpc"/></port>
   <port protocol="tcp" portid="22"><state state="closed"/></port>
  </ports>
  <os>
   <osmatch name="Microsoft Windows 10 1709 - 21H2" accuracy="97">
    <osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="10" accuracy="97"/>
   </osmatch>
   <osmatch name="Microsoft Windows 11" accuracy="90"/>
  </os>
 </host>
 <host><status state="up"/><address addr="10.20.22.163" addrtype="ipv4"/></host>
 <host><status state="up"/><address addr="10.20.22.109" addrtype="ipv4"/></host>
</nmaprun>`

func TestParseOSScan(t *testing.T) {
	var run nmapRun
	if err := xml.Unmarshal([]byte(osXML), &run); err != nil {
		t.Fatal(err)
	}
	byIP := map[string]string{"10.20.22.66": "00:11:22:33:44:20", "10.20.22.163": "00:11:22:33:44:21"}
	now := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	got := parseOSScan(&run, byIP, now)
	if len(got) != 2 {
		t.Fatalf("want 2 results (unrequested host skipped), got %d", len(got))
	}
	w := got[0]
	if !w.Matched || w.Name != "Microsoft Windows 10 1709 - 21H2" || w.Accuracy != 97 || w.Family != "Windows" || w.Type != "general purpose" {
		t.Errorf("best match not taken: %+v", w)
	}
	if !slices.Equal(w.OpenPorts, []string{"135/tcp msrpc"}) {
		t.Errorf("open ports: %v", w.OpenPorts)
	}
	if got[1].Matched || got[1].MAC != "00:11:22:33:44:21" || !got[1].ScannedAt.Equal(now) {
		t.Errorf("unmatched host should still be recorded: %+v", got[1])
	}
}
