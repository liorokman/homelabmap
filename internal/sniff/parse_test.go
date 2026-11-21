package sniff

import (
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
)

func frame(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(h), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const (
	ethBcastARP = "ffffffffffff 3c7c3f000001 0806"
	arpHdr      = "0001 0800 06 04"
)

func TestParseARP(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		want string // "mac ip" or "" for no sighting
	}{
		{"request", ethBcastARP + arpHdr + "0001 3c7c3f000001 0a1417d2 000000000000 0a141701", "3c:7c:3f:00:00:01 10.20.23.210"},
		{"reply", "3c7c3f000002 b827eb000003 0806" + arpHdr + "0002 b827eb000003 0a1414c3 3c7c3f000002 0a1417d2", "b8:27:eb:00:00:03 10.20.20.195"},
		{"probe skipped", ethBcastARP + arpHdr + "0001 3c7c3f000001 00000000 000000000000 0a1417d2", ""},
		{"apipa skipped", ethBcastARP + arpHdr + "0001 3c7c3f000001 a9fe0101 000000000000 a9fe0102", ""},
		{"multicast sender skipped", ethBcastARP + arpHdr + "0001 01005e000001 0a1417d2 000000000000 0a141701", ""},
		{"truncated", ethBcastARP + arpHdr + "0001 3c7c3f", ""},
		{"not ipv4", ethBcastARP + "0001 86dd 06 10" + "0001 3c7c3f000001 0a1417d2 000000000000 0a141701", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, ok := Parse(frame(t, c.hex))
			got := ""
			if ok {
				got = s.MAC + " " + s.IP.String()
				if s.Via != "arp" {
					t.Errorf("via = %q", s.Via)
				}
			}
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// ndp builds an Ethernet+IPv6+ICMPv6 frame.
func ndp(srcMAC, srcIP string, hop string, icmp string) string {
	return "333300000001" + srcMAC + "86dd" +
		"60000000 0020 3a" + hop + srcIP + "ff020000000000000000000000000001" + icmp
}

const (
	llAddr     = "fe800000000000003e7c3ffffe000001"
	globalAddr = "20010db8000000003e7c3ffffe000001"
	zeroAddr   = "00000000000000000000000000000000"
)

func TestParseNDP(t *testing.T) {
	mac := "3c7c3f000001"
	cases := []struct {
		name string
		hex  string
		want string
	}{
		{"neighbour solicitation", ndp(mac, llAddr, "ff", "87 00 0000 00000000"+globalAddr), "3c:7c:3f:00:00:01 fe80::3e7c:3fff:fe00:1"},
		{"DAD uses target", ndp(mac, zeroAddr, "ff", "87 00 0000 00000000"+globalAddr), "3c:7c:3f:00:00:01 2001:db8::3e7c:3fff:fe00:1"},
		{"advertisement uses target", ndp(mac, llAddr, "ff", "88 00 0000 20000000"+globalAddr), "3c:7c:3f:00:00:01 2001:db8::3e7c:3fff:fe00:1"},
		{"router solicitation", ndp(mac, llAddr, "ff", "85 00 0000 00000000"), "3c:7c:3f:00:00:01 fe80::3e7c:3fff:fe00:1"},
		{"hop limit not 255", ndp(mac, llAddr, "40", "87 00 0000 00000000"+globalAddr), ""},
		{"echo request ignored", ndp(mac, llAddr, "ff", "80 00 0000 00000000"), ""},
		{"DAD truncated", ndp(mac, zeroAddr, "ff", "87 00 0000 00000000"), ""},
		{"router solicitation from ::", ndp(mac, zeroAddr, "ff", "85 00 0000 00000000"), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, ok := Parse(frame(t, c.hex))
			got := ""
			if ok {
				got = s.MAC + " " + s.IP.String()
			}
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestParseOther(t *testing.T) {
	for _, h := range []string{"", "ffff", "ffffffffffff 3c7c3f000001 0800 4500"} {
		if _, ok := Parse(frame(t, h)); ok {
			t.Errorf("%q parsed", h)
		}
	}
}

func TestDeduper(t *testing.T) {
	d := NewDeduper(2)
	s := Sighting{MAC: "3c:7c:3f:00:00:01", IP: netip.MustParseAddr("10.20.23.210"), Via: "arp"}
	if !d.Fresh(s, 0) || d.Fresh(s, 1) {
		t.Fatal("second sighting within the window must be suppressed")
	}
	if !d.Fresh(s, 2) {
		t.Fatal("sighting after the window must pass")
	}
	other := s
	other.IP = netip.MustParseAddr("10.20.23.53")
	if !d.Fresh(other, 2) {
		t.Fatal("a new IP for the same MAC must pass")
	}
}
