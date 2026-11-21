// Package sniff listens passively for ARP and IPv6 neighbour discovery and
// turns each frame into a MAC/IP sighting.
//
// Parsing is portable and pure; the raw-socket listener is Linux-only and
// lives in the homelabmap-listen helper, the only process with CAP_NET_RAW.
package sniff

import (
	"encoding/binary"
	"net"
	"net/netip"
)

const (
	etherARP  = 0x0806
	etherIPv6 = 0x86dd
	etherHdr  = 14

	icmpv6     = 58
	ndpRS      = 133 // router solicitation
	ndpRA      = 134 // router advertisement
	ndpNS      = 135 // neighbour solicitation
	ndpNA      = 136 // neighbour advertisement
	ipv6Hdr    = 40
	icmpOffset = etherHdr + ipv6Hdr
)

// Sighting is a MAC heard using an IP address.
type Sighting struct {
	MAC string
	IP  netip.Addr
	Via string // "arp" | "ndp"
}

// Parse decodes an Ethernet frame. It reports false for anything that is
// not an ARP or NDP packet from a unicast MAC with a usable address.
func Parse(frame []byte) (Sighting, bool) {
	if len(frame) < etherHdr {
		return Sighting{}, false
	}
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case etherARP:
		return parseARP(frame)
	case etherIPv6:
		return parseNDP(frame)
	}
	return Sighting{}, false
}

// parseARP takes the sender of requests, replies and gratuitous ARPs.
// Probes (sender IP 0.0.0.0) are skipped: an announcement follows them.
func parseARP(f []byte) (Sighting, bool) {
	const arpLen = 28
	if len(f) < etherHdr+arpLen {
		return Sighting{}, false
	}
	a := f[etherHdr:]
	if binary.BigEndian.Uint16(a[0:2]) != 1 || binary.BigEndian.Uint16(a[2:4]) != 0x0800 || a[4] != 6 || a[5] != 4 {
		return Sighting{}, false // not Ethernet/IPv4
	}
	mac, ok := unicastMAC(a[8:14])
	if !ok {
		return Sighting{}, false
	}
	ip := netip.AddrFrom4([4]byte(a[14:18]))
	if !usable(ip) {
		return Sighting{}, false
	}
	return Sighting{MAC: mac, IP: ip, Via: "arp"}, true
}

// parseNDP attributes an address to the frame's source MAC: NDP is
// link-local only (hop limit 255), so the sender is on this segment.
// Duplicate address detection (source ::) announces the target address.
func parseNDP(f []byte) (Sighting, bool) {
	if len(f) < icmpOffset+4 || f[etherHdr]>>4 != 6 || f[etherHdr+6] != icmpv6 || f[etherHdr+7] != 255 {
		return Sighting{}, false
	}
	mac, ok := unicastMAC(f[6:12])
	if !ok {
		return Sighting{}, false
	}
	src := netip.AddrFrom16([16]byte(f[etherHdr+8 : etherHdr+24]))
	icmp := f[icmpOffset:]
	var ip netip.Addr
	switch icmp[0] {
	case ndpRS, ndpRA:
		ip = src
	case ndpNS:
		if src.IsUnspecified() {
			if len(icmp) < 24 {
				return Sighting{}, false
			}
			ip = netip.AddrFrom16([16]byte(icmp[8:24])) // DAD: the tentative address
		} else {
			ip = src
		}
	case ndpNA:
		if len(icmp) < 24 {
			return Sighting{}, false
		}
		ip = netip.AddrFrom16([16]byte(icmp[8:24])) // the advertised address
	default:
		return Sighting{}, false
	}
	if !usable(ip) {
		return Sighting{}, false
	}
	return Sighting{MAC: mac, IP: ip, Via: "ndp"}, true
}

func unicastMAC(b []byte) (string, bool) {
	if b[0]&0x01 != 0 {
		return "", false // multicast/broadcast
	}
	zero := true
	for _, x := range b {
		if x != 0 {
			zero = false
			break
		}
	}
	if zero {
		return "", false
	}
	return net.HardwareAddr(b).String(), true
}

func usable(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLoopback() &&
		!(ip.Is4() && ip.IsLinkLocalUnicast()) // 169.254/16: APIPA noise
}
