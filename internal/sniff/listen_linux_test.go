//go:build linux

package sniff

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestListenErrors(t *testing.T) {
	if err := Listen(context.Background(), "no-such-iface0", func(Sighting) {}); err == nil {
		t.Error("unknown interface accepted")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: raw sockets are allowed (see TestListenLoopback)")
	}
	// Without CAP_NET_RAW the packet socket can't be opened.
	if err := Listen(context.Background(), "lo", func(Sighting) {}); err == nil {
		t.Error("unprivileged raw socket opened")
	}
}

func TestListenLoopback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs CAP_NET_RAW")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if err := Listen(ctx, "lo", func(Sighting) {}); err != nil {
		t.Errorf("listen on loopback: %v", err)
	}
}

func TestOpenPacketRanges(t *testing.T) {
	if _, err := openPacket(0, etherARP, nil, false); err == nil {
		t.Error("interface index 0 accepted")
	}
	if htons(0x0806) != 0x0608 {
		t.Error("htons")
	}
}

func TestDeduperBounded(t *testing.T) {
	d := NewDeduper(1)
	for i := range 50001 {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		d.Fresh(Sighting{MAC: "00:00:5e:00:53:01", IP: ip}, 0)
	}
	// Everything is outside the window at t=5: the map is pruned.
	d.Fresh(Sighting{MAC: "00:00:5e:00:53:02", IP: netip.MustParseAddr("192.0.2.1")}, 5)
	if len(d.last) > 2 {
		t.Errorf("deduper kept %d entries", len(d.last))
	}
}
