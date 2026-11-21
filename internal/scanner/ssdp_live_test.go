package scanner

import (
	"context"
	"net/netip"
	"os"
	"testing"
)

// TestLiveSSDP searches the real LAN. Opt-in:
// HOMELABMAP_LIVE_SSDP=10.20.20.0/22 go test ./internal/scanner -run LiveSSDP -v
func TestLiveSSDP(t *testing.T) {
	subnet := os.Getenv("HOMELABMAP_LIVE_SSDP")
	if subnet == "" {
		t.Skip("set HOMELABMAP_LIVE_SSDP to a subnet to search the real LAN")
	}
	cfg := Config{Subnets: []netip.Prefix{netip.MustParsePrefix(subnet)}}
	devs, err := ssdpDiscover(context.Background(), cfg, lanIface(cfg, selfInfo("")))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devs {
		t.Logf("%-15s %-40q %-25q %-25q %q types=%d server=%q", d.IP, d.FriendlyName, d.Manufacturer, d.ModelName, d.DeviceType, len(d.Types), d.Server)
	}
}
