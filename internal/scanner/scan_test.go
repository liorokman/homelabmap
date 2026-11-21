package scanner

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/liorokman/homelabmap/internal/obs"
)

func TestPVENICs(t *testing.T) {
	qemu := map[string]any{
		"net0":   "virtio=BC:24:11:AA:BB:01,bridge=vmbr0,firewall=1",
		"net1":   "e1000=BC:24:11:AA:BB:02,bridge=vmbr1",
		"ostype": "l26",
		"netx":   "virtio=BC:24:11:AA:BB:03", // not a netN key
	}
	got := pveNICs(qemu, "qemu")
	want := []obs.PVENIC{
		{Name: "net0", MAC: "bc:24:11:aa:bb:01", Bridge: "vmbr0"},
		{Name: "net1", MAC: "bc:24:11:aa:bb:02", Bridge: "vmbr1"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("qemu: got %+v, want %+v", got, want)
	}

	lxc := map[string]any{"net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:CC:DD:01,ip=dhcp,type=veth"}
	got = pveNICs(lxc, "lxc")
	want = []obs.PVENIC{{Name: "eth0", MAC: "bc:24:11:cc:dd:01", Bridge: "vmbr0"}}
	if !slices.Equal(got, want) {
		t.Errorf("lxc: got %+v, want %+v", got, want)
	}
}

func TestOSScanTargets(t *testing.T) {
	sweep := []obs.SweepHost{
		{IP: "10.0.0.1", MAC: "00:00:00:00:00:01"}, // known, fresh
		{IP: "10.0.0.2", MAC: "00:00:00:00:00:02"}, // known, stale -> requested
		{IP: "10.0.0.3", MAC: "00:00:00:00:00:03"}, // never seen
		{IP: "10.0.0.4"}, // no MAC: can't track the result
	}
	job := obs.Job{
		OSScanMACs: []string{"00:00:00:00:00:02"},
		KnownMACs:  []string{"00:00:00:00:00:01", "00:00:00:00:00:02"},
	}
	got := osScanTargets(job, sweep, 10)
	var ips []string
	for _, h := range got {
		ips = append(ips, h.IP)
	}
	if !slices.Equal(ips, []string{"10.0.0.2", "10.0.0.3"}) {
		t.Errorf("targets = %v", ips)
	}
	if n := len(osScanTargets(job, sweep, 1)); n != 1 {
		t.Errorf("cap not applied: %d", n)
	}
	job.OSScanMax = 1
	if n := len(osScanTargets(job, sweep, 10)); n != 1 {
		t.Errorf("job cap not applied: %d", n)
	}
	if n := len(osScanTargets(job, sweep, 0)); n != 0 {
		t.Errorf("disabled scan still returned %d targets", n)
	}
}

func TestLoadConfig(t *testing.T) {
	t.Run("minimal v2c", func(t *testing.T) {
		t.Setenv("HOMELABMAP_SUBNETS", "10.20.20.0/22, 10.1.0.7/24")
		t.Setenv("HOMELABMAP_SNMP_COMMUNITY", "x")
		c, err := LoadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if len(c.Subnets) != 2 || c.Subnets[1].String() != "10.1.0.0/24" {
			t.Errorf("subnets not parsed/masked: %v", c.Subnets)
		}
	})
	t.Run("errors are all reported", func(t *testing.T) {
		t.Setenv("HOMELABMAP_SUBNETS", "")
		t.Setenv("HOMELABMAP_SNMP_COMMUNITY", "")
		t.Setenv("HOMELABMAP_PVE_URL", "https://pve:8006")
		t.Setenv("HOMELABMAP_OS_SCAN_MAX", "lots")
		_, err := LoadConfig()
		if err == nil {
			t.Fatal("expected errors")
		}
		for _, want := range []string{"HOMELABMAP_SUBNETS", "HOMELABMAP_SNMP_COMMUNITY", "HOMELABMAP_PVE_URL", "HOMELABMAP_OS_SCAN_MAX"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error does not mention %s: %v", want, err)
			}
		}
	})
	t.Run("v3 needs a user", func(t *testing.T) {
		t.Setenv("HOMELABMAP_SUBNETS", "10.20.20.0/22")
		t.Setenv("HOMELABMAP_SNMP_VERSION", "3")
		if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "HOMELABMAP_SNMP_USER") {
			t.Errorf("got %v", err)
		}
	})
}

func TestIsVirtualIface(t *testing.T) {
	for name, want := range map[string]bool{"eno2": false, "eth0": false, "vmbr0": false, "docker0": true, "br-bb7432def970": true, "veth12ab": true, "wg0": true} {
		if got := isVirtualIface(name); got != want {
			t.Errorf("isVirtualIface(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestKeepSighting(t *testing.T) {
	cfg := Config{Subnets: []netip.Prefix{netip.MustParsePrefix("10.20.20.0/22")}}
	own := map[string]bool{"aa:bb:cc:00:00:01": true}
	cases := []struct {
		s    obs.Sighting
		want bool
	}{
		{obs.Sighting{MAC: "3C:7C:3F:00:00:01", IP: "10.20.23.210"}, true},
		{obs.Sighting{MAC: "aa:bb:cc:00:00:01", IP: "10.20.23.80"}, false}, // the scanner host
		{obs.Sighting{MAC: "3c:7c:3f:00:00:01", IP: "10.1.2.3"}, false},      // other segment
		{obs.Sighting{MAC: "3c:7c:3f:00:00:01", IP: "fe80::1"}, true},        // IPv6 kept
		{obs.Sighting{MAC: "01:00:5e:00:00:01", IP: "10.20.23.210"}, false},
		{obs.Sighting{MAC: "nonsense", IP: "10.20.23.210"}, false},
		{obs.Sighting{MAC: "3c:7c:3f:00:00:01", IP: "nonsense"}, false},
	}
	for _, c := range cases {
		if got := keepSighting(cfg, own, c.s); got != c.want {
			t.Errorf("%+v: got %v", c.s, got)
		}
	}
}

func TestReadSightings(t *testing.T) {
	in := `{"mac":"3c:7c:3f:00:00:01","ip":"10.20.23.210","via":"arp","at":"2026-11-21T08:00:00Z"}
garbage
{"mac":"","ip":"10.20.23.53"}
{"mac":"3c:7c:3f:00:00:02","ip":"fe80::1","via":"ndp","at":"2026-11-21T08:00:01Z"}
`
	var got []obs.Sighting
	readSightings(strings.NewReader(in), func(s obs.Sighting) { got = append(got, s) })
	if len(got) != 2 || got[0].Via != "arp" || got[1].IP != "fe80::1" {
		t.Errorf("got %+v", got)
	}
}

func TestProbeIPsAndLanIface(t *testing.T) {
	cfg := Config{Subnets: []netip.Prefix{netip.MustParsePrefix("10.20.20.0/22")}}
	got := probeIPs(cfg, []obs.ProbeTarget{
		{MAC: "a", IPs: []string{"10.20.23.90", "fe80::1", "10.0.0.1"}},
		{MAC: "b", IPs: []string{"10.20.23.247", "10.20.23.90"}},
	})
	if strings.Join(got, ",") != "10.20.23.247,10.20.23.90" {
		t.Errorf("probeIPs = %v", got)
	}
	self := obs.Self{Interfaces: []obs.SelfIface{
		{Name: "eth1", MAC: "aa:00:00:00:00:01", IPs: []string{"10.9.9.9"}},
		{Name: "eth0", MAC: "aa:00:00:00:00:02", IPs: []string{"10.20.23.80"}},
	}}
	if got := lanIface(cfg, self); got != "eth0" {
		t.Errorf("lanIface = %q", got)
	}
	if got := lanIface(cfg, obs.Self{}); got != "" {
		t.Errorf("lanIface without match = %q", got)
	}
}
