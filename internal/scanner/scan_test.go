package scanner

import (
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
