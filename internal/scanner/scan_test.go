package scanner

import (
	"context"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

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
	cleanEnv(t)
	t.Setenv("HOMELABMAP_AGENT_TOKEN", "tok")
	t.Setenv("HOMELABMAP_NMAP_PRIVILEGED", "true")
	c, err := LoadConfig()
	if err != nil || c.AgentToken != "tok" || !c.NmapPrivileged || c.Server != "http://127.0.0.1:8097" || c.NmapPath != "nmap" {
		t.Fatalf("bootstrap config: %+v %v", c, err)
	}
	t.Setenv("HOMELABMAP_NMAP_PRIVILEGED", "maybe")
	if _, err := LoadConfig(); err == nil {
		t.Error("bad bool accepted")
	}
}

func TestLegacySettings(t *testing.T) {
	cleanEnv(t)
	t.Run("nothing set", func(t *testing.T) {
		l, err := LegacySettings()
		if err != nil || len(l.Set) != 0 || l.Settings.SNMP.Default != nil || !l.Settings.Passive || l.Settings.SNMP.TimeoutMS != 1500 {
			t.Errorf("defaults: %+v %v", l, err)
		}
	})
	t.Run("old environment", func(t *testing.T) {
		for k, v := range map[string]string{
			"HOMELABMAP_SUBNETS": "192.0.2.0/24, 198.51.100.7/24", "HOMELABMAP_SNMP_COMMUNITY": "x",
			"HOMELABMAP_UNIFI_URL": "https://unifi.example/", "HOMELABMAP_UNIFI_API_KEY": "k",
			"HOMELABMAP_PVE_URL": "https://pve.example:8006", "HOMELABMAP_PVE_TOKEN_ID": "u@pve!t", "HOMELABMAP_PVE_TOKEN_SECRET": "s",
			"HOMELABMAP_COSMOS_URL": "https://cosmos.example", "HOMELABMAP_COSMOS_TOKEN": "t", "HOMELABMAP_SSDP": "false",
		} {
			t.Setenv(k, v)
		}
		l, err := LegacySettings()
		s := l.Settings
		if err != nil || len(l.Set) != 10 || len(s.Subnets) != 2 || s.SNMP.Default == nil || s.SNMP.Default.Community != "x" ||
			len(s.UniFi) != 1 || s.UniFi[0].URL != "https://unifi.example" || s.UniFi[0].Site != "default" || s.UniFi[0].HistoryHours != 720 ||
			len(s.Proxmox) != 1 || len(s.Cosmos) != 1 || s.SSDP {
			t.Fatalf("legacy: %+v %v", l, err)
		}
		c, err := Config{}.WithSettings(s)
		if err != nil || len(c.Subnets) != 2 || c.Subnets[1].String() != "198.51.100.0/24" || c.SNMP.Timeout != 1500*time.Millisecond {
			t.Errorf("applied: %+v %v", c, err)
		}
	})
	t.Run("errors are reported", func(t *testing.T) {
		t.Setenv("HOMELABMAP_OS_SCAN_MAX", "lots")
		t.Setenv("HOMELABMAP_SNMP_VERSION", "3") // without a user: no default credentials
		l, err := LegacySettings()
		if err == nil || !strings.Contains(err.Error(), "HOMELABMAP_OS_SCAN_MAX") || l.Settings.SNMP.Default != nil {
			t.Errorf("got %+v %v", l.Settings.SNMP, err)
		}
	})
}

func TestSNMPCredentialChoice(t *testing.T) {
	c, err := Config{}.WithSettings(obs.ScannerSettings{
		Subnets: []string{"192.0.2.0/24", "bad"},
		SNMP: obs.SNMPSettings{
			Default: &obs.SNMPCredentials{Version: "2c", Community: "public"},
			Hosts: []obs.SNMPHost{
				{Match: "192.0.2.0/25", Credentials: obs.SNMPCredentials{Version: "2c", Community: "lower-half"}},
				{Match: "192.0.2.0/27", Credentials: obs.SNMPCredentials{Version: "3", User: "admin", AuthPass: "a"}},
				{Match: "192.0.2.10", Credentials: obs.SNMPCredentials{Version: "2c", Community: "switch"}},
				{Match: "192.0.2.200/32", Credentials: obs.SNMPCredentials{Version: "3"}}, // no user: unusable
				{Match: "localhost", Credentials: obs.SNMPCredentials{Version: "2c", Community: "named"}},
			},
		},
	})
	if err == nil || len(c.Subnets) != 1 {
		t.Fatalf("bad subnet should be reported and skipped: %v %v", c.Subnets, err)
	}
	if err := c.SNMP.resolveHosts(context.Background()); err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]string{
		"192.0.2.10": "switch", "192.0.2.20": "3/admin", "192.0.2.100": "lower-half", "192.0.2.150": "public", "127.0.0.1": "named",
	} {
		got, ok := c.SNMP.forIP(ip)
		desc := got.Community
		if got.Version == "3" {
			desc = "3/" + got.User
		}
		if !ok || desc != want {
			t.Errorf("%s: got %q (ok=%v), want %q", ip, desc, ok, want)
		}
	}
	if _, ok := c.SNMP.forIP("192.0.2.200"); ok {
		t.Error("unusable override should not fall back to the default")
	}
	none, _ := Config{}.WithSettings(obs.ScannerSettings{})
	if _, ok := none.SNMP.forIP("192.0.2.1"); ok {
		t.Error("no default, no override: no SNMP")
	}
	ips := c.SNMP.overrideIPs()
	if !slices.Contains(ips, "192.0.2.10") || !slices.Contains(ips, "127.0.0.1") || slices.Contains(ips, "192.0.2.0") {
		t.Errorf("override targets: %v", ips)
	}
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
		{obs.Sighting{MAC: "3c:7c:3f:00:00:01", IP: "10.1.2.3"}, false},    // other segment
		{obs.Sighting{MAC: "3c:7c:3f:00:00:01", IP: "fe80::1"}, true},      // IPv6 kept
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

// cleanEnv empties every HOMELABMAP_ variable for the test (restored after),
// so a developer's .env can't leak into config tests.
func cleanEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "HOMELABMAP_") {
			t.Setenv(k, "")
		}
	}
}
