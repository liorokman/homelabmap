package obs

import (
	"testing"
	"time"
)

func TestMergeProbe(t *testing.T) {
	t0 := time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)
	base := &Result{
		JobID: 1, StartedAt: t0,
		Sweep: []SweepHost{
			{IP: "10.0.0.1", MAC: "00:00:00:00:00:01"},
			{IP: "10.0.0.5", MAC: "00:00:00:00:00:05"}, // DHCP gave .5 to the new device since
			{IP: "10.0.0.7", MAC: "00:00:00:00:00:99"}, // the new device's old address
		},
		OSScans: []OSScan{{MAC: "00:00:00:00:00:01", Name: "old"}},
		DNS:     map[string]string{"10.0.0.1": "gw"},
		UniFi:   UniFiList{{Flavor: "legacy"}},
		SNMP:    []SNMPDevice{{IP: "10.0.0.1"}},
		Errors:  []string{"base"},
	}
	probe := &Result{
		JobID: 2, StartedAt: t0.Add(time.Minute), Probe: true,
		Sweep:   []SweepHost{{IP: "10.0.0.5", MAC: "00:00:00:00:00:99", Vendor: "Acme"}},
		OSScans: []OSScan{{MAC: "00:00:00:00:00:99", Name: "new"}},
		DNS:     map[string]string{"10.0.0.5": "phone"},
		Errors:  []string{"probe"},
	}
	m := MergeProbe(base, probe)
	if m.JobID != 2 || !m.Probe || !m.StartedAt.Equal(probe.StartedAt) {
		t.Errorf("header: %+v", m)
	}
	if len(m.Sweep) != 2 || m.Sweep[0].MAC != "00:00:00:00:00:01" || m.Sweep[1].Vendor != "Acme" {
		t.Errorf("sweep: %+v", m.Sweep)
	}
	if len(m.OSScans) != 2 || m.DNS["10.0.0.1"] != "gw" || m.DNS["10.0.0.5"] != "phone" {
		t.Errorf("os/dns: %+v %+v", m.OSScans, m.DNS)
	}
	if len(m.UniFi) != 1 || len(m.SNMP) != 1 || len(m.Errors) != 2 {
		t.Errorf("kept base collectors: %+v", m)
	}
	if len(base.Sweep) != 3 || len(base.DNS) != 1 || len(base.Errors) != 1 {
		t.Errorf("base was modified: %+v", base)
	}
	if got := MergeProbe(nil, probe); got.JobID != 2 || len(got.Sweep) != 1 {
		t.Errorf("no base: %+v", got)
	}
}
