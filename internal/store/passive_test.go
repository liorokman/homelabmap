package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
	"github.com/liorokman/homelabmap/internal/topo"
)

func sight(mac, ip string, at time.Time) obs.Sighting {
	via := "arp"
	if len(ip) > 15 || ip[0] == 'f' {
		via = "ndp"
	}
	return obs.Sighting{MAC: mac, IP: ip, Via: via, At: at}
}

func TestRecordSightingsFindsNewMACs(t *testing.T) {
	ctx := context.Background()
	s := open(t)

	// A MAC already on a map is not new.
	sc, _, _ := s.Enqueue(ctx, "schedule", t0)
	if _, err := s.Claim(ctx, t0); err != nil {
		t.Fatal(err)
	}
	g := &topo.Graph{Version: topo.Version, Nodes: []topo.Node{{ID: "n-1", MACs: []string{"00:00:00:00:00:01"}}}}
	if err := s.Complete(ctx, sc.ID, &obs.Result{JobID: sc.ID, StartedAt: t0}, g, t0); err != nil {
		t.Fatal(err)
	}

	got, err := s.RecordSightings(ctx, []obs.Sighting{
		sight("00:00:00:00:00:01", "10.20.23.1", t0),
		sight("00:00:00:00:00:02", "10.20.23.98", t0),
		sight("00:00:00:00:00:02", "fe80::2", t0),
		sight("00:00:00:00:00:03", "fe80::3", t0), // IPv6 only: nothing to probe yet
	}, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].MAC != "00:00:00:00:00:02" || len(got[0].IPs) != 1 || got[0].IPs[0] != "10.20.23.98" {
		t.Fatalf("new devices: %+v", got)
	}

	// Once heard over ARP, the IPv6-only device becomes probeable.
	got, err = s.RecordSightings(ctx, []obs.Sighting{sight("00:00:00:00:00:03", "10.20.23.195", t0.Add(time.Minute))}, t0.Add(time.Minute))
	if err != nil || len(got) != 1 || got[0].MAC != "00:00:00:00:00:03" {
		t.Fatalf("after ARP: %+v %v", got, err)
	}

	rows, err := s.Sightings(ctx, 10)
	if err != nil || len(rows) != 5 || rows[0].MAC != "00:00:00:00:00:03" || rows[0].IP != "10.20.23.195" {
		t.Fatalf("sightings: %+v %v", rows, err)
	}

	h, err := s.History(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v6 := h.IPv6["00:00:00:00:00:02"]; len(v6) != 1 || v6[0] != "fe80::2" {
		t.Errorf("history IPv6: %v", h.IPv6)
	}
	if !h.LastSeen["00:00:00:00:00:03"].Equal(t0.Add(time.Minute)) {
		t.Errorf("history last seen: %v", h.LastSeen)
	}
}

func TestEnqueueProbe(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	tgt := func(mac, ip string) obs.ProbeTarget { return obs.ProbeTarget{MAC: mac, IPs: []string{ip}} }

	p, acc, err := s.EnqueueProbe(ctx, []obs.ProbeTarget{tgt("aa:00:00:00:00:01", "10.0.0.1")}, 3, t0)
	if err != nil || p == nil || p.Trigger != TriggerProbe || len(acc) != 1 {
		t.Fatalf("first probe: %+v %v %v", p, acc, err)
	}
	// While pending, more devices join the same probe; the budget caps them.
	p2, acc, err := s.EnqueueProbe(ctx, []obs.ProbeTarget{tgt("aa:00:00:00:00:02", "10.0.0.2"), tgt("aa:00:00:00:00:03", "10.0.0.3"), tgt("aa:00:00:00:00:04", "10.0.0.4")}, 3, t0)
	if err != nil || p2.ID != p.ID || len(acc) != 2 || len(p2.Targets) != 3 {
		t.Fatalf("joined probe: %+v %v %v", p2, acc, err)
	}
	if _, acc, _ := s.EnqueueProbe(ctx, []obs.ProbeTarget{tgt("aa:00:00:00:00:05", "10.0.0.5")}, 3, t0); len(acc) != 0 {
		t.Fatalf("over budget accepted %v", acc)
	}
	// Probed MACs are not new any more.
	if got, _ := s.RecordSightings(ctx, []obs.Sighting{sight("aa:00:00:00:00:01", "10.0.0.1", t0)}, t0); len(got) != 0 {
		t.Errorf("probed MAC reported new again: %+v", got)
	}

	// Probes neither block nor delay full scans.
	full, created, err := s.Enqueue(ctx, "schedule", t0)
	if err != nil || !created || full.ID == p.ID {
		t.Fatalf("full scan blocked by probe: %+v %v %v", full, created, err)
	}
	if a, err := s.Active(ctx); err != nil || a.ID != full.ID {
		t.Fatalf("active should be the full scan: %+v %v", a, err)
	}
	if last, _ := s.LastRequested(ctx); !last.Equal(t0) {
		t.Errorf("last requested: %v", last)
	}

	// The probe is claimed first (it is older) and carries its targets.
	c, err := s.Claim(ctx, t0)
	if err != nil || c.ID != p.ID || len(c.Targets) != 3 {
		t.Fatalf("claim probe: %+v %v", c, err)
	}

	// With a full scan pending, new devices wait for it instead.
	p3, acc, err := s.EnqueueProbe(ctx, []obs.ProbeTarget{tgt("aa:00:00:00:00:06", "10.0.0.6")}, 10, t0.Add(2*time.Hour))
	if err != nil || p3 != nil || len(acc) != 1 {
		t.Fatalf("with full scan pending: %+v %v %v", p3, acc, err)
	}

	got, err := s.Get(ctx, p.ID)
	if err != nil || got.Status != StatusRunning {
		t.Fatalf("get: %+v %v", got, err)
	}
	if _, err := s.Get(ctx, 999); !errors.Is(err, ErrNotFound) {
		t.Errorf("get missing: %v", err)
	}
}

func TestCompleteProbeOnlyTouchesProbedMACs(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	sc, _, _ := s.Enqueue(ctx, "schedule", t0)
	s.Claim(ctx, t0)
	g := &topo.Graph{Version: topo.Version, Nodes: []topo.Node{{ID: "a", MACs: []string{"00:00:00:00:00:0a"}}}}
	if err := s.Complete(ctx, sc.ID, &obs.Result{JobID: sc.ID, StartedAt: t0}, g, t0); err != nil {
		t.Fatal(err)
	}
	p, _, _ := s.EnqueueProbe(ctx, []obs.ProbeTarget{{MAC: "00:00:00:00:00:0b", IPs: []string{"10.0.0.11"}}}, 10, t0)
	s.Claim(ctx, t0)
	later := t0.Add(30 * time.Minute)
	g2 := &topo.Graph{Version: topo.Version, Nodes: []topo.Node{
		{ID: "a", MACs: []string{"00:00:00:00:00:0a"}}, {ID: "b", MACs: []string{"00:00:00:00:00:0b"}}}}
	if err := s.CompleteProbe(ctx, p.ID, &obs.Result{JobID: p.ID, StartedAt: later}, g2, []string{"00:00:00:00:00:0b"}, later); err != nil {
		t.Fatal(err)
	}
	h, _ := s.History(ctx)
	if !h.LastSeen["00:00:00:00:00:0a"].Equal(t0) || !h.LastSeen["00:00:00:00:00:0b"].Equal(later) {
		t.Errorf("last seen: %v", h.LastSeen)
	}
	if sc, _, err := s.LatestGraph(ctx); err != nil || sc.ID != p.ID {
		t.Errorf("latest graph should be the probe's: %+v %v", sc, err)
	}
	if r, err := s.LatestResult(ctx); err != nil || r.JobID != p.ID {
		t.Errorf("latest result: %+v %v", r, err)
	}
}
