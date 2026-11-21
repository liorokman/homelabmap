package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
	"github.com/liorokman/homelabmap/internal/topo"
)

func TestFailPruneAndLookups(t *testing.T) {
	ctx := context.Background()
	s := open(t)

	if _, err := s.LatestResult(ctx); !errors.Is(err, ErrNotFound) {
		t.Errorf("latest result on empty store: %v", err)
	}
	if last, err := s.LastRequested(ctx); err != nil || !last.IsZero() {
		t.Errorf("last requested on empty store: %v %v", last, err)
	}
	if _, err := s.Graph(ctx, 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("graph of missing scan: %v", err)
	}
	if _, err := s.Result(ctx, 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("result of missing scan: %v", err)
	}

	// An old failed scan and an old done scan, then a newer done scan.
	old, _, _ := s.Enqueue(ctx, "schedule", t0)
	s.Claim(ctx, t0)
	if err := s.Fail(ctx, old.ID, "scanner found no hosts", t0); err != nil {
		t.Fatal(err)
	}
	if sc, _ := s.Get(ctx, old.ID); sc.Status != StatusFailed || sc.Error != "scanner found no hosts" {
		t.Errorf("failed scan: %+v", sc)
	}
	g := &topo.Graph{Version: topo.Version, Nodes: []topo.Node{{ID: "n-1", MACs: []string{"00:00:5e:00:53:01"}}}}
	done1, _, _ := s.Enqueue(ctx, "schedule", t0.Add(time.Hour))
	s.Claim(ctx, t0.Add(time.Hour))
	res := &obs.Result{JobID: done1.ID, StartedAt: t0.Add(time.Hour),
		OSScans: []obs.OSScan{{MAC: "00:00:5e:00:53:01", ScannedAt: t0.Add(time.Hour), Name: "Linux"}}}
	if err := s.Complete(ctx, done1.ID, res, g, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, err := s.Graph(ctx, done1.ID)
	if err != nil || len(got.Nodes) != 1 {
		t.Fatalf("graph: %+v %v", got, err)
	}
	times, err := s.OSScanTimes(ctx)
	if err != nil || !times["00:00:5e:00:53:01"].Equal(t0.Add(time.Hour)) {
		t.Errorf("os scan times: %v %v", times, err)
	}
	r, err := s.LatestResult(ctx)
	if err != nil || len(r.OSScans) != 1 {
		t.Errorf("latest result: %+v %v", r, err)
	}

	// Sessions and sightings expire; the newest good scan always stays.
	if err := s.CreateSession(ctx, "h", Session{Subject: "s", ExpiresAt: t0.Add(time.Minute)}, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordSightings(ctx, []obs.Sighting{{MAC: "00:00:5e:00:53:09", IP: "192.0.2.9", Via: "arp", At: t0}}, t0); err != nil {
		t.Fatal(err)
	}
	later := t0.Add(30 * 24 * time.Hour)
	if err := s.Prune(ctx, later.Add(-time.Hour), later); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, old.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("old failed scan kept: %v", err)
	}
	if _, err := s.Get(ctx, done1.ID); err != nil {
		t.Errorf("newest good scan pruned: %v", err)
	}
	if _, err := s.GetSession(ctx, "h", later); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired session kept: %v", err)
	}
	if rows, _ := s.Sightings(ctx, 10); len(rows) != 0 {
		t.Errorf("old sightings kept: %+v", rows)
	}

	// Stale graphs are found and replaced.
	stale, err := s.StaleGraphs(ctx, topo.Version+1, 5)
	if err != nil || len(stale) != 1 || stale[0] != done1.ID {
		t.Fatalf("stale graphs: %v %v", stale, err)
	}
	g.Version = topo.Version + 1
	if err := s.UpdateGraph(ctx, done1.ID, g); err != nil {
		t.Fatal(err)
	}
	if stale, _ := s.StaleGraphs(ctx, topo.Version+1, 5); len(stale) != 0 {
		t.Errorf("still stale: %v", stale)
	}
}

func TestOpenRejectsBadPath(t *testing.T) {
	if _, err := Open(context.Background(), filepath.Join(t.TempDir(), "missing-dir", "x.db")); err == nil {
		t.Error("database in a missing directory accepted")
	}
}

func TestMergeTargets(t *testing.T) {
	got := mergeTargets(
		[]obs.ProbeTarget{{MAC: "a", IPs: []string{"192.0.2.1"}}},
		[]obs.ProbeTarget{{MAC: "a", IPs: []string{"192.0.2.1", "192.0.2.2"}}, {MAC: "b", IPs: []string{"192.0.2.3"}}})
	if len(got) != 2 || len(got[0].IPs) != 2 || got[1].MAC != "b" {
		t.Errorf("merged %+v", got)
	}
}
