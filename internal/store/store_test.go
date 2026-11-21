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

var t0 = time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "homelabmap.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestReopenKeepsSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "homelabmap.db")
	ctx := context.Background()
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Enqueue(ctx, "test", t0); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(ctx, path) // migrations must not re-run
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if a, err := s.Active(ctx); err != nil || a.Trigger != "test" {
		t.Fatalf("scan lost across reopen: %v %v", a, err)
	}
}

func TestScanLifecycle(t *testing.T) {
	ctx := context.Background()
	s := open(t)

	if _, err := s.Claim(ctx, t0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("claim on empty queue: %v", err)
	}
	sc, created, err := s.Enqueue(ctx, "schedule", t0)
	if err != nil || !created {
		t.Fatalf("enqueue: %v %v", created, err)
	}
	// A second request while one is pending joins it.
	again, created, err := s.Enqueue(ctx, "manual", t0)
	if err != nil || created || again.ID != sc.ID {
		t.Fatalf("duplicate enqueue: %+v %v %v", again, created, err)
	}

	claimed, err := s.Claim(ctx, t0.Add(time.Second))
	if err != nil || claimed.ID != sc.ID || claimed.Status != StatusRunning {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	if _, err := s.Claim(ctx, t0); !errors.Is(err, ErrNotFound) {
		t.Fatal("a running scan must not be claimed twice")
	}
	if _, created, _ := s.Enqueue(ctx, "manual", t0); created {
		t.Fatal("must not queue while a scan is running")
	}

	res := &obs.Result{JobID: sc.ID, StartedAt: t0, Subnets: []string{"10.0.0.0/24"},
		OSScans: []obs.OSScan{{MAC: "00:00:00:00:00:01", Matched: true, Name: "Linux", ScannedAt: t0}}}
	g := &topo.Graph{Version: topo.Version, Nodes: []topo.Node{{ID: "a", MACs: []string{"00:00:00:00:00:01"}}}}
	if err := s.Complete(ctx, sc.ID, res, g, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(ctx, sc.ID, res, g, t0); err == nil {
		t.Fatal("completing a finished scan must fail")
	}

	latest, gj, err := s.LatestGraph(ctx)
	if err != nil || latest.ID != sc.ID || latest.Nodes != 1 || len(gj) == 0 {
		t.Fatalf("latest graph: %+v %v", latest, err)
	}
	back, err := s.Result(ctx, sc.ID)
	if err != nil || back.JobID != sc.ID || len(back.OSScans) != 1 {
		t.Fatalf("result round trip: %+v %v", back, err)
	}
	h, err := s.History(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !h.FirstSeen["00:00:00:00:00:01"].Equal(t0) || h.OSScans["00:00:00:00:00:01"].Name != "Linux" || !h.Since.Equal(t0.Add(time.Second)) {
		t.Errorf("history: %+v", h)
	}
	known, _ := s.KnownMACs(ctx)
	if len(known) != 1 {
		t.Errorf("known macs: %v", known)
	}
}

func TestFirstSeenIsKept(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	g := &topo.Graph{Version: topo.Version, Nodes: []topo.Node{{ID: "a", MACs: []string{"00:00:00:00:00:01"}}}}
	for i, at := range []time.Time{t0, t0.Add(time.Hour)} {
		sc, _, _ := s.Enqueue(ctx, "schedule", at)
		if _, err := s.Claim(ctx, at); err != nil {
			t.Fatal(i, err)
		}
		if err := s.Complete(ctx, sc.ID, &obs.Result{StartedAt: at}, g, at); err != nil {
			t.Fatal(i, err)
		}
	}
	h, _ := s.History(ctx)
	if !h.FirstSeen["00:00:00:00:00:01"].Equal(t0) {
		t.Errorf("first_seen overwritten: %v", h.FirstSeen)
	}
}

func TestFailStaleAndPrune(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	g := &topo.Graph{Version: topo.Version}

	old, _, _ := s.Enqueue(ctx, "schedule", t0)
	s.Claim(ctx, t0)
	if err := s.Complete(ctx, old.ID, &obs.Result{StartedAt: t0}, g, t0); err != nil {
		t.Fatal(err)
	}
	stuck, _, _ := s.Enqueue(ctx, "schedule", t0.Add(time.Hour))
	s.Claim(ctx, t0.Add(time.Hour))
	n, err := s.FailStale(ctx, t0.Add(2*time.Hour), t0.Add(2*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("fail stale: %d %v", n, err)
	}
	recent, _ := s.Recent(ctx, 10)
	if len(recent) != 2 || recent[0].ID != stuck.ID || recent[0].Status != StatusFailed {
		t.Fatalf("recent: %+v", recent)
	}

	// Everything is older than the cutoff, but the newest good graph stays.
	if err := s.Prune(ctx, t0.Add(48*time.Hour), t0.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	recent, _ = s.Recent(ctx, 10)
	if len(recent) != 1 || recent[0].ID != old.ID {
		t.Fatalf("after prune: %+v", recent)
	}
}

func TestStaleGraphs(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	sc, _, _ := s.Enqueue(ctx, "schedule", t0)
	s.Claim(ctx, t0)
	if err := s.Complete(ctx, sc.ID, &obs.Result{StartedAt: t0}, &topo.Graph{Version: 0}, t0); err != nil {
		t.Fatal(err)
	}
	ids, err := s.StaleGraphs(ctx, topo.Version, 5)
	if err != nil || len(ids) != 1 {
		t.Fatalf("stale: %v %v", ids, err)
	}
	if err := s.UpdateGraph(ctx, sc.ID, &topo.Graph{Version: topo.Version}); err != nil {
		t.Fatal(err)
	}
	if ids, _ := s.StaleGraphs(ctx, topo.Version, 5); len(ids) != 0 {
		t.Fatalf("still stale: %v", ids)
	}
}

func TestSessionsAndLoginFlows(t *testing.T) {
	ctx := context.Background()
	s := open(t)

	if err := s.CreateSession(ctx, "h1", Session{Subject: "sub", Name: "Alex", ExpiresAt: t0.Add(time.Hour)}, t0); err != nil {
		t.Fatal(err)
	}
	if sess, err := s.GetSession(ctx, "h1", t0); err != nil || sess.Subject != "sub" {
		t.Fatalf("get: %+v %v", sess, err)
	}
	if _, err := s.GetSession(ctx, "h1", t0.Add(2*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired session returned")
	}
	if err := s.DeleteSession(ctx, "h1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "h1", t0); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted session returned")
	}

	f := LoginFlow{State: "st", Nonce: "no", Verifier: "ve", ReturnTo: "/", ExpiresAt: t0.Add(10 * time.Minute)}
	if err := s.CreateLoginFlow(ctx, "f1", f); err != nil {
		t.Fatal(err)
	}
	got, err := s.TakeLoginFlow(ctx, "f1", t0)
	if err != nil || got.State != "st" || got.Verifier != "ve" {
		t.Fatalf("take: %+v %v", got, err)
	}
	if _, err := s.TakeLoginFlow(ctx, "f1", t0); !errors.Is(err, ErrNotFound) {
		t.Fatal("login flow usable twice")
	}
	s.CreateLoginFlow(ctx, "f2", f)
	if _, err := s.TakeLoginFlow(ctx, "f2", t0.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired login flow accepted")
	}
}
