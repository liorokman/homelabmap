package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
	"github.com/liorokman/homelabmap/internal/store"
	"github.com/liorokman/homelabmap/internal/topo"
)

func TestRunServesAndStops(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Listen, c.AgentListen = "127.0.0.1:0", "127.0.0.1:0" })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.s.Run(ctx) }()
	// The scheduler's first pass queues a scan right away.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if a, err := h.st.Active(context.Background()); err == nil && a.Trigger == "schedule" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no scheduled scan")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestRunFailsOnBusyAddress(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Listen, c.AgentListen = "127.0.0.1:1", "256.0.0.1:0" })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := h.s.Run(ctx); err == nil {
		t.Error("Run with unusable addresses returned nil")
	}
}

func TestRebuildStaleGraphs(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	sc, _, _ := h.st.Enqueue(ctx, "schedule", time.Now())
	h.st.Claim(ctx, time.Now())
	res := &obs.Result{JobID: sc.ID, StartedAt: time.Now().UTC(), Subnets: []string{"192.0.2.0/24"},
		Sweep: []obs.SweepHost{{IP: "192.0.2.1", MAC: "00:00:5e:00:53:01"}}}
	old := &topo.Graph{Version: 0, Nodes: []topo.Node{{ID: "old"}}}
	if err := h.st.Complete(ctx, sc.ID, res, old, time.Now()); err != nil {
		t.Fatal(err)
	}
	h.s.rebuildStaleGraphs(ctx)
	g, err := h.st.Graph(ctx, sc.ID)
	if err != nil || g.Version != topo.Version || len(g.Nodes) != 1 || g.Nodes[0].ID == "old" {
		t.Errorf("rebuilt graph: %+v %v", g, err)
	}
}

func TestScansAPIAndErrors(t *testing.T) {
	h := newHarness(t, nil)
	h.login(t)
	var scans []store.Scan
	if err := json.NewDecoder(h.get(t, "/api/scans").Body).Decode(&scans); err != nil || len(scans) != 0 {
		t.Fatalf("empty scans: %+v %v", scans, err)
	}
	h.st.Enqueue(context.Background(), "manual", time.Now())
	if err := json.NewDecoder(h.get(t, "/api/scans").Body).Decode(&scans); err != nil || len(scans) != 1 {
		t.Errorf("scans: %+v %v", scans, err)
	}
	var g map[string]any
	if err := json.NewDecoder(h.get(t, "/api/graph").Body).Decode(&g); err != nil || g["nodes"] == nil {
		t.Errorf("empty graph: %v %v", g, err)
	}

	// A broken database is a generic 500: no details leak to the client.
	h.st.Close()
	resp := h.get(t, "/api/scans")
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusInternalServerError || strings.TrimSpace(string(body)) != "internal error" {
		t.Errorf("broken store: %d %q", resp.StatusCode, body)
	}
	for _, p := range []string{"/api/status", "/api/graph", "/api/sightings"} {
		if r := h.get(t, p); r.StatusCode != http.StatusInternalServerError {
			t.Errorf("%s with broken store: %d", p, r.StatusCode)
		}
	}
}

func TestLoginWithUnreachableIdP(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.OIDCIssuer = "http://127.0.0.1:1/nowhere" })
	h.s.auth.client = &http.Client{Timeout: time.Second}
	resp := h.get(t, "/auth/login?return=/")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("login with IdP down: %d", resp.StatusCode)
	}
}
