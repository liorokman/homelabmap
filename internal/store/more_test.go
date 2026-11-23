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

func TestLocalUsers(t *testing.T) {
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "u.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if ok, err := s.HasLocalUser(ctx); ok || err != nil {
		t.Fatalf("empty: %v %v", ok, err)
	}
	if _, err := s.GetLocalUser(ctx, "admin"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing user: %v", err)
	}
	now := time.Unix(1_900_000_000, 0).UTC()
	if err := s.CreateFirstLocalUser(ctx, LocalUser{Username: "Admin", PasswordHash: "$argon2id$x", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateFirstLocalUser(ctx, LocalUser{Username: "other", PasswordHash: "h", CreatedAt: now}); !errors.Is(err, ErrUserExists) {
		t.Errorf("second account: %v", err)
	}
	u, err := s.GetLocalUser(ctx, "admin")
	if err != nil || u.Username != "Admin" || u.PasswordHash != "$argon2id$x" || !u.CreatedAt.Equal(now) {
		t.Errorf("lookup ignoring case: %+v %v", u, err)
	}
	if ok, _ := s.HasLocalUser(ctx); !ok {
		t.Error("account not reported")
	}
}

func TestSetPasswordAndOtherSessions(t *testing.T) {
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now()
	if err := s.SetLocalPassword(ctx, "admin", "h"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing account: %v", err)
	}
	_ = s.CreateFirstLocalUser(ctx, LocalUser{Username: "admin", PasswordHash: "old", CreatedAt: now})
	if err := s.SetLocalPassword(ctx, "ADMIN", "new"); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.GetLocalUser(ctx, "admin"); u.PasswordHash != "new" {
		t.Errorf("hash not replaced: %q", u.PasswordHash)
	}
	for _, id := range []string{"a", "b", "c"} {
		_ = s.CreateSession(ctx, id, Session{Subject: "local:admin", ExpiresAt: now.Add(time.Hour)}, now)
	}
	_ = s.CreateSession(ctx, "d", Session{Subject: "someone-else", ExpiresAt: now.Add(time.Hour)}, now)
	if n, err := s.DeleteOtherSessions(ctx, "local:admin", "b"); n != 2 || err != nil {
		t.Errorf("ended %d sessions: %v", n, err)
	}
	for id, want := range map[string]bool{"a": false, "b": true, "c": false, "d": true} {
		if _, err := s.GetSession(ctx, id, now); (err == nil) != want {
			t.Errorf("session %s kept=%v", id, err == nil)
		}
	}
}

func TestPasswordResets(t *testing.T) {
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Unix(1_900_000_000, 0).UTC()
	if _, err := s.OnlyLocalUser(ctx); !errors.Is(err, ErrNotFound) {
		t.Errorf("no account: %v", err)
	}
	_ = s.CreateFirstLocalUser(ctx, LocalUser{Username: "admin", PasswordHash: "h", CreatedAt: now})
	if u, err := s.OnlyLocalUser(ctx); err != nil || u.Username != "admin" {
		t.Errorf("only account: %+v %v", u, err)
	}
	if err := s.TakePasswordReset(ctx, "x", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("no code: %v", err)
	}
	_ = s.SetPasswordReset(ctx, "one", now.Add(time.Minute))
	_ = s.SetPasswordReset(ctx, "two", now.Add(time.Minute))
	if err := s.TakePasswordReset(ctx, "one", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("replaced code: %v", err)
	}
	if err := s.TakePasswordReset(ctx, "two", now.Add(time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired code: %v", err)
	}
	_ = s.SetPasswordReset(ctx, "three", now.Add(time.Minute))
	if err := s.TakePasswordReset(ctx, "three", now); err != nil {
		t.Errorf("live code: %v", err)
	}
	if err := s.TakePasswordReset(ctx, "three", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("reused code: %v", err)
	}
}
