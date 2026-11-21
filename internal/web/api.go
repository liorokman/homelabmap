package web

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/liorokman/homelabmap/internal/store"
)

type statusResponse struct {
	User            *User       `json:"user"`
	Latest          *store.Scan `json:"latest"`
	Active          *store.Scan `json:"active"`
	NextScanAt      time.Time   `json:"nextScanAt"`
	IntervalSeconds int         `json:"intervalSeconds"`
	ScannerLastSeen *time.Time  `json:"scannerLastSeen"`
	ScannerOnline   bool        `json:"scannerOnline"`
	// LastSightingAt is when the passive listener last reported anything.
	LastSightingAt *time.Time `json:"lastSightingAt"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	resp := statusResponse{User: userFrom(ctx), IntervalSeconds: int(s.cfg.ScanInterval.Seconds())}
	var err error
	if resp.Latest, _, err = s.store.LatestGraph(ctx); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, "latest graph", err)
		return
	}
	if resp.Active, err = s.store.Active(ctx); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, "active scan", err)
		return
	}
	last, err := s.store.LastRequested(ctx)
	if err != nil {
		s.serverError(w, "last requested", err)
		return
	}
	resp.NextScanAt = last.Add(s.cfg.ScanInterval)
	if seen := s.scannerSeen.Load(); seen != 0 {
		t := time.Unix(seen, 0).UTC()
		resp.ScannerLastSeen = &t
		// The agent re-polls at least every long-poll period.
		resp.ScannerOnline = s.now().Sub(t) < 2*s.longPoll || resp.Active != nil && resp.Active.Status == store.StatusRunning
	}
	if t := s.lastSighting.Load(); t != 0 {
		at := time.Unix(t, 0).UTC()
		resp.LastSightingAt = &at
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSightings(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.Sightings(r.Context(), 5000)
	if err != nil {
		s.serverError(w, "sightings", err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// handleGraph returns the latest map. The graph JSON is stored ready-made.
func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	_, raw, err := s.store.LatestGraph(r.Context())
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]any{"nodes": []any{}, "edges": []any{}})
		return
	}
	if err != nil {
		s.serverError(w, "latest graph", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.store.Recent(r.Context(), 50)
	if err != nil {
		s.serverError(w, "recent scans", err)
		return
	}
	if scans == nil {
		scans = []store.Scan{}
	}
	writeJSON(w, http.StatusOK, scans)
}

// handleScanNow queues a scan. Cross-site requests are refused: the custom
// header forces a CORS preflight that the server never approves.
func (s *Server) handleScanNow(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) || r.Header.Get("X-Homelabmap-Request") != "1" {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	sc, created, err := s.store.Enqueue(r.Context(), "manual", s.now())
	if err != nil {
		s.serverError(w, "queueing scan", err)
		return
	}
	if created {
		u := userFrom(r.Context())
		s.log.Info("manual scan requested", "scan", sc.ID, "by", u.Name)
		s.notifyAgent()
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"scan": sc, "created": created})
}

// runScheduler queues a scan every interval, fails scans the scanner
// abandoned, and prunes old data.
func (s *Server) runScheduler(ctx context.Context) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	var lastPrune time.Time
	for {
		now := s.now()
		if n, err := s.store.FailStale(ctx, now.Add(-20*time.Minute), now); err != nil {
			s.log.Warn("failing stale scans", "err", err)
		} else if n > 0 {
			s.log.Warn("scanner did not report back; scan marked failed", "count", n)
		}
		last, err := s.store.LastRequested(ctx)
		if err != nil {
			s.log.Warn("scheduler", "err", err)
		} else if now.Sub(last) >= s.cfg.ScanInterval {
			if sc, created, err := s.store.Enqueue(ctx, "schedule", now); err != nil {
				s.log.Warn("scheduling scan", "err", err)
			} else if created {
				s.log.Info("scheduled scan queued", "scan", sc.ID)
				s.notifyAgent()
			}
		}
		if now.Sub(lastPrune) > time.Hour {
			if err := s.store.Prune(ctx, now.Add(-s.cfg.Retention), now); err != nil {
				s.log.Warn("pruning", "err", err)
			}
			lastPrune = now
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
