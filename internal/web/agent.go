package web

import (
	"compress/gzip"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
	"github.com/liorokman/homelabmap/internal/store"
	"github.com/liorokman/homelabmap/internal/topo"
)

const (
	maxResultGzip = 64 << 20
	maxResultJSON = 512 << 20
)

func (s *Server) requireAgent(next http.Handler) http.Handler {
	want := []byte("Bearer " + s.cfg.AgentToken)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.scannerSeen.Store(s.now().Unix())
		next.ServeHTTP(w, r)
	})
}

// handleAgentJob long-polls for a pending scan and hands it out.
func (s *Server) handleAgentJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	deadline := time.NewTimer(s.longPoll)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		sc, err := s.store.Claim(ctx, s.now())
		switch {
		case err == nil:
			job, err := s.buildJob(ctx, sc.ID)
			if err != nil {
				_ = s.store.Fail(ctx, sc.ID, "building job failed", s.now())
				s.serverError(w, "building job", err)
				return
			}
			s.log.Info("scan handed to scanner", "scan", sc.ID, "trigger", sc.Trigger, "os_targets", len(job.OSScanMACs))
			writeJSON(w, http.StatusOK, job)
			return
		case !errors.Is(err, store.ErrNotFound):
			s.serverError(w, "claiming scan", err)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			w.WriteHeader(http.StatusNoContent)
			return
		case <-s.wake:
		case <-tick.C:
		}
	}
}

// buildJob picks hosts whose OS is still a guess and that weren't
// fingerprinted recently.
func (s *Server) buildJob(ctx context.Context, id int64) (obs.Job, error) {
	job := obs.Job{ID: id, OSScanMax: s.cfg.OSScanMax}
	if s.cfg.OSScanMax == 0 {
		return job, nil
	}
	known, err := s.store.KnownMACs(ctx)
	if err != nil {
		return job, err
	}
	job.KnownMACs = known
	scanned, err := s.store.OSScanTimes(ctx)
	if err != nil {
		return job, err
	}
	_, raw, err := s.store.LatestGraph(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return job, nil
	}
	if err != nil {
		return job, err
	}
	var g topo.Graph
	if err := json.Unmarshal(raw, &g); err != nil {
		return job, err
	}
	cutoff := s.now().Add(-s.cfg.OSRescan)
	for _, n := range g.Nodes {
		if n.Infra || len(n.MACs) == 0 || !weakOS(n.OSSource) {
			continue
		}
		if t, ok := scanned[n.MACs[0]]; ok && t.After(cutoff) {
			continue
		}
		job.OSScanMACs = append(job.OSScanMACs, n.MACs[0])
		if len(job.OSScanMACs) >= s.cfg.OSScanMax {
			break
		}
	}
	return job, nil
}

// weakOS reports guesses that a fingerprint could improve on.
func weakOS(source string) bool {
	return source == "" || source == "name" || source == "vendor" || source == "mac" || strings.HasPrefix(source, "nmap")
}

func (s *Server) handleAgentResult(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var body io.Reader = http.MaxBytesReader(w, r.Body, maxResultGzip)
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(body)
		if err != nil {
			http.Error(w, "bad gzip", http.StatusBadRequest)
			return
		}
		defer zr.Close()
		body = io.LimitReader(zr, maxResultJSON)
	}
	var res obs.Result
	if err := json.NewDecoder(body).Decode(&res); err != nil {
		http.Error(w, "bad result: "+err.Error(), http.StatusBadRequest)
		return
	}
	active, err := s.store.Active(ctx)
	if err != nil || active.ID != res.JobID || active.Status != store.StatusRunning {
		http.Error(w, fmt.Sprintf("scan %d is not running", res.JobID), http.StatusConflict)
		return
	}

	// A scan that saw nothing at all would wipe the map; keep the last
	// good graph instead and surface why.
	if len(res.Sweep) == 0 && len(res.SNMP) == 0 {
		msg := "scanner found no hosts"
		if len(res.Errors) > 0 {
			msg += ": " + strings.Join(res.Errors, "; ")
		}
		_ = s.store.Fail(ctx, res.JobID, msg, s.now())
		s.log.Warn("scan failed", "scan", res.JobID, "reason", msg)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	hist, err := s.store.History(ctx)
	if err != nil {
		s.serverError(w, "loading history", err)
		return
	}
	g := topo.Build(res.JobID, &res, hist)
	if err := s.store.Complete(ctx, res.JobID, &res, g, s.now()); err != nil {
		s.serverError(w, "storing scan", err)
		return
	}
	s.log.Info("scan stored", "scan", res.JobID, "nodes", len(g.Nodes), "edges", len(g.Edges),
		"warnings", len(g.Warnings), "took", res.FinishedAt.Sub(res.StartedAt).Round(time.Second))
	w.WriteHeader(http.StatusNoContent)
}

// rebuildStaleGraphs re-runs inference on stored observations after an
// upgrade, so the map improves without waiting for the next scan.
func (s *Server) rebuildStaleGraphs(ctx context.Context) {
	ids, err := s.store.StaleGraphs(ctx, topo.Version, 3)
	if err != nil {
		s.log.Warn("listing stale graphs", "err", err)
		return
	}
	hist, err := s.store.History(ctx)
	if err != nil {
		s.log.Warn("loading history", "err", err)
		return
	}
	slices.Reverse(ids)
	for _, id := range ids {
		res, err := s.store.Result(ctx, id)
		if err != nil {
			s.log.Warn("loading result", "scan", id, "err", err)
			continue
		}
		if err := s.store.UpdateGraph(ctx, id, topo.Build(id, res, hist)); err != nil {
			s.log.Warn("updating graph", "scan", id, "err", err)
			continue
		}
		s.log.Info("graph rebuilt with new inference", "scan", id, "version", topo.Version)
	}
}
