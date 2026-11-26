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
	"net/netip"
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
			job, err := s.buildJob(ctx, sc)
			if err != nil {
				_ = s.store.Fail(ctx, sc.ID, "building job failed", s.now())
				s.serverError(w, "building job", err)
				return
			}
			s.log.Info("scan handed to scanner", "scan", sc.ID, "trigger", sc.Trigger,
				"os_targets", len(job.OSScanMACs), "probe_targets", len(job.Probe))
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
func (s *Server) buildJob(ctx context.Context, sc *store.Scan) (obs.Job, error) {
	set := s.settings()
	job := obs.Job{ID: sc.ID, OSScanMax: set.Scan.OSScanMax, Settings: set.forScanner()}
	if sc.Trigger == store.TriggerProbe {
		job.Probe = sc.Targets
		return job, nil
	}
	if set.Scan.OSScanMax == 0 {
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
	cutoff := s.now().Add(-set.Scan.OSRescan.D())
	for _, n := range g.Nodes {
		if n.Infra || n.Absent || len(n.MACs) == 0 || !weakOS(n.OSSource) {
			continue
		}
		if t, ok := scanned[n.MACs[0]]; ok && t.After(cutoff) {
			continue
		}
		job.OSScanMACs = append(job.OSScanMACs, n.MACs[0])
		if len(job.OSScanMACs) >= set.Scan.OSScanMax {
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
	sc, err := s.store.Get(ctx, res.JobID)
	if err != nil || sc.Status != store.StatusRunning {
		http.Error(w, fmt.Sprintf("scan %d is not running", res.JobID), http.StatusConflict)
		return
	}
	// The job decides what kind of result this is, not the scanner.
	if sc.Trigger == store.TriggerProbe {
		s.completeProbe(w, r, &res)
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
	s.carryOver(ctx, g)
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
		g := topo.Build(id, res, hist)
		// The old version of this same map knows which devices it carried.
		if old, err := s.store.Graph(ctx, id); err == nil {
			topo.CarryOver(g, old, g.ScanStarted, s.settings().Scan.ForgetAfter.D())
		}
		if err := s.store.UpdateGraph(ctx, id, g); err != nil {
			s.log.Warn("updating graph", "scan", id, "err", err)
			continue
		}
		s.log.Info("graph rebuilt with new inference", "scan", id, "version", topo.Version)
	}
}

// completeProbe merges a probe into the current map. A device that didn't
// answer leaves the map alone.
func (s *Server) completeProbe(w http.ResponseWriter, r *http.Request, res *obs.Result) {
	ctx := r.Context()
	res.Probe = true
	var probed []string
	for _, h := range res.Sweep {
		if h.MAC != "" {
			probed = append(probed, h.MAC)
		}
	}
	if len(probed) == 0 {
		msg := "probed device did not answer"
		if len(res.Errors) > 0 {
			msg += ": " + strings.Join(res.Errors, "; ")
		}
		_ = s.store.Fail(ctx, res.JobID, msg, s.now())
		s.log.Info("probe found nothing", "scan", res.JobID, "reason", msg)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	base, err := s.store.LatestResult(ctx)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, "loading latest result", err)
		return
	}
	merged := obs.MergeProbe(base, res)
	hist, err := s.store.History(ctx)
	if err != nil {
		s.serverError(w, "loading history", err)
		return
	}
	g := topo.Build(res.JobID, merged, hist)
	s.carryOver(ctx, g)
	if err := s.store.CompleteProbe(ctx, res.JobID, merged, g, probed, s.now()); err != nil {
		s.serverError(w, "storing probe", err)
		return
	}
	s.log.Info("probe stored", "scan", res.JobID, "devices", probed, "nodes", len(g.Nodes),
		"took", res.FinishedAt.Sub(res.StartedAt).Round(time.Second))
	w.WriteHeader(http.StatusNoContent)
}

const maxSightings = 2000

// handleAgentSightings records what the passive listener heard and queues
// a probe for devices never seen before.
func (s *Server) handleAgentSightings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var body obs.Sightings
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		http.Error(w, "bad sightings: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(body.Sightings) > maxSightings {
		http.Error(w, "too many sightings", http.StatusRequestEntityTooLarge)
		return
	}
	clean := make([]obs.Sighting, 0, len(body.Sightings))
	for _, x := range body.Sightings {
		if c, ok := cleanSighting(x); ok {
			clean = append(clean, c)
		}
	}
	if len(clean) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	now := s.now()
	s.lastSighting.Store(now.Unix())
	fresh, err := s.store.RecordSightings(ctx, clean, now)
	if err != nil {
		s.serverError(w, "recording sightings", err)
		return
	}
	if perHour := s.settings().Scan.ProbeMaxPerHour; len(fresh) > 0 && perHour > 0 {
		probe, accepted, err := s.store.EnqueueProbe(ctx, fresh, perHour, now)
		if err != nil {
			s.serverError(w, "queueing probe", err)
			return
		}
		if len(accepted) < len(fresh) {
			s.log.Warn("probe budget exhausted; the next full scan will cover the rest",
				"new", len(fresh), "accepted", len(accepted), "per_hour", perHour)
		}
		if probe != nil {
			s.log.Info("new device heard; probe queued", "scan", probe.ID, "macs", accepted)
			s.notifyAgent()
		} else if len(accepted) > 0 {
			s.log.Info("new device heard; a full scan is already queued", "macs", accepted)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// cleanSighting validates and normalises one sighting from the scanner.
func cleanSighting(x obs.Sighting) (obs.Sighting, bool) {
	x.MAC = obs.NormMAC(x.MAC)
	if x.MAC == "" || obs.IsMulticast(x.MAC) {
		return x, false
	}
	a, err := netip.ParseAddr(x.IP)
	if err != nil || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() || a.Zone() != "" {
		return x, false
	}
	x.IP = a.String()
	if x.Via != "arp" && x.Via != "ndp" {
		return x, false
	}
	return x, true
}

// carryOver keeps devices from the current map that this scan didn't see.
func (s *Server) carryOver(ctx context.Context, g *topo.Graph) {
	var prev *topo.Graph
	if _, raw, err := s.store.LatestGraph(ctx); err == nil {
		var p topo.Graph
		if json.Unmarshal(raw, &p) == nil {
			prev = &p
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		s.log.Warn("loading previous map; absent devices not carried this time", "err", err)
	}
	topo.CarryOver(g, prev, s.now(), s.settings().Scan.ForgetAfter.D())
}
