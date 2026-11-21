package scanner

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
)

// Agent polls the frontend for jobs and posts results back. It never listens.
type Agent struct {
	cfg  Config
	http *http.Client
	log  *slog.Logger
}

func NewAgent(cfg Config, log *slog.Logger) *Agent {
	return &Agent{
		cfg:  cfg,
		http: &http.Client{Timeout: 60 * time.Second},
		log:  log,
	}
}

// Run blocks until ctx is cancelled, then returns ctx.Err().
func (a *Agent) Run(ctx context.Context) error {
	backoff := 2 * time.Second
	for ctx.Err() == nil {
		job, err := a.poll(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			a.log.Warn("polling frontend failed", "err", err, "retry_in", backoff)
			sleep(ctx, backoff)
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = 2 * time.Second
		if job == nil {
			continue // long-poll timed out without work
		}

		jctx, cancel := context.WithTimeout(ctx, a.cfg.JobTimeout)
		var res *obs.Result
		if len(job.Probe) > 0 {
			a.log.Info("probe started", "job", job.ID, "devices", len(job.Probe))
			res = Probe(jctx, a.cfg, *job, a.log)
		} else {
			a.log.Info("scan started", "job", job.ID)
			res = Scan(jctx, a.cfg, *job, a.log)
		}
		cancel()
		a.log.Info("job finished", "job", job.ID, "probe", res.Probe,
			"hosts", len(res.Sweep), "snmp", len(res.SNMP), "os_scans", len(res.OSScans),
			"errors", len(res.Errors), "took", res.FinishedAt.Sub(res.StartedAt).Round(time.Second))

		for attempt := 1; ; attempt++ {
			err := a.post(ctx, res)
			if err == nil {
				break
			}
			if ctx.Err() != nil || attempt == 5 {
				a.log.Error("posting result failed, dropping it", "job", job.ID, "err", err)
				break
			}
			a.log.Warn("posting result failed", "job", job.ID, "attempt", attempt, "err", err)
			sleep(ctx, time.Duration(attempt)*5*time.Second)
		}
	}
	return ctx.Err()
}

func (a *Agent) poll(ctx context.Context) (*obs.Job, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.Server+"/agent/v1/job", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.cfg.AgentToken)
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
		var job obs.Job
		if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&job); err != nil {
			return nil, fmt.Errorf("decoding job: %w", err)
		}
		return &job, nil
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("job poll: HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(b))
	}
}

func (a *Agent) post(ctx context.Context, res *obs.Result) error {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(res); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.Server+"/agent/v1/result", &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.cfg.AgentToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(b))
	}
	return nil
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
