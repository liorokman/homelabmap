package scanner

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
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
	// settingsEvery is how often WatchLoop rereads the settings.
	settingsEvery time.Duration
}

func NewAgent(cfg Config, log *slog.Logger) *Agent {
	return &Agent{
		cfg:           cfg,
		http:          &http.Client{Timeout: 60 * time.Second},
		log:           log,
		settingsEvery: time.Minute,
	}
}

// jobConfig applies the settings that came with a job.
func (a *Agent) jobConfig(job *obs.Job) (Config, error) {
	if job.Settings == nil {
		return a.cfg, errors.New("the job has no settings: update homelabmap-web and homelabmap-scanner to the same version")
	}
	cfg, err := a.cfg.WithSettings(*job.Settings)
	if err != nil {
		return cfg, err
	}
	if len(cfg.Subnets) == 0 {
		return cfg, errors.New("no subnets to scan: add them on the Settings page")
	}
	return cfg, nil
}

// Run blocks until ctx is cancelled, then returns ctx.Err().
func (a *Agent) Run(ctx context.Context) error {
	a.importLegacy(ctx)
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

		cfg, err := a.jobConfig(job)
		var res *obs.Result
		switch {
		case err != nil:
			a.log.Error("can't run job", "job", job.ID, "err", err)
			now := time.Now().UTC()
			res = &obs.Result{JobID: job.ID, StartedAt: now, FinishedAt: now, Probe: len(job.Probe) > 0, Errors: []string{err.Error()}}
		case len(job.Probe) > 0:
			a.log.Info("probe started", "job", job.ID, "devices", len(job.Probe))
			jctx, cancel := context.WithTimeout(ctx, cfg.JobTimeout)
			res = Probe(jctx, cfg, *job, a.log)
			cancel()
		default:
			a.log.Info("scan started", "job", job.ID)
			jctx, cancel := context.WithTimeout(ctx, cfg.JobTimeout)
			res = Scan(jctx, cfg, *job, a.log)
			cancel()
		}
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

// do sends an authenticated request to the web and decodes a JSON answer.
func (a *Agent) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.cfg.Server+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.cfg.AgentToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return &httpStatusError{Code: resp.StatusCode, URL: path + ": " + string(bytes.TrimSpace(b))}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
}

// importLegacy offers the scan settings from the scanner's environment to
// the web, which takes them once, into settings that are still empty.
// After that, they're ignored.
func (a *Agent) importLegacy(ctx context.Context) {
	l, err := LegacySettings()
	if err != nil {
		a.log.Warn("some scan environment variables are invalid and were left out", "err", err)
	}
	if len(l.Set) == 0 {
		return
	}
	var answer struct {
		Imported bool `json:"imported"`
	}
	for backoff := 2 * time.Second; ; backoff = min(backoff*2, time.Minute) {
		err := a.do(ctx, http.MethodPost, "/agent/v1/legacy-settings", l, &answer)
		var he *httpStatusError
		switch {
		case err == nil && answer.Imported:
			a.log.Warn("copied the scan settings from this container's environment to the Settings page; "+
				"they're configured there now, so remove these variables", "vars", l.Set)
			return
		case err == nil:
			a.log.Warn("these environment variables are ignored: scans are configured on the Settings page", "vars", l.Set)
			return
		case errors.As(err, &he) && he.Code == http.StatusNotFound:
			return // an older web without settings
		case ctx.Err() != nil:
			return
		}
		a.log.Warn("offering environment settings to the web failed", "err", err, "retry_in", backoff)
		sleep(ctx, backoff)
	}
}

// WatchLoop runs the passive listener as the settings say (on, and on the
// interface in the subnets), rereading them every settingsEvery and
// restarting the listener when that changes.
func (a *Agent) WatchLoop(ctx context.Context) {
	var stop context.CancelFunc
	running := "?"
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	for {
		var s obs.ScannerSettings
		if err := a.do(ctx, http.MethodGet, "/agent/v1/settings", nil, &s); err != nil {
			if ctx.Err() != nil {
				return
			}
			a.log.Warn("reading settings failed", "err", err)
		} else {
			cfg, err := a.cfg.WithSettings(s)
			want := ""
			if err == nil && cfg.Passive {
				if iface := lanIface(cfg, selfInfo("")); iface != "" {
					want = iface + " " + fmt.Sprint(cfg.Subnets)
				}
			}
			if want != running {
				if stop != nil {
					stop()
					stop = nil
				}
				running = want
				if want == "" {
					a.log.Info("passive listening off (disabled, or no interface in the subnets)")
				} else {
					wctx, cancel := context.WithCancel(ctx)
					stop = cancel
					sub := *a
					sub.cfg = cfg
					go sub.Watch(wctx)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(a.settingsEvery):
		}
	}
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
