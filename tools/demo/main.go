// Command demo runs the homelabmap UI on a fictional home lab, without a
// scanner or a login: for trying the UI and for screenshots.
//
//	go run ./tools/demo            # then open http://127.0.0.1:8090
//
// It also plays the scanner, so "Scan now" works. Nothing leaves the machine.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
	"github.com/liorokman/homelabmap/internal/store"
	"github.com/liorokman/homelabmap/internal/topo"
	"github.com/liorokman/homelabmap/internal/web"
)

const agentToken = "demo-agent-token-0123456789abcdef0123"

func main() {
	listen := flag.String("listen", "127.0.0.1:8090", "UI address (loopback only: there is no login)")
	agent := flag.String("agent", "127.0.0.1:8098", "scanner API address")
	flag.Parse()
	if err := run(*listen, *agent); err != nil {
		fmt.Fprintln(os.Stderr, "demo:", err)
		os.Exit(1)
	}
}

func run(listen, agent string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	dir, err := os.MkdirTemp("", "homelabmap-demo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	st, err := store.Open(ctx, filepath.Join(dir, "demo.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	now := time.Now().UTC()
	if err := seed(ctx, st, now); err != nil {
		return err
	}

	pub, _ := url.Parse("http://" + listen)
	cfg := web.Config{
		Listen: listen, AgentListen: agent, PublicURL: pub, InsecureNoAuth: true,
		AgentToken: agentToken, SessionTTL: time.Hour, ScanInterval: time.Hour,
		Retention: 14 * 24 * time.Hour, OSRescan: 7 * 24 * time.Hour, ForgetAfter: 30 * 24 * time.Hour,
	}
	go playScanner(ctx, "http://"+agent, log)
	fmt.Printf("homelabmap demo: http://%s (Ctrl-C to stop)\n", listen)
	return web.New(cfg, st, log).Run(ctx)
}

// seed stores one finished scan of the demo network, plus a few things the
// passive listener "heard".
func seed(ctx context.Context, st *store.Store, now time.Time) error {
	sc, _, err := st.Enqueue(ctx, "schedule", now.Add(-2*time.Minute))
	if err != nil {
		return err
	}
	if _, err := st.Claim(ctx, now.Add(-2*time.Minute)); err != nil {
		return err
	}
	res := demoResult(sc.ID, now.Add(-2*time.Minute), now.Add(-time.Minute))
	if _, err := st.RecordSightings(ctx, demoSightings(now), now); err != nil {
		return err
	}
	hist, err := st.History(ctx)
	if err != nil {
		return err
	}
	return st.Complete(ctx, sc.ID, res, topo.Build(sc.ID, res, hist), now.Add(-time.Minute))
}

// playScanner polls the web like the real scanner and answers every job
// with the demo network, so the UI shows the scanner online.
func playScanner(ctx context.Context, base string, log *slog.Logger) {
	c := &http.Client{Timeout: time.Minute}
	for ctx.Err() == nil {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/agent/v1/job", nil)
		req.Header.Set("Authorization", "Bearer "+agentToken)
		resp, err := c.Do(req)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		var job obs.Job
		ok := resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&job) == nil
		_ = resp.Body.Close()
		if !ok {
			continue
		}
		time.Sleep(2 * time.Second) // "scanning"
		now := time.Now().UTC()
		res := demoResult(job.ID, now.Add(-2*time.Second), now)
		if len(job.Probe) > 0 {
			res = &obs.Result{JobID: job.ID, Probe: true, StartedAt: now, FinishedAt: now}
		}
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_ = json.NewEncoder(zw).Encode(res)
		_ = zw.Close()
		req, _ = http.NewRequestWithContext(ctx, http.MethodPost, base+"/agent/v1/result", &buf)
		req.Header.Set("Authorization", "Bearer "+agentToken)
		req.Header.Set("Content-Encoding", "gzip")
		if resp, err := c.Do(req); err == nil {
			_ = resp.Body.Close()
		} else {
			log.Warn("posting demo result", "err", err)
		}
	}
}
