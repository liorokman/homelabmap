// Command homelabmap-scanner observes the LAN and reports to homelabmap-web.
//
// It runs on the host network (nmap needs raw sockets and the local segment)
// and has no listening sockets: it long-polls the frontend for jobs.
//
// What to scan, and the credentials, come from the web's Settings page with
// each job. With -once it instead reads them from the old HOMELABMAP_*
// variables, runs a single scan and writes the JSON result to stdout or
// -out, without contacting the frontend (useful for testing).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/liorokman/homelabmap/internal/obs"
	"github.com/liorokman/homelabmap/internal/scanner"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "homelabmap-scanner:", err)
		os.Exit(1)
	}
}

func run() error {
	once := flag.Bool("once", false, "run one scan and print the result instead of polling the frontend")
	out := flag.String("out", "", "with -once: write the result to this file instead of stdout")
	debug := flag.Bool("debug", false, "debug logging")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := scanner.LoadConfig()
	if err != nil {
		return err
	}
	if *once {
		// No web to ask: the scan settings come from the environment.
		legacy, err := scanner.LegacySettings()
		if err != nil {
			return err
		}
		if cfg, err = cfg.WithSettings(legacy.Settings); err != nil {
			return err
		}
		if len(cfg.Subnets) == 0 {
			return errors.New("-once needs HOMELABMAP_SUBNETS")
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *once {
		res := scanner.Scan(ctx, cfg, obs.Job{OSScanMax: cfg.OSScanMax}, log)
		w := os.Stdout
		if *out != "" {
			f, err := os.Create(*out)
			if err != nil {
				return err
			}
			defer f.Close()
			w = f
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}

	if cfg.AgentToken == "" {
		return fmt.Errorf("HOMELABMAP_AGENT_TOKEN is required")
	}
	log.Info("homelabmap-scanner starting", "version", scanner.Version, "server", cfg.Server, "nmap_privileged", cfg.NmapPrivileged)
	agent := scanner.NewAgent(cfg, log)
	go agent.WatchLoop(ctx)
	if err := agent.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil // stopped by a signal
}
