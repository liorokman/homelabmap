// Command homelabmap-scanner observes the LAN and reports to homelabmap-web.
//
// It runs on the host network (nmap needs raw sockets and the local segment)
// and has no listening sockets: it long-polls the frontend for jobs.
//
// With -once it runs a single scan and writes the JSON result to stdout or
// -out, without contacting the frontend (useful for testing).
package main

import (
	"context"
	"encoding/json"
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
	log.Info("homelabmap-scanner starting", "version", scanner.Version, "server", cfg.Server, "subnets", cfg.Subnets,
		"unifi", cfg.UniFiURL != "", "pve", cfg.PVEURL != "", "nmap_privileged", cfg.NmapPrivileged)
	return scanner.NewAgent(cfg, log).Run(ctx)
}
