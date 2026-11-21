// Command homelabmap-web serves the network map UI, stores scans in SQLite,
// schedules scans and hands them to homelabmap-scanner.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/liorokman/homelabmap/internal/store"
	"github.com/liorokman/homelabmap/internal/web"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "homelabmap-web:", err)
		os.Exit(1)
	}
}

func run() error {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := web.LoadConfig()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()

	if cfg.InsecureNoAuth {
		log.Warn("LOGIN DISABLED (HOMELABMAP_INSECURE_NO_AUTH) - local development only")
	}
	log.Info("homelabmap-web starting", "public_url", cfg.PublicURL, "db", cfg.DBPath, "scan_interval", cfg.ScanInterval)
	return web.New(cfg, st, log).Run(ctx)
}
