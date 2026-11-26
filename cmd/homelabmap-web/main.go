// Command homelabmap-web serves the network map UI, stores scans in SQLite,
// schedules scans and hands them to homelabmap-scanner.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/liorokman/homelabmap/internal/store"
	"github.com/liorokman/homelabmap/internal/web"
)

func main() {
	cmd := run
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "reset-code":
			cmd = resetCode
		default:
			fmt.Fprintf(os.Stderr, "usage: homelabmap-web [reset-code]\n\n"+
				"  reset-code  print a one-time code for the sign-in page's \"Forgot password?\" form\n")
			os.Exit(2)
		}
	}
	if err := cmd(); err != nil {
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

	switch {
	case cfg.InsecureNoAuth:
		log.Warn("LOGIN DISABLED (HOMELABMAP_INSECURE_NO_AUTH) - local development only")
	case cfg.PasswordLogin():
		log.Info("password login (no OIDC provider configured)")
	}
	log.Info("homelabmap-web starting", "public_url", cfg.PublicURL, "db", cfg.DBPath, "scan_interval", cfg.ScanInterval)
	srv, err := web.New(cfg, st, log)
	if err != nil {
		return err
	}
	return srv.Run(ctx)
}

// resetCode prints a one-time password reset code. It runs next to the
// server (docker compose exec web homelabmap-web reset-code) and writes to
// the same database; being able to run it is the proof of ownership.
func resetCode() error {
	if os.Getenv("HOMELABMAP_OIDC_ISSUER") != "" || os.Getenv("HOMELABMAP_OIDC_CLIENT_ID") != "" {
		return errors.New("password login is off: an OIDC provider is configured; reset the password there")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, web.DBPathFromEnv())
	if err != nil {
		return err
	}
	defer st.Close()
	code, exp, err := web.CreateResetCode(ctx, st, time.Now().UTC())
	if err != nil {
		return err
	}
	where := "the sign-in page"
	if u := strings.TrimRight(os.Getenv("HOMELABMAP_PUBLIC_URL"), "/"); u != "" {
		where = u + "/signin/forgot"
	}
	fmt.Printf("Reset code: %s\n\nEnter it at %s before %s.\nIt works once; running this again replaces it.\n",
		code, where, exp.Local().Format("15:04"))
	return nil
}
