// Command homelabmap-listen is the scanner's passive ears: it reads ARP and
// IPv6 neighbour discovery on one interface and prints each new MAC/IP
// pair as a JSON line on stdout.
//
// It is a separate binary so that it alone carries CAP_NET_RAW (as a file
// capability); homelabmap-scanner, which talks to the network APIs, does not.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
	"github.com/liorokman/homelabmap/internal/sniff"
)

func main() {
	iface := flag.String("iface", "", "interface to listen on (required)")
	window := flag.Duration("repeat", 10*time.Minute, "report the same MAC/IP pair at most this often")
	flag.Parse()
	if *iface == "" {
		fmt.Fprintln(os.Stderr, "homelabmap-listen: -iface is required")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	enc := json.NewEncoder(os.Stdout)
	dedupe := sniff.NewDeduper(int64(window.Seconds()))
	sightings := make(chan sniff.Sighting, 256)
	go func() {
		for s := range sightings {
			now := time.Now().UTC()
			if !dedupe.Fresh(s, now.Unix()) {
				continue
			}
			if err := enc.Encode(obs.Sighting{MAC: s.MAC, IP: s.IP.String(), Via: s.Via, At: now}); err != nil {
				stop() // the scanner went away
				return
			}
		}
	}()
	err := sniff.Listen(ctx, *iface, func(s sniff.Sighting) {
		select {
		case sightings <- s:
		default: // never block the socket readers; a later frame repeats it
		}
	})
	close(sightings)
	if err != nil {
		fmt.Fprintln(os.Stderr, "homelabmap-listen:", err)
		os.Exit(1)
	}
}
