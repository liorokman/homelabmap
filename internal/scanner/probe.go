package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
)

// Probe takes a quick look at newly heard devices: confirm them with an
// ARP ping, fingerprint them, resolve their names, and refresh UniFi and
// PVE (cheap API calls that place Wi-Fi clients and new guests). SNMP is
// left to the next full scan, so a new wired device's switch port shows up
// then.
func Probe(ctx context.Context, cfg Config, job obs.Job, log *slog.Logger) *obs.Result {
	res := &obs.Result{JobID: job.ID, StartedAt: time.Now().UTC(), Probe: true}
	host, _ := os.Hostname()
	res.Scanner = fmt.Sprintf("homelabmap-scanner %s on %s", Version, host)
	for _, p := range cfg.Subnets {
		res.Subnets = append(res.Subnets, p.String())
	}
	res.Self = selfInfo(host)
	errs := &errSink{}

	ips := probeIPs(cfg, job.Probe)
	if len(ips) > 0 {
		sweep, err := nmapSweep(ctx, cfg, ips)
		errs.add("probe", err)
		res.Sweep = sweep
	}

	var wg sync.WaitGroup
	if len(res.Sweep) > 0 && cfg.OSScanMax > 0 {
		wg.Go(func() {
			scans, err := nmapOSScan(ctx, cfg, res.Sweep)
			errs.add("os-scan", err)
			res.OSScans = scans
		})
	}
	if cfg.UniFiURL != "" {
		wg.Go(func() {
			u, err := unifiCollect(ctx, cfg)
			errs.add("unifi", err)
			res.UniFi = u
		})
	}
	if cfg.PVEURL != "" {
		wg.Go(func() {
			p, err := pveCollect(ctx, cfg)
			errs.add("pve", err)
			res.PVE = p
		})
	}
	wg.Wait()

	res.DNS = reverseDNS(ctx, ips)
	res.Errors = errs.errs
	res.FinishedAt = time.Now().UTC()
	log.Debug("probe done", "targets", len(job.Probe), "answered", len(res.Sweep))
	return res
}

// probeIPs is the targets' IPv4 addresses inside the scanned subnets.
// nmap can't confirm a MAC over IPv6 the same way, and the frontend only
// probes devices it has heard an IPv4 address for.
func probeIPs(cfg Config, targets []obs.ProbeTarget) []string {
	var out []string
	for _, t := range targets {
		for _, ip := range t.IPs {
			if a, err := parseAddr(ip); err == nil && a.Is4() && inSubnets(cfg, ip) && !slices.Contains(out, ip) {
				out = append(out, ip)
			}
		}
	}
	slices.Sort(out)
	return out
}
