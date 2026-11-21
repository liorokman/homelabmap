package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
)

// Version is set at build time.
var Version = "dev"

// errSink collects non-fatal collector errors from concurrent goroutines.
type errSink struct {
	mu   sync.Mutex
	errs []string
}

func (e *errSink) add(source string, err error) {
	if err == nil {
		return
	}
	e.mu.Lock()
	e.errs = append(e.errs, fmt.Sprintf("%s: %v", source, err))
	e.mu.Unlock()
}

// Scan runs every collector once. It always returns a result; problems are
// reported in Result.Errors so a partial picture still reaches the frontend.
func Scan(ctx context.Context, cfg Config, job obs.Job, log *slog.Logger) *obs.Result {
	res := &obs.Result{JobID: job.ID, StartedAt: time.Now().UTC()}
	host, _ := os.Hostname()
	res.Scanner = fmt.Sprintf("homelabmap-scanner %s on %s", Version, host)
	for _, p := range cfg.Subnets {
		res.Subnets = append(res.Subnets, p.String())
	}
	errs := &errSink{}

	res.Self = selfInfo(host)

	// 1. Find live hosts. Everything else keys off this list.
	sweep, err := nmapSweep(ctx, cfg, res.Subnets)
	errs.add("sweep", err)
	res.Sweep = sweep
	log.Debug("sweep done", "hosts", len(sweep))

	// 2. SNMP, UniFi and PVE are independent of each other.
	var wg sync.WaitGroup
	wg.Go(func() {
		targets := snmpTargets(cfg, sweep, res.Self)
		res.SNMP = snmpCollect(ctx, cfg.SNMP, targets, errs, log)
	})
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

	// 3. OS fingerprinting for stale or brand-new hosts.
	targets := osScanTargets(job, sweep, cfg.OSScanMax)
	if len(targets) > 0 {
		scans, err := nmapOSScan(ctx, cfg, targets)
		errs.add("os-scan", err)
		res.OSScans = scans
	}

	// 4. Reverse DNS for every IP we learned about.
	res.DNS = reverseDNS(ctx, collectIPs(res))

	res.Errors = errs.errs
	res.FinishedAt = time.Now().UTC()
	return res
}

// snmpTargets is every live host plus configured seeds, minus duplicates.
func snmpTargets(cfg Config, sweep []obs.SweepHost, self obs.Self) []string {
	seen := map[string]bool{}
	var out []string
	add := func(ip string) {
		if ip != "" && !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	for _, s := range cfg.SNMP.Seeds {
		add(s)
	}
	for _, h := range sweep {
		add(h.IP)
	}
	for _, i := range self.Interfaces {
		for _, ip := range i.IPs {
			if inSubnets(cfg, ip) {
				add(ip)
			}
		}
	}
	return out
}

func inSubnets(cfg Config, ip string) bool {
	for _, p := range cfg.Subnets {
		if a, err := parseAddr(ip); err == nil && p.Contains(a) {
			return true
		}
	}
	return false
}

// osScanTargets maps requested MACs to their current IPs, plus unknown MACs.
func osScanTargets(job obs.Job, sweep []obs.SweepHost, max int) []obs.SweepHost {
	if max <= 0 {
		return nil
	}
	if job.OSScanMax > 0 && job.OSScanMax < max {
		max = job.OSScanMax
	}
	want := map[string]bool{}
	for _, m := range job.OSScanMACs {
		want[obs.NormMAC(m)] = true
	}
	known := map[string]bool{}
	for _, m := range job.KnownMACs {
		known[obs.NormMAC(m)] = true
	}
	var out []obs.SweepHost
	for _, h := range sweep {
		if h.MAC == "" {
			continue
		}
		if want[h.MAC] || !known[h.MAC] {
			out = append(out, h)
		}
		if len(out) >= max {
			break
		}
	}
	return out
}

func collectIPs(res *obs.Result) []string {
	set := map[string]bool{}
	for _, h := range res.Sweep {
		set[h.IP] = true
	}
	for _, d := range res.SNMP {
		set[d.IP] = true
		for _, a := range d.ARP {
			set[a.IP] = true
		}
	}
	if res.PVE != nil {
		for _, n := range res.PVE.Nodes {
			set[n.IP] = true
			for _, g := range n.Guests {
				for _, ip := range g.IPs {
					set[ip] = true
				}
			}
		}
	}
	delete(set, "")
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	slices.Sort(out)
	return out
}

func selfInfo(host string) obs.Self {
	s := obs.Self{Hostname: host}
	ifs, err := net.Interfaces()
	if err != nil {
		return s
	}
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 || isVirtualIface(i.Name) {
			continue
		}
		mac := obs.MACFromBytes(i.HardwareAddr)
		if mac == "" {
			continue
		}
		si := obs.SelfIface{Name: i.Name, MAC: mac}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				si.IPs = append(si.IPs, ipn.IP.String())
			}
		}
		if len(si.IPs) > 0 {
			s.Interfaces = append(s.Interfaces, si)
		}
	}
	return s
}

// isVirtualIface skips container bridges and tunnels on the scanner host:
// their addresses are not the host's identity on the LAN.
func isVirtualIface(name string) bool {
	for _, p := range []string{"docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "tun", "wg", "tap", "vnet", "podman", "lxc"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
