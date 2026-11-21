package scanner

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
)

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
		Vendor   string `xml:"vendor,attr"`
	} `xml:"address"`
	Ports []struct {
		Protocol string `xml:"protocol,attr"`
		PortID   int    `xml:"portid,attr"`
		State    struct {
			State string `xml:"state,attr"`
		} `xml:"state"`
		Service struct {
			Name string `xml:"name,attr"`
		} `xml:"service"`
	} `xml:"ports>port"`
	OSMatches []struct {
		Name     string `xml:"name,attr"`
		Accuracy int    `xml:"accuracy,attr"`
		Classes  []struct {
			Type     string `xml:"type,attr"`
			Vendor   string `xml:"vendor,attr"`
			Family   string `xml:"osfamily,attr"`
			Gen      string `xml:"osgen,attr"`
			Accuracy int    `xml:"accuracy,attr"`
		} `xml:"osclass"`
	} `xml:"os>osmatch"`
}

func (h nmapHost) addr(kind string) (string, string) {
	for _, a := range h.Addresses {
		if a.AddrType == kind {
			return a.Addr, a.Vendor
		}
	}
	return "", ""
}

func runNmap(ctx context.Context, cfg Config, args []string) (*nmapRun, error) {
	if cfg.NmapPrivileged {
		args = append([]string{"--privileged"}, args...)
	}
	args = append(args, "-oX", "-")
	cmd := exec.CommandContext(ctx, cfg.NmapPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, fmt.Errorf("nmap: %w: %s", err, msg)
	}
	var run nmapRun
	if err := xml.Unmarshal(stdout.Bytes(), &run); err != nil {
		return nil, fmt.Errorf("nmap: parsing XML: %w", err)
	}
	return &run, nil
}

// nmapSweep finds live hosts. With raw-socket privileges on the local
// segment nmap uses ARP, which also yields each host's MAC and vendor.
func nmapSweep(ctx context.Context, cfg Config, subnets []string) ([]obs.SweepHost, error) {
	args := []string{"-sn", "-n", "-T4", "--max-retries", "2"}
	args = append(args, subnets...)
	run, err := runNmap(ctx, cfg, args)
	if err != nil {
		return nil, err
	}
	return parseSweep(run), nil
}

func parseSweep(run *nmapRun) []obs.SweepHost {
	var out []obs.SweepHost
	for _, h := range run.Hosts {
		if h.Status.State != "up" {
			continue
		}
		ip, _ := h.addr("ipv4")
		mac, vendor := h.addr("mac")
		if ip == "" {
			continue
		}
		out = append(out, obs.SweepHost{IP: ip, MAC: obs.NormMAC(mac), Vendor: vendor})
	}
	return out
}

// nmapOSScan fingerprints the given hosts. It needs raw sockets.
func nmapOSScan(ctx context.Context, cfg Config, targets []obs.SweepHost) ([]obs.OSScan, error) {
	if !cfg.NmapPrivileged && os.Geteuid() != 0 {
		return nil, errors.New("OS detection needs raw sockets: set HOMELABMAP_NMAP_PRIVILEGED=true with CAP_NET_RAW")
	}
	byIP := map[string]string{}
	args := []string{"-O", "--osscan-guess", "--max-os-tries", "1", "-n", "-Pn", "-T4",
		"--top-ports", "200", "--host-timeout", "90s"}
	for _, t := range targets {
		byIP[t.IP] = t.MAC
		args = append(args, t.IP)
	}
	run, err := runNmap(ctx, cfg, args)
	if err != nil {
		return nil, err
	}
	return parseOSScan(run, byIP, time.Now().UTC()), nil
}

func parseOSScan(run *nmapRun, byIP map[string]string, now time.Time) []obs.OSScan {
	var out []obs.OSScan
	for _, h := range run.Hosts {
		ip, _ := h.addr("ipv4")
		mac := byIP[ip]
		if mac == "" {
			continue
		}
		s := obs.OSScan{IP: ip, MAC: mac, ScannedAt: now}
		for _, p := range h.Ports {
			if p.State.State == "open" {
				e := strconv.Itoa(p.PortID) + "/" + p.Protocol
				if p.Service.Name != "" {
					e += " " + p.Service.Name
				}
				s.OpenPorts = append(s.OpenPorts, e)
			}
		}
		if len(h.OSMatches) > 0 {
			m := h.OSMatches[0]
			s.Matched = true
			s.Name, s.Accuracy = m.Name, m.Accuracy
			if len(m.Classes) > 0 {
				c := m.Classes[0]
				s.Vendor, s.Family, s.Gen, s.Type = c.Vendor, c.Family, c.Gen, c.Type
			}
		}
		out = append(out, s)
	}
	return out
}

func parseAddr(s string) (netip.Addr, error) { return netip.ParseAddr(s) }
