package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
)

// Watch runs the homelabmap-listen helper on the LAN interface and forwards
// what it hears to the frontend, which decides what is new. It restarts
// the helper if it dies and returns when ctx ends.
func (a *Agent) Watch(ctx context.Context) {
	self := selfInfo("")
	iface := lanIface(a.cfg, self)
	if iface == "" {
		a.log.Warn("passive listening disabled: no interface has an address in HOMELABMAP_SUBNETS")
		return
	}
	own := map[string]bool{}
	for _, i := range self.Interfaces {
		own[i.MAC] = true
	}

	batch := make(chan obs.Sighting, 1024)
	go a.forward(ctx, batch)

	backoff := 5 * time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := a.runListener(ctx, iface, func(s obs.Sighting) {
			if keepSighting(a.cfg, own, s) {
				select {
				case batch <- s:
				default: // frontend unreachable for a while; drop
				}
			}
		})
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > time.Minute {
			backoff = 5 * time.Second
		}
		a.log.Warn("passive listener stopped; restarting", "err", err, "retry_in", backoff)
		sleep(ctx, backoff)
		backoff = min(backoff*2, 5*time.Minute)
	}
}

func (a *Agent) runListener(ctx context.Context, iface string, emit func(obs.Sighting)) error {
	cmd := exec.CommandContext(ctx, a.cfg.ListenPath, "-iface", iface)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	a.log.Info("passive listener started", "iface", iface)
	readSightings(out, emit)
	err = cmd.Wait()
	if msg := strings.TrimSpace(stderr.String()); msg != "" {
		err = fmt.Errorf("%w: %s", err, msg)
	}
	return err
}

// readSightings decodes the helper's JSON lines, skipping garbage.
func readSightings(r io.Reader, emit func(obs.Sighting)) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		var s obs.Sighting
		if json.Unmarshal(sc.Bytes(), &s) == nil && s.MAC != "" && s.IP != "" {
			emit(s)
		}
	}
}

// keepSighting drops the scanner host itself and IPv4 addresses outside
// the scanned subnets (another segment's traffic, or misconfigured hosts).
func keepSighting(cfg Config, own map[string]bool, s obs.Sighting) bool {
	s.MAC = obs.NormMAC(s.MAC)
	if s.MAC == "" || own[s.MAC] || obs.IsMulticast(s.MAC) {
		return false
	}
	a, err := parseAddr(s.IP)
	if err != nil {
		return false
	}
	return !a.Is4() || inSubnets(cfg, s.IP)
}

// lanIface is the first interface with an IPv4 address in the subnets.
func lanIface(cfg Config, self obs.Self) string {
	for _, i := range self.Interfaces {
		for _, ip := range i.IPs {
			if inSubnets(cfg, ip) {
				return i.Name
			}
		}
	}
	return ""
}

// forward posts sightings in batches: whatever arrived within a couple of
// seconds of the first one, up to 500.
func (a *Agent) forward(ctx context.Context, in <-chan obs.Sighting) {
	for {
		var batch []obs.Sighting
		select {
		case <-ctx.Done():
			return
		case s := <-in:
			batch = append(batch, s)
		}
		linger := time.NewTimer(2 * time.Second)
	collect:
		for len(batch) < 500 {
			select {
			case s := <-in:
				batch = append(batch, s)
			case <-linger.C:
				break collect
			case <-ctx.Done():
				linger.Stop()
				return
			}
		}
		linger.Stop()
		for attempt := 1; ; attempt++ {
			err := a.postSightings(ctx, batch)
			if err == nil || ctx.Err() != nil {
				break
			}
			if attempt == 3 {
				a.log.Warn("dropping sightings", "count", len(batch), "err", err)
				break
			}
			sleep(ctx, time.Duration(attempt)*3*time.Second)
		}
	}
}

func (a *Agent) postSightings(ctx context.Context, batch []obs.Sighting) error {
	body, err := json.Marshal(obs.Sightings{Sightings: batch})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.Server+"/agent/v1/sightings", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.cfg.AgentToken)
	req.Header.Set("Content-Type", "application/json")
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
