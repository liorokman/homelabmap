package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
)

const (
	ssdpAddr   = "239.255.255.250:1900"
	ssdpWait   = 3 * time.Second
	descLimit  = 256 << 10
	descTimout = 3 * time.Second
)

var mSearch = []byte("M-SEARCH * HTTP/1.1\r\nHOST: " + ssdpAddr + "\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n")

// ssdpDiscover asks every UPnP device on the LAN to identify itself and
// fetches each one's description (friendly name, maker, model).
func ssdpDiscover(ctx context.Context, cfg Config, iface string) ([]obs.SSDPDevice, error) {
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if iface != "" {
		if err := setMulticastIface(conn, iface); err != nil {
			return nil, fmt.Errorf("multicast interface %s: %w", iface, err)
		}
	}
	dst, err := net.ResolveUDPAddr("udp4", ssdpAddr)
	if err != nil {
		return nil, err
	}
	// UDP is lossy and devices answer once per search: ask twice.
	for range 2 {
		if _, err := conn.WriteTo(mSearch, dst); err != nil {
			return nil, err
		}
	}

	byIP := map[string]*obs.SSDPDevice{}
	deadline := time.Now().Add(ssdpWait)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetReadDeadline(deadline)
	buf := make([]byte, 4096)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			break // deadline
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		ip := ua.IP.String()
		if !inSubnets(cfg, ip) {
			continue
		}
		hdr, ok := parseSSDPResponse(buf[:n])
		if !ok {
			continue
		}
		d := byIP[ip]
		if d == nil {
			d = &obs.SSDPDevice{IP: ip}
			byIP[ip] = d
		}
		if d.Server == "" {
			d.Server = hdr.Get("Server")
		}
		if loc := hdr.Get("Location"); d.Location == "" && descURLAllowed(loc, ip) {
			d.Location = loc
		}
		if st := hdr.Get("St"); st != "" && !slices.Contains(d.Types, st) && len(d.Types) < 32 {
			d.Types = append(d.Types, st)
		}
	}

	out := make([]obs.SSDPDevice, 0, len(byIP))
	for _, d := range byIP {
		out = append(out, *d)
	}
	slices.SortFunc(out, func(a, b obs.SSDPDevice) int { return strings.Compare(a.IP, b.IP) })

	client := &http.Client{
		Timeout: descTimout,
		// A description must come from the device itself.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i := range out {
		if out[i].Location == "" {
			continue
		}
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			fetchDescription(ctx, client, &out[i])
		})
	}
	wg.Wait()
	return out, nil
}

// parseSSDPResponse reads the HTTP-over-UDP answer to an M-SEARCH.
func parseSSDPResponse(b []byte) (http.Header, bool) {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(b)), nil)
	if err != nil {
		return nil, false
	}
	_ = resp.Body.Close() // in-memory; nothing to release, but keep linters honest
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	return resp.Header, true
}

// descURLAllowed only lets the scanner fetch plain HTTP(S) URLs on the
// address that answered: a device can't point it anywhere else.
func descURLAllowed(loc, ip string) bool {
	u, err := url.Parse(loc)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return false
	}
	a, err := netip.ParseAddr(u.Hostname())
	return err == nil && a.Unmap().String() == ip
}

type upnpDescription struct {
	Device struct {
		DeviceType       string `xml:"deviceType"`
		FriendlyName     string `xml:"friendlyName"`
		Manufacturer     string `xml:"manufacturer"`
		ModelName        string `xml:"modelName"`
		ModelNumber      string `xml:"modelNumber"`
		ModelDescription string `xml:"modelDescription"`
	} `xml:"device"`
}

func fetchDescription(ctx context.Context, c *http.Client, d *obs.SSDPDevice) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.Location, nil)
	if err != nil {
		return
	}
	resp, err := c.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, descLimit))
	if err != nil {
		return
	}
	parseDescription(body, d)
}

// parseDescription fills d from a UPnP device description document.
func parseDescription(body []byte, d *obs.SSDPDevice) bool {
	var desc upnpDescription
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = false
	if err := dec.Decode(&desc); err != nil {
		return false
	}
	clean := func(s string) string {
		s = strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return ' '
			}
			return r
		}, s)
		s = strings.Join(strings.Fields(s), " ")
		if len(s) > 200 {
			s = s[:200]
		}
		return s
	}
	dd := desc.Device
	d.DeviceType = clean(dd.DeviceType)
	d.FriendlyName = clean(dd.FriendlyName)
	d.Manufacturer = clean(dd.Manufacturer)
	d.ModelName = clean(dd.ModelName)
	d.ModelNumber = clean(dd.ModelNumber)
	d.ModelDescription = clean(dd.ModelDescription)
	return d.FriendlyName != "" || d.ModelName != "" || d.Manufacturer != ""
}
