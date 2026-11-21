package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/liorokman/homelabmap/internal/obs"
)

var pveNetKey = regexp.MustCompile(`^net\d+$`)

type pveClient struct {
	c    *http.Client
	base string
	hdr  map[string]string
}

func (p *pveClient) get(ctx context.Context, path string, v any) error {
	var wrap struct {
		Data any `json:"data"`
	}
	wrap.Data = v
	return getJSON(ctx, p.c, p.base+"/api2/json"+path, p.hdr, &wrap)
}

// pveCollect lists nodes and guests with their NICs. Read-only: a token with
// the PVEAuditor role is enough. Guest-agent IPs need VM.GuestAgent.Audit
// (or VM.Monitor on older PVE) and are skipped quietly if not permitted.
func pveCollect(ctx context.Context, cfg Config) (*obs.PVE, error) {
	p := &pveClient{
		c:    httpClient(cfg.PVEInsecureTLS),
		base: cfg.PVEURL,
		hdr:  map[string]string{"Authorization": "PVEAPIToken=" + cfg.PVETokenID + "=" + cfg.PVETokenSecret},
	}

	var status []struct {
		Type   string `json:"type"`
		Name   string `json:"name"`
		IP     string `json:"ip"`
		Online int    `json:"online"`
	}
	if err := p.get(ctx, "/cluster/status", &status); err != nil {
		return nil, err
	}
	out := &obs.PVE{}
	for _, s := range status {
		if s.Type != "node" {
			continue
		}
		node := obs.PVENode{Name: s.Name, IP: s.IP, Status: "offline"}
		if s.Online == 1 {
			node.Status = "online"
			guests, err := pveGuests(ctx, p, s.Name)
			if err != nil {
				return out, fmt.Errorf("node %s: %w", s.Name, err)
			}
			node.Guests = guests
		}
		out.Nodes = append(out.Nodes, node)
	}
	return out, nil
}

func pveGuests(ctx context.Context, p *pveClient, node string) ([]obs.PVEGuest, error) {
	var guests []obs.PVEGuest
	for _, kind := range []string{"qemu", "lxc"} {
		var list []struct {
			VMID   any    `json:"vmid"`
			Name   string `json:"name"`
			Status string `json:"status"`
		}
		if err := p.get(ctx, "/nodes/"+url.PathEscape(node)+"/"+kind, &list); err != nil {
			return nil, err
		}
		for _, l := range list {
			vmid := toInt(l.VMID)
			g := obs.PVEGuest{VMID: vmid, Name: l.Name, Type: kind, Status: l.Status}
			path := fmt.Sprintf("/nodes/%s/%s/%d", url.PathEscape(node), kind, vmid)

			var conf map[string]any
			if err := p.get(ctx, path+"/config", &conf); err == nil {
				if v, ok := conf["ostype"].(string); ok {
					g.OSType = v
				}
				if g.Name == "" {
					if v, ok := conf["hostname"].(string); ok {
						g.Name = v
					}
				}
				g.NICs = pveNICs(conf, kind)
			}
			if g.Status == "running" {
				g.IPs = pveGuestIPs(ctx, p, path, kind)
			}
			guests = append(guests, g)
		}
	}
	slices.SortFunc(guests, func(a, b obs.PVEGuest) int { return a.VMID - b.VMID })
	return guests, nil
}

// pveNICs parses "net0: virtio=BC:24:11:..,bridge=vmbr0" (qemu) and
// "net0: name=eth0,bridge=vmbr0,hwaddr=BC:24:11:..,ip=dhcp" (lxc).
func pveNICs(conf map[string]any, kind string) []obs.PVENIC {
	var keys []string
	for k := range conf {
		if pveNetKey.MatchString(k) {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	var nics []obs.PVENIC
	for _, k := range keys {
		s, _ := conf[k].(string)
		nic := obs.PVENIC{Name: k}
		for _, kv := range strings.Split(s, ",") {
			key, val, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			switch {
			case key == "bridge":
				nic.Bridge = val
			case key == "name" && kind == "lxc":
				nic.Name = val
			case key == "hwaddr" || key == "macaddr":
				nic.MAC = obs.NormMAC(val)
			case kind == "qemu" && nic.MAC == "":
				// First "model=MAC" pair, e.g. virtio=..., e1000=...
				nic.MAC = obs.NormMAC(val)
			}
		}
		if nic.MAC != "" {
			nics = append(nics, nic)
		}
	}
	return nics
}

func pveGuestIPs(ctx context.Context, p *pveClient, path, kind string) []string {
	var ips []string
	add := func(s string) {
		s, _, _ = strings.Cut(s, "/")
		a, err := netip.ParseAddr(s)
		if err != nil || !a.Is4() || a.IsLoopback() || a.IsLinkLocalUnicast() {
			return
		}
		if !slices.Contains(ips, a.String()) {
			ips = append(ips, a.String())
		}
	}
	if kind == "lxc" {
		var ifs []struct {
			Name string `json:"name"`
			Inet string `json:"inet"`
		}
		if p.get(ctx, path+"/interfaces", &ifs) == nil {
			for _, i := range ifs {
				if i.Name != "lo" {
					add(i.Inet)
				}
			}
		}
		return ips
	}
	var agent struct {
		Result []struct {
			Name string `json:"name"`
			IPs  []struct {
				Addr string `json:"ip-address"`
			} `json:"ip-addresses"`
		} `json:"result"`
	}
	if p.get(ctx, path+"/agent/network-get-interfaces", &agent) == nil {
		for _, i := range agent.Result {
			if i.Name == "lo" || strings.HasPrefix(i.Name, "docker") || strings.HasPrefix(i.Name, "br-") || strings.HasPrefix(i.Name, "veth") {
				continue
			}
			for _, a := range i.IPs {
				add(a.Addr)
			}
		}
	}
	return ips
}

func toInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		var n int
		_, _ = fmt.Sscan(x, &n)
		return n
	}
	return 0
}
