package topo

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
)

// uniDev is a UniFi device normalised from either API flavour.
type uniDev struct {
	ID, MAC, IP, Name, Model, Type, Version string
	UplinkMAC, UplinkID                     string
	UplinkRemotePort, LocalPort             int
	UplinkWireless                          bool
	Offline                                 bool
}

// uniClient is a UniFi client normalised from either API flavour.
type uniClient struct {
	MAC, IP, Name, Hostname, OUI string
	Wired, WiredKnown            bool
	SwMAC                        string
	SwPort                       int
	APMAC, UplinkID, ESSID       string
	FirstSeen, LastSeen          time.Time
	// Offline clients come from the controller's history: seen recently,
	// not connected now. Their last IP may belong to someone else by now.
	Offline bool
}

// uniKnown is what the controller remembers about a client it has ever
// seen: the alias set in UniFi, and when it was first and last seen.
type uniKnown struct {
	Alias, Hostname     string
	FirstSeen, LastSeen time.Time
}

func unixTime(n int64) time.Time {
	if n <= 0 {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}

// parseUniFiKnown indexes the controller's remembered clients by MAC.
func parseUniFiKnown(u *obs.UniFi) map[string]uniKnown {
	out := map[string]uniKnown{}
	if u == nil {
		return out
	}
	for _, raw := range u.Known {
		var r struct {
			MAC       string `json:"mac"`
			Name      string `json:"name"`
			Hostname  string `json:"hostname"`
			FirstSeen int64  `json:"first_seen"`
			LastSeen  int64  `json:"last_seen"`
		}
		if json.Unmarshal(raw, &r) != nil {
			continue
		}
		if m := obs.NormMAC(r.MAC); m != "" {
			out[m] = uniKnown{Alias: strings.TrimSpace(r.Name), Hostname: strings.TrimSpace(r.Hostname),
				FirstSeen: unixTime(r.FirstSeen), LastSeen: unixTime(r.LastSeen)}
		}
	}
	return out
}

// parseUniFiHistory reads recently seen, currently disconnected clients
// (v2 API), skipping any that are connected now.
func parseUniFiHistory(u *obs.UniFi, connected map[string]bool) []uniClient {
	if u == nil {
		return nil
	}
	var out []uniClient
	for _, raw := range u.History {
		var r struct {
			MAC           string `json:"mac"`
			Name          string `json:"name"`
			Hostname      string `json:"hostname"`
			OUI           string `json:"oui"`
			Type          string `json:"type"`
			IsWired       *bool  `json:"is_wired"`
			LastUplinkMAC string `json:"last_uplink_mac"`
			SwPort        int    `json:"sw_port"`
			FirstSeen     int64  `json:"first_seen"`
			LastSeen      int64  `json:"last_seen"`
		}
		if json.Unmarshal(raw, &r) != nil {
			continue
		}
		m := obs.NormMAC(r.MAC)
		if m == "" || connected[m] {
			continue
		}
		c := uniClient{MAC: m, Name: strings.TrimSpace(r.Name), Hostname: strings.TrimSpace(r.Hostname), OUI: r.OUI,
			FirstSeen: unixTime(r.FirstSeen), LastSeen: unixTime(r.LastSeen), Offline: true}
		switch {
		case r.IsWired != nil:
			c.Wired, c.WiredKnown = *r.IsWired, true
		case r.Type == "WIRED":
			c.Wired, c.WiredKnown = true, true
		case r.Type == "WIRELESS":
			c.Wired, c.WiredKnown = false, true
		}
		if c.Wired {
			c.SwMAC, c.SwPort = obs.NormMAC(r.LastUplinkMAC), r.SwPort
		} else {
			c.APMAC = obs.NormMAC(r.LastUplinkMAC)
		}
		out = append(out, c)
	}
	return out
}

type rawUniDev struct {
	// classic
	MAC     string `json:"mac"`
	IP      string `json:"ip"`
	Name    string `json:"name"`
	Model   string `json:"model"`
	Type    string `json:"type"`
	Version string `json:"version"`
	Uplink  *struct {
		UplinkMAC        string `json:"uplink_mac"`
		UplinkRemotePort int    `json:"uplink_remote_port"`
		PortIdx          int    `json:"port_idx"`
		Type             string `json:"type"`
		// integration
		DeviceID string `json:"deviceId"`
	} `json:"uplink"`
	LastUplink *struct {
		UplinkMAC        string `json:"uplink_mac"`
		UplinkRemotePort int    `json:"uplink_remote_port"`
	} `json:"last_uplink"`
	// integration
	ID              string          `json:"id"`
	MACAddress      string          `json:"macAddress"`
	IPAddress       string          `json:"ipAddress"`
	FirmwareVersion string          `json:"firmwareVersion"`
	Features        json.RawMessage `json:"features"`
	// classic: int (0 = disconnected); integration: "ONLINE", "OFFLINE", ...
	State json.RawMessage `json:"state"`
}

type rawUniClient struct {
	// classic
	MAC       string `json:"mac"`
	IP        string `json:"ip"`
	Name      string `json:"name"`
	Hostname  string `json:"hostname"`
	OUI       string `json:"oui"`
	IsWired   *bool  `json:"is_wired"`
	SwMAC     string `json:"sw_mac"`
	SwPort    int    `json:"sw_port"`
	APMAC     string `json:"ap_mac"`
	ESSID     string `json:"essid"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
	// integration
	Type           string `json:"type"`
	MACAddress     string `json:"macAddress"`
	IPAddress      string `json:"ipAddress"`
	UplinkDeviceID string `json:"uplinkDeviceId"`
}

func parseUniFi(u *obs.UniFi) ([]uniDev, []uniClient) {
	if u == nil {
		return nil, nil
	}
	var devs []uniDev
	for _, raw := range u.Devices {
		var r rawUniDev
		if json.Unmarshal(raw, &r) != nil {
			continue
		}
		d := uniDev{
			ID:      r.ID,
			MAC:     obs.NormMAC(first(r.MAC, r.MACAddress)),
			IP:      first(r.IP, r.IPAddress),
			Name:    r.Name,
			Model:   r.Model,
			Type:    r.Type,
			Version: first(r.Version, r.FirmwareVersion),
			Offline: uniOffline(r.State),
		}
		if r.Uplink != nil {
			d.UplinkMAC = obs.NormMAC(r.Uplink.UplinkMAC)
			d.UplinkRemotePort = r.Uplink.UplinkRemotePort
			d.LocalPort = r.Uplink.PortIdx
			d.UplinkWireless = r.Uplink.Type == "wireless"
			d.UplinkID = r.Uplink.DeviceID
		}
		if d.UplinkMAC == "" && r.LastUplink != nil {
			d.UplinkMAC = obs.NormMAC(r.LastUplink.UplinkMAC)
			d.UplinkRemotePort = r.LastUplink.UplinkRemotePort
		}
		if d.Type == "" {
			d.Type = uniTypeFromFeatures(r.Features, r.Model)
		}
		if d.MAC != "" {
			devs = append(devs, d)
		}
	}
	var clients []uniClient
	for _, raw := range u.Clients {
		var r rawUniClient
		if json.Unmarshal(raw, &r) != nil {
			continue
		}
		c := uniClient{
			MAC:      obs.NormMAC(first(r.MAC, r.MACAddress)),
			IP:       first(r.IP, r.IPAddress),
			Name:     r.Name,
			Hostname: r.Hostname,
			OUI:      r.OUI,
			SwMAC:    obs.NormMAC(r.SwMAC),
			SwPort:   r.SwPort,
			APMAC:    obs.NormMAC(r.APMAC),
			UplinkID: r.UplinkDeviceID,
			ESSID:    r.ESSID,

			FirstSeen: unixTime(r.FirstSeen),
			LastSeen:  unixTime(r.LastSeen),
		}
		switch {
		case r.IsWired != nil:
			c.Wired, c.WiredKnown = *r.IsWired, true
		case r.Type == "WIRED":
			c.Wired, c.WiredKnown = true, true
		case r.Type == "WIRELESS":
			c.Wired, c.WiredKnown = false, true
		}
		if c.MAC != "" {
			clients = append(clients, c)
		}
	}
	return devs, clients
}

// uniTypeFromFeatures maps integration-API features/models to classic types.
func uniTypeFromFeatures(raw json.RawMessage, model string) string {
	f := strings.ToLower(string(raw))
	switch {
	case strings.Contains(f, "accesspoint"):
		return "uap"
	case strings.Contains(f, "switching"):
		return "usw"
	}
	return uniTypeFromModel(model)
}

func uniTypeFromModel(model string) string {
	m := strings.ToUpper(model)
	switch {
	case strings.HasPrefix(m, "UDM"), strings.HasPrefix(m, "UXG"), strings.HasPrefix(m, "UCG"),
		strings.HasPrefix(m, "USG"), strings.HasPrefix(m, "UGW"), strings.HasPrefix(m, "UDR"):
		return "ugw"
	case strings.HasPrefix(m, "US"), strings.HasPrefix(m, "USW"):
		return "usw"
	case strings.HasPrefix(m, "U"):
		return "uap"
	}
	return ""
}

func first(vals ...string) string {
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// uniOffline reads a device state from either API flavour. Anything other
// than an explicit "disconnected" (upgrading, provisioning, ...) is on.
func uniOffline(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" { // null would decode as 0
		return false
	}
	var n int
	if json.Unmarshal(raw, &n) == nil {
		return n == 0
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.EqualFold(s, "offline") || strings.EqualFold(s, "disconnected")
	}
	return false
}
