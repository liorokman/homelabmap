package topo

import (
	"encoding/json"
	"strings"

	"github.com/liorokman/homelabmap/internal/obs"
)

// uniDev is a UniFi device normalised from either API flavour.
type uniDev struct {
	ID, MAC, IP, Name, Model, Type, Version string
	UplinkMAC, UplinkID                     string
	UplinkRemotePort, LocalPort             int
	UplinkWireless                          bool
}

// uniClient is a UniFi client normalised from either API flavour.
type uniClient struct {
	MAC, IP, Name, Hostname, OUI string
	Wired, WiredKnown            bool
	SwMAC                        string
	SwPort                       int
	APMAC, UplinkID, ESSID       string
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
}

type rawUniClient struct {
	// classic
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	OUI      string `json:"oui"`
	IsWired  *bool  `json:"is_wired"`
	SwMAC    string `json:"sw_mac"`
	SwPort   int    `json:"sw_port"`
	APMAC    string `json:"ap_mac"`
	ESSID    string `json:"essid"`
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
