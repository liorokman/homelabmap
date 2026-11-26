// Package obs defines the wire format between the scanner and the web frontend.
//
// The scanner only observes: it reports what each source said, as close to the
// source as practical. All interpretation (identity, topology, OS guessing)
// happens in the frontend, so stored observations can be re-interpreted when
// that logic improves.
package obs

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"time"
)

// Job is handed from the frontend to the scanner.
type Job struct {
	ID int64 `json:"id"`
	// OSScanMACs are known hosts whose OS fingerprint is missing or stale.
	OSScanMACs []string `json:"osScanMacs,omitempty"`
	// KnownMACs lets the scanner fingerprint never-seen hosts as well.
	KnownMACs []string `json:"knownMacs,omitempty"`
	// OSScanMax caps the number of hosts fingerprinted in one job.
	OSScanMax int `json:"osScanMax,omitempty"`
	// Probe, when set, asks for a quick look at just these devices instead
	// of a full scan (new MACs heard by the passive listener).
	Probe []ProbeTarget `json:"probe,omitempty"`
	// Settings is what to scan and with which credentials, as configured
	// on the web's Settings page when the job was handed out.
	Settings *ScannerSettings `json:"settings,omitempty"`
}

// ProbeTarget is one newly heard device.
type ProbeTarget struct {
	MAC string   `json:"mac"`
	IPs []string `json:"ips"`
}

// Sighting is one MAC/IP pair heard passively (ARP or IPv6 neighbour
// discovery). The scanner forwards these as they happen.
type Sighting struct {
	MAC string    `json:"mac"`
	IP  string    `json:"ip"`
	Via string    `json:"via"` // "arp" | "ndp"
	At  time.Time `json:"at"`
}

// Sightings is the body of POST /agent/v1/sightings.
type Sightings struct {
	Sightings []Sighting `json:"sightings"`
}

// Result is posted by the scanner when a job is finished.
type Result struct {
	JobID      int64     `json:"jobId"`
	Scanner    string    `json:"scanner"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	Subnets    []string  `json:"subnets"`

	Self    Self              `json:"self"`
	Sweep   []SweepHost       `json:"sweep"`
	SNMP    []SNMPDevice      `json:"snmp"`
	UniFi   UniFiList         `json:"unifi,omitempty"`
	PVE     *PVE              `json:"pve,omitempty"`
	OSScans []OSScan          `json:"osScans,omitempty"`
	SSDP    []SSDPDevice      `json:"ssdp,omitempty"`
	Cosmos  CosmosList        `json:"cosmos,omitempty"`
	DNS     map[string]string `json:"dns,omitempty"` // IP -> PTR name
	// Errors are non-fatal collector problems, shown in the UI.
	Errors []string `json:"errors,omitempty"`
	// Probe marks a probe result: it covers only Job.Probe's devices and
	// is merged into the latest full scan by the frontend.
	Probe bool `json:"probe,omitempty"`
}

// Self describes the scanner host, which nmap cannot see a MAC for.
type Self struct {
	Hostname   string      `json:"hostname"`
	Interfaces []SelfIface `json:"interfaces"`
}

type SelfIface struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac"`
	IPs  []string `json:"ips"`
}

// SweepHost is one live host from the nmap ARP/ping sweep.
type SweepHost struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac,omitempty"`
	Vendor string `json:"vendor,omitempty"` // from nmap's OUI database
}

// SNMPDevice is everything read from one SNMP agent.
type SNMPDevice struct {
	IP          string `json:"ip"`
	SysName     string `json:"sysName"`
	SysDescr    string `json:"sysDescr"`
	SysObjectID string `json:"sysObjectId"`
	Forwarding  bool   `json:"forwarding"` // ipForwarding == 1
	IsPrinter   bool   `json:"isPrinter"`  // Printer-MIB present
	BridgeMAC   string `json:"bridgeMac,omitempty"`

	LLDPChassisID string `json:"lldpChassisId,omitempty"`

	Interfaces []Interface     `json:"interfaces,omitempty"`
	LLDPLocal  []LLDPLocalPort `json:"lldpLocal,omitempty"`
	LLDP       []LLDPNeighbor  `json:"lldp,omitempty"`
	CDP        []CDPNeighbor   `json:"cdp,omitempty"`
	FDB        []FDBEntry      `json:"fdb,omitempty"`
	ARP        []ARPEntry      `json:"arp,omitempty"`
	Errors     []string        `json:"errors,omitempty"`
}

type Interface struct {
	Index     int    `json:"index"`
	Name      string `json:"name,omitempty"`
	Descr     string `json:"descr,omitempty"`
	Alias     string `json:"alias,omitempty"`
	Type      int    `json:"type,omitempty"`
	MAC       string `json:"mac,omitempty"`
	Up        bool   `json:"up"`
	SpeedMbps uint   `json:"speedMbps,omitempty"`
	// AggIndex is the ifIndex of the LAG this port belongs to, if any.
	AggIndex int `json:"aggIndex,omitempty"`
}

type LLDPLocalPort struct {
	Num       int    `json:"num"`
	IDSubtype int    `json:"idSubtype"`
	ID        string `json:"id"`
	Desc      string `json:"desc,omitempty"`
}

type LLDPNeighbor struct {
	LocalPortNum   int      `json:"localPort"`
	ChassisSubtype int      `json:"chassisSubtype"`
	ChassisID      string   `json:"chassisId"`
	PortSubtype    int      `json:"portSubtype"`
	PortID         string   `json:"portId"`
	PortDesc       string   `json:"portDesc,omitempty"`
	SysName        string   `json:"sysName,omitempty"`
	SysDesc        string   `json:"sysDesc,omitempty"`
	Caps           []string `json:"caps,omitempty"`
	// MgmtAddrs holds every address the agent reported, valid or not.
	MgmtAddrs []string `json:"mgmtAddrs,omitempty"`
}

type CDPNeighbor struct {
	IfIndex  int    `json:"ifIndex"`
	DeviceID string `json:"deviceId"`
	Address  string `json:"address,omitempty"`
	Port     string `json:"port,omitempty"`
	Platform string `json:"platform,omitempty"`
}

type FDBEntry struct {
	MAC     string `json:"mac"`
	IfIndex int    `json:"ifIndex"`
	VLAN    int    `json:"vlan,omitempty"`
}

type ARPEntry struct {
	IP      string `json:"ip"`
	MAC     string `json:"mac"`
	IfIndex int    `json:"ifIndex,omitempty"`
}

// UniFi carries raw controller JSON; the frontend parses both API flavours.
type UniFi struct {
	// Flavor is "legacy" (/proxy/network/api) or "integration" (/integration/v1).
	Flavor  string            `json:"flavor"`
	Devices []json.RawMessage `json:"devices"`
	Clients []json.RawMessage `json:"clients"`
	// Known is every client the controller remembers, with the aliases
	// set in UniFi (classic API rest/user).
	Known []json.RawMessage `json:"known,omitempty"`
	// History is clients seen recently but not connected now (v2 API).
	History []json.RawMessage `json:"history,omitempty"`
}

// UniFiList is one entry per UniFi controller. Results stored before
// several controllers were supported hold a single object; it decodes as a
// list of one.
type UniFiList []UniFi

func (l *UniFiList) UnmarshalJSON(b []byte) error { return decodeOneOrMany(b, (*[]UniFi)(l)) }

// CosmosList is one entry per Cosmos server (a single object in older
// stored results).
type CosmosList []Cosmos

func (l *CosmosList) UnmarshalJSON(b []byte) error { return decodeOneOrMany(b, (*[]Cosmos)(l)) }

// decodeOneOrMany decodes a JSON array, or a lone object as a list of one.
func decodeOneOrMany[T any](b []byte, out *[]T) error {
	b = bytes.TrimSpace(b)
	switch {
	case bytes.Equal(b, []byte("null")):
		*out = nil
		return nil
	case len(b) > 0 && b[0] == '{':
		var one T
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		*out = []T{one}
		return nil
	default:
		return json.Unmarshal(b, out)
	}
}

// Cosmos is a Cosmos server's containers and reverse-proxy routes. Only
// what the map needs is kept: no environment, commands or other config.
type Cosmos struct {
	URL        string            `json:"url"`
	HostIPs    []string          `json:"hostIps,omitempty"` // the Cosmos host's addresses
	Containers []CosmosContainer `json:"containers"`
	Routes     []CosmosRoute     `json:"routes,omitempty"`
}

type CosmosContainer struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Image       string       `json:"image"`
	State       string       `json:"state"`  // running, exited, ...
	Status      string       `json:"status"` // "Up 4 days"
	Created     time.Time    `json:"created,omitzero"`
	NetworkMode string       `json:"networkMode,omitempty"`
	Networks    []string     `json:"networks,omitempty"`
	Ports       []DockerPort `json:"ports,omitempty"`
	Stack       string       `json:"stack,omitempty"` // cosmos-stack or compose project
	StackMain   bool         `json:"stackMain,omitempty"`
}

type DockerPort struct {
	IP          string `json:"ip,omitempty"`
	PrivatePort int    `json:"privatePort"`
	PublicPort  int    `json:"publicPort,omitempty"`
	Type        string `json:"type"`
}

type CosmosRoute struct {
	Name       string `json:"name"`
	Host       string `json:"host,omitempty"`
	PathPrefix string `json:"pathPrefix,omitempty"`
	Target     string `json:"target"`
	Mode       string `json:"mode"`
	AuthOnly   bool   `json:"authOnly,omitempty"`
	Disabled   bool   `json:"disabled,omitempty"`
}

// SSDPDevice is a UPnP device that answered an SSDP search, with its
// description document if it could be fetched.
type SSDPDevice struct {
	IP               string   `json:"ip"`
	Server           string   `json:"server,omitempty"`
	Location         string   `json:"location,omitempty"`
	Types            []string `json:"types,omitempty"` // ST values answered
	DeviceType       string   `json:"deviceType,omitempty"`
	FriendlyName     string   `json:"friendlyName,omitempty"`
	Manufacturer     string   `json:"manufacturer,omitempty"`
	ModelName        string   `json:"modelName,omitempty"`
	ModelNumber      string   `json:"modelNumber,omitempty"`
	ModelDescription string   `json:"modelDescription,omitempty"`
}

type PVE struct {
	Nodes []PVENode `json:"nodes"`
}

type PVENode struct {
	Name   string     `json:"name"`
	IP     string     `json:"ip,omitempty"`
	Status string     `json:"status,omitempty"`
	Guests []PVEGuest `json:"guests"`
}

type PVEGuest struct {
	VMID   int      `json:"vmid"`
	Name   string   `json:"name"`
	Type   string   `json:"type"` // qemu | lxc
	Status string   `json:"status"`
	OSType string   `json:"osType,omitempty"`
	NICs   []PVENIC `json:"nics,omitempty"`
	IPs    []string `json:"ips,omitempty"`
}

type PVENIC struct {
	Name   string `json:"name"`
	MAC    string `json:"mac"`
	Bridge string `json:"bridge,omitempty"`
}

// OSScan is one nmap OS-detection result.
type OSScan struct {
	IP        string    `json:"ip"`
	MAC       string    `json:"mac"`
	Matched   bool      `json:"matched"`
	Name      string    `json:"name,omitempty"`
	Accuracy  int       `json:"accuracy,omitempty"`
	Vendor    string    `json:"vendor,omitempty"`
	Family    string    `json:"family,omitempty"`
	Gen       string    `json:"gen,omitempty"`
	Type      string    `json:"type,omitempty"`
	OpenPorts []string  `json:"openPorts,omitempty"` // "22/tcp ssh"
	ScannedAt time.Time `json:"scannedAt"`
}

// NormMAC returns a lowercase colon-separated MAC, or "" if s is not one.
func NormMAC(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	hw, err := net.ParseMAC(s)
	if err != nil {
		// Accept bare 12-hex-digit forms such as "001122aabbcc".
		if len(s) == 12 {
			hw, err = net.ParseMAC(s[0:2] + ":" + s[2:4] + ":" + s[4:6] + ":" + s[6:8] + ":" + s[8:10] + ":" + s[10:12])
		}
		if err != nil {
			return ""
		}
	}
	if len(hw) != 6 {
		return ""
	}
	if isZeroOrBroadcast(hw) {
		return ""
	}
	return hw.String()
}

// MACFromBytes formats 6 raw bytes as a MAC, or "" otherwise.
func MACFromBytes(b []byte) string {
	if len(b) != 6 || isZeroOrBroadcast(b) {
		return ""
	}
	return net.HardwareAddr(b).String()
}

func isZeroOrBroadcast(b []byte) bool {
	zero, ff := true, true
	for _, x := range b {
		if x != 0 {
			zero = false
		}
		if x != 0xff {
			ff = false
		}
	}
	return zero || ff
}

// IsLocallyAdministered reports a randomized/private MAC (phones, VMs).
func IsLocallyAdministered(mac string) bool {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) == 0 {
		return false
	}
	return hw[0]&0x02 != 0
}

// IsMulticast reports a group MAC, which never identifies a host.
func IsMulticast(mac string) bool {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) == 0 {
		return false
	}
	return hw[0]&0x01 != 0
}
