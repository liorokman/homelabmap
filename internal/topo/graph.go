// Package topo turns raw scanner observations into a topology graph.
//
// Identity is by MAC address, never by IP: network gear is on DHCP on
// purpose, so IPs are only used within a single scan to connect sources.
package topo

import (
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
)

// Version changes whenever inference changes, so stored graphs get rebuilt.
const Version = 2

// Roles. Infra roles are drawn as network gear.
const (
	RoleRouter     = "router"
	RoleSwitch     = "switch"
	RoleAP         = "ap"
	RoleHypervisor = "hypervisor"
	RoleServer     = "server"
	RoleVM         = "vm"
	RoleContainer  = "container"
	RolePrinter    = "printer"
	RoleClient     = "client"
)

// Edge kinds.
const (
	KindInfra    = "infra"    // cable between two network devices
	KindWired    = "wired"    // cable to an end device
	KindWireless = "wireless" // Wi-Fi client or wireless mesh uplink
	KindVirtual  = "virtual"  // guest inside a hypervisor
	KindInferred = "inferred" // location deduced, not reported
	KindUnknown  = "unknown"  // seen on the network, location unknown
)

// Power states. Empty means unknown: the device was only seen in another
// device's tables (ARP, MAC table) and never answered itself.
const (
	PowerOn  = "on"
	PowerOff = "off"
)

type Graph struct {
	ScanID      int64     `json:"scanId"`
	Version     int       `json:"version"`
	ScanStarted time.Time `json:"scanStarted"`
	ScanEnded   time.Time `json:"scanEnded"`
	Nodes       []Node    `json:"nodes"`
	Edges       []Edge    `json:"edges"`
	Warnings    []string  `json:"warnings,omitempty"`
}

type Node struct {
	ID         string    `json:"id"`
	Label      string    `json:"label"`
	Role       string    `json:"role"`
	Infra      bool      `json:"infra"`
	Icon       string    `json:"icon"`
	OS         string    `json:"os,omitempty"`
	OSSource   string    `json:"osSource,omitempty"`
	IPs        []string  `json:"ips,omitempty"`
	MACs       []string  `json:"macs,omitempty"`
	DNS        []string  `json:"dns,omitempty"`
	Vendor     string    `json:"vendor,omitempty"`
	Model      string    `json:"model,omitempty"`
	Location   string    `json:"location,omitempty"`
	Connection string    `json:"connection,omitempty"`
	Parent     string    `json:"parent,omitempty"`
	Power      string    `json:"power,omitempty"`      // PowerOn, PowerOff or unknown
	PowerState string    `json:"powerState,omitempty"` // as reported, e.g. "stopped"
	OpenPorts  []string  `json:"openPorts,omitempty"`
	Sources    []string  `json:"sources"`
	FirstSeen  time.Time `json:"firstSeen,omitzero"`
	New        bool      `json:"new,omitempty"`
	Depth      int       `json:"depth"`
}

type Edge struct {
	ID         string   `json:"id"`
	Source     string   `json:"source"`
	Target     string   `json:"target"`
	Kind       string   `json:"kind"`
	SourcePort string   `json:"sourcePort,omitempty"`
	TargetPort string   `json:"targetPort,omitempty"`
	Sources    []string `json:"sources"`
}

// History is what the store remembers across scans.
type History struct {
	// OSScans holds the latest nmap result per MAC.
	OSScans map[string]obs.OSScan
	// FirstSeen per MAC.
	FirstSeen map[string]time.Time
	// Since is when the first scan was stored; nothing is "new" before
	// a day of history exists.
	Since time.Time
}

func isInfraRole(r string) bool { return r == RoleRouter || r == RoleSwitch || r == RoleAP }
