package obs

// ScannerSettings is the scanner's share of the web's Settings page: what
// to scan and the credentials to use. It travels only over the scanner API
// (loopback, bearer token), with secrets in clear text, because the
// scanner needs them to log in.
type ScannerSettings struct {
	Subnets []string     `json:"subnets"`
	SNMP    SNMPSettings `json:"snmp"`

	Proxmox []ProxmoxTarget `json:"proxmox,omitempty"`
	UniFi   []UniFiTarget   `json:"unifi,omitempty"`
	Cosmos  []CosmosTarget  `json:"cosmos,omitempty"`

	OSScanMax         int  `json:"osScanMax"`
	JobTimeoutSeconds int  `json:"jobTimeoutSeconds"`
	Passive           bool `json:"passive"`
	SSDP              bool `json:"ssdp"`
}

// SNMPSettings: the default credentials, per-host overrides, and tuning.
type SNMPSettings struct {
	// Default applies to hosts no override matches; nil means no SNMP
	// for them.
	Default *SNMPCredentials `json:"default,omitempty"`
	Hosts   []SNMPHost       `json:"hosts,omitempty"`
	// Seeds are extra IPs to query even if the sweep missed them.
	Seeds       []string `json:"seeds,omitempty"`
	TimeoutMS   int      `json:"timeoutMs"`
	Retries     int      `json:"retries"`
	Concurrency int      `json:"concurrency"`
}

// SNMPCredentials is a v2c community or a v3 (USM) user.
type SNMPCredentials struct {
	Version   string `json:"version"` // "2c" or "3"
	Community string `json:"community,omitempty"`
	User      string `json:"user,omitempty"`
	AuthProto string `json:"authProto,omitempty"` // SHA, SHA224, SHA256, SHA384, SHA512, MD5
	AuthPass  string `json:"authPass,omitempty"`
	PrivProto string `json:"privProto,omitempty"` // AES, AES192, AES256, DES
	PrivPass  string `json:"privPass,omitempty"`
}

// SNMPHost overrides the credentials for hosts matching Match: an IP
// address, a CIDR prefix or a hostname. An exact IP or hostname beats a
// prefix, and a longer prefix beats a shorter one.
type SNMPHost struct {
	Match       string          `json:"match"`
	Credentials SNMPCredentials `json:"credentials"`
}

// ProxmoxTarget is one Proxmox VE cluster (any of its nodes).
type ProxmoxTarget struct {
	URL         string `json:"url"`
	TokenID     string `json:"tokenId"` // user@realm!tokenid
	TokenSecret string `json:"tokenSecret"`
	InsecureTLS bool   `json:"insecureTls,omitempty"`
}

// UniFiTarget is one UniFi OS console.
type UniFiTarget struct {
	URL          string `json:"url"`
	APIKey       string `json:"apiKey"`
	Site         string `json:"site"`
	InsecureTLS  bool   `json:"insecureTls,omitempty"`
	HistoryHours int    `json:"historyHours"`
}

// CosmosTarget is one Cosmos server.
type CosmosTarget struct {
	URL         string `json:"url"`
	Token       string `json:"token"`
	InsecureTLS bool   `json:"insecureTls,omitempty"`
}

// LegacySettings is the body of POST /agent/v1/legacy-settings: what the
// scanner found in its own HOMELABMAP_* environment, which the web imports
// once into its settings.
type LegacySettings struct {
	Settings ScannerSettings `json:"settings"`
	// Set names the environment variables that were set.
	Set []string `json:"set"`
}
