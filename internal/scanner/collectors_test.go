package scanner

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/liorokman/homelabmap/internal/obs"
)

// All data below is fictional (TEST-NET addresses, documentation MACs).

const fakeSweepXML = `<?xml version="1.0"?><nmaprun>
<host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><address addr="00:00:5E:00:53:10" addrtype="mac" vendor="IANA"/></host>
<host><status state="up"/><address addr="192.0.2.30" addrtype="ipv4"/><address addr="00:00:5E:00:53:30" addrtype="mac" vendor="Example Corp"/></host>
<host><status state="down"/><address addr="192.0.2.31" addrtype="ipv4"/></host>
<host><status state="up"/><address addr="00:00:5E:00:53:32" addrtype="mac"/></host>
</nmaprun>`

const fakeOSXML = `<?xml version="1.0"?><nmaprun>
<host><status state="up"/><address addr="192.0.2.30" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="80"><state state="closed"/></port>
<port protocol="tcp" portid="9999"><state state="open"/></port></ports>
<os><osmatch name="Linux 6.1" accuracy="96"><osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="6.X" accuracy="96"/></osmatch></os></host>
<host><status state="up"/><address addr="192.0.2.77" addrtype="ipv4"/></host>
</nmaprun>`

// fakeNmap writes an executable that prints sweep or OS-scan XML.
func fakeNmap(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sweep.xml"), []byte(fakeSweepXML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "os.xml"), []byte(fakeOSXML), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncase \" $* \" in *\" -O \"*) cat " + dir + "/os.xml;; *\" fail \"*) echo boom >&2; exit 3;; *) cat " + dir + "/sweep.xml;; esac\n"
	p := filepath.Join(dir, "nmap")
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil { //nolint:gosec // test executable
		t.Fatal(err)
	}
	return p
}

func TestNmap(t *testing.T) {
	cfg := Config{NmapPath: fakeNmap(t), NmapPrivileged: true}
	ctx := context.Background()
	hosts, err := nmapSweep(ctx, cfg, []string{"192.0.2.0/24"})
	if err != nil || len(hosts) != 2 || hosts[0].MAC != "00:00:5e:00:53:10" || hosts[1].Vendor != "Example Corp" {
		t.Fatalf("sweep: %+v %v", hosts, err)
	}
	scans, err := nmapOSScan(ctx, cfg, []obs.SweepHost{hosts[1]})
	if err != nil || len(scans) != 1 {
		t.Fatalf("os scan: %+v %v", scans, err)
	}
	s := scans[0]
	if !s.Matched || s.Name != "Linux 6.1" || s.Accuracy != 96 || s.Family != "Linux" ||
		!slices.Equal(s.OpenPorts, []string{"22/tcp ssh", "9999/tcp"}) {
		t.Errorf("os scan result: %+v", s)
	}
	if _, err := nmapSweep(ctx, cfg, []string{"fail"}); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("nmap failure: %v", err)
	}
	if _, err := nmapSweep(ctx, Config{NmapPath: filepath.Join(t.TempDir(), "missing")}, nil); err == nil {
		t.Error("missing nmap accepted")
	}
	if os.Geteuid() != 0 {
		if _, err := nmapOSScan(ctx, Config{NmapPath: cfg.NmapPath}, hosts); err == nil {
			t.Error("unprivileged OS scan accepted")
		}
	}
}

// lanServices fakes the UniFi controller (classic API), Proxmox and Cosmos.
func lanServices(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	j := func(v any) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(v) }
	}
	ok := func(data any) any { return map[string]any{"meta": map[string]any{"rc": "ok"}, "data": data} }
	mux.HandleFunc("GET /proxy/network/api/s/default/stat/device", j(ok([]any{
		map[string]any{"mac": "00:00:5e:00:53:20", "ip": "192.0.2.20", "name": "ap1", "type": "uap", "model": "U6P"}})))
	mux.HandleFunc("GET /proxy/network/api/s/default/stat/sta", j(ok([]any{
		map[string]any{"mac": "00:00:5e:00:53:30", "ip": "192.0.2.30", "hostname": "laptop", "is_wired": false, "ap_mac": "00:00:5e:00:53:20"}})))
	mux.HandleFunc("GET /proxy/network/api/s/default/rest/user", j(ok([]any{map[string]any{"mac": "00:00:5e:00:53:30", "name": "Work laptop"}})))
	mux.HandleFunc("GET /proxy/network/v2/api/site/default/clients/history", j([]any{map[string]any{"mac": "00:00:5e:00:53:40", "hostname": "tablet"}}))

	pve := func(path string, data any) { mux.HandleFunc("GET /api2/json"+path, j(map[string]any{"data": data})) }
	pve("/cluster/status", []any{
		map[string]any{"type": "cluster", "name": "lab"},
		map[string]any{"type": "node", "name": "hv1", "ip": "192.0.2.2", "online": 1},
		map[string]any{"type": "node", "name": "hv2", "ip": "192.0.2.3", "online": 0},
	})
	pve("/nodes/hv1/qemu", []any{map[string]any{"vmid": 100, "name": "apps", "status": "running"}, map[string]any{"vmid": "102", "status": "stopped"}})
	pve("/nodes/hv1/lxc", []any{map[string]any{"vmid": 101, "name": "dns", "status": "running"}})
	pve("/nodes/hv1/qemu/100/config", map[string]any{"ostype": "l26", "net0": "virtio=BC:24:11:00:00:64,bridge=vmbr0"})
	pve("/nodes/hv1/qemu/102/config", map[string]any{"ostype": "win11", "hostname": "desk"})
	pve("/nodes/hv1/lxc/101/config", map[string]any{"ostype": "debian", "net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:65,ip=dhcp"})
	pve("/nodes/hv1/qemu/100/agent/network-get-interfaces", map[string]any{"result": []any{
		map[string]any{"name": "lo", "ip-addresses": []any{map[string]any{"ip-address": "127.0.0.1"}}},
		map[string]any{"name": "docker0", "ip-addresses": []any{map[string]any{"ip-address": "172.17.0.1"}}},
		map[string]any{"name": "eth0", "ip-addresses": []any{map[string]any{"ip-address": "192.0.2.100"}, map[string]any{"ip-address": "fe80::1"}}},
	}})
	pve("/nodes/hv1/lxc/101/interfaces", []any{map[string]any{"name": "lo", "inet": "127.0.0.1/8"}, map[string]any{"name": "eth0", "inet": "192.0.2.101/24"}})

	mux.HandleFunc("GET /cosmos/api/servapps", j(map[string]any{"status": "OK", "data": []any{
		map[string]any{"Id": "a1", "Names": []string{"/web"}, "Image": "example/web:1", "State": "running", "Status": "Up 1 hour",
			"Labels": map[string]string{"cosmos-stack": "site", "cosmos-stack-main": "web"}, "HostConfig": map[string]any{"NetworkMode": "bridge"}},
	}}))
	mux.HandleFunc("GET /cosmos/api/config", j(map[string]any{"data": map[string]any{"HTTPConfig": map[string]any{"ProxyConfig": map[string]any{
		"Routes": []any{map[string]any{"Name": "web", "UseHost": true, "Host": "web.example.net", "Target": "http://web:80", "Mode": "SERVAPP"}}}}}}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestUniFiClassic(t *testing.T) {
	srv := lanServices(t)
	u, err := unifiCollect(context.Background(), obs.UniFiTarget{URL: srv.URL, APIKey: "k", Site: "default", HistoryHours: 24})
	if err != nil || u.Flavor != "legacy" || len(u.Devices) != 1 || len(u.Clients) != 1 || len(u.Known) != 1 || len(u.History) != 1 {
		t.Fatalf("classic: %+v %v", u, err)
	}
}

func TestUniFiIntegrationFallback(t *testing.T) {
	mux := http.NewServeMux()
	j := func(v any) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(v) }
	}
	base := "/proxy/network/integration/v1"
	mux.HandleFunc("GET "+base+"/sites", j(map[string]any{"data": []any{map[string]any{"id": "s1", "internalReference": "default", "name": "Default"}}}))
	mux.HandleFunc("GET "+base+"/sites/s1/devices", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"totalCount": 2, "data": []any{map[string]any{"id": "d1"}, map[string]any{"id": "d2"}}})
	})
	mux.HandleFunc("GET "+base+"/sites/s1/devices/d1", j(map[string]any{"id": "d1", "macAddress": "00:00:5e:00:53:20", "features": []string{"accessPoint"}}))
	// d2 has no detail endpoint: the summary is kept.
	mux.HandleFunc("GET "+base+"/sites/s1/clients", func(w http.ResponseWriter, r *http.Request) {
		page := []any{map[string]any{"macAddress": "00:00:5e:00:53:30"}}
		if r.URL.Query().Get("offset") != "0" {
			page = []any{map[string]any{"macAddress": "00:00:5e:00:53:31"}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"totalCount": 2, "data": page})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, err := unifiCollect(context.Background(), obs.UniFiTarget{URL: srv.URL, APIKey: "k", Site: "default"})
	if err != nil || u.Flavor != "integration" || len(u.Devices) != 2 || len(u.Clients) != 2 {
		t.Fatalf("integration: %+v %v", u, err)
	}
	// Neither API: both errors are reported.
	if _, err := unifiCollect(context.Background(), obs.UniFiTarget{URL: srv.URL + "/elsewhere", Site: "default"}); err == nil ||
		!strings.Contains(err.Error(), "classic API") || !strings.Contains(err.Error(), "integration API") {
		t.Errorf("no API: %v", err)
	}
}

func TestPVECollect(t *testing.T) {
	srv := lanServices(t)
	p, err := pveCollect(context.Background(), obs.ProxmoxTarget{URL: srv.URL, TokenID: "u@pve!t", TokenSecret: "s"})
	if err != nil || len(p.Nodes) != 2 {
		t.Fatalf("pve: %+v %v", p, err)
	}
	hv1, hv2 := p.Nodes[0], p.Nodes[1]
	if hv1.Status != "online" || hv2.Status != "offline" || len(hv1.Guests) != 3 {
		t.Fatalf("nodes: %+v", p.Nodes)
	}
	vm, ct, off := hv1.Guests[0], hv1.Guests[1], hv1.Guests[2]
	if vm.Name != "apps" || vm.OSType != "l26" || !slices.Equal(vm.IPs, []string{"192.0.2.100"}) || len(vm.NICs) != 1 {
		t.Errorf("vm: %+v", vm)
	}
	if ct.Type != "lxc" || !slices.Equal(ct.IPs, []string{"192.0.2.101"}) || ct.NICs[0].MAC != "bc:24:11:00:00:65" {
		t.Errorf("container: %+v", ct)
	}
	if off.VMID != 102 || off.Name != "desk" || off.IPs != nil {
		t.Errorf("stopped vm: %+v", off)
	}
	if _, err := pveCollect(context.Background(), obs.ProxmoxTarget{URL: srv.URL + "/nope"}); err == nil {
		t.Error("bad URL accepted")
	}
}

func TestCosmosCollect(t *testing.T) {
	srv := lanServices(t)
	c, err := cosmosCollect(context.Background(), obs.CosmosTarget{URL: srv.URL, Token: "t"})
	if err != nil || len(c.Containers) != 1 || c.Containers[0].Stack != "site" || len(c.Routes) != 1 ||
		!slices.Contains(c.HostIPs, "127.0.0.1") {
		t.Fatalf("cosmos: %+v %v", c, err)
	}
	if _, err := cosmosCollect(context.Background(), obs.CosmosTarget{URL: srv.URL + "/nope", Token: "t"}); err == nil {
		t.Error("bad URL accepted")
	}
}

func testConfig(t *testing.T, srv *httptest.Server) Config {
	return Config{
		Subnets:  []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		NmapPath: fakeNmap(t), NmapPrivileged: true, OSScanMax: 5,
		SNMP:       SNMPConfig{Version: "2c", Community: "public", Concurrency: 4},
		UniFi:      []obs.UniFiTarget{{URL: srv.URL, APIKey: "k", Site: "default"}},
		PVE:        []obs.ProxmoxTarget{{URL: srv.URL, TokenID: "u@pve!t", TokenSecret: "s"}},
		Cosmos:     []obs.CosmosTarget{{URL: srv.URL, Token: "t"}},
		JobTimeout: time.Minute,
	}
}

func TestScanAndProbe(t *testing.T) {
	srv := lanServices(t)
	useAgents(t, map[string]*fakeAgent{"192.0.2.10": switchAgent()})
	cfg := testConfig(t, srv)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res := Scan(ctx, cfg, obs.Job{ID: 7, KnownMACs: []string{"00:00:5e:00:53:10"}}, log)
	if res.JobID != 7 || len(res.Sweep) != 2 || len(res.SNMP) != 1 || len(res.UniFi) != 1 || res.PVE == nil || len(res.Cosmos) != 1 {
		t.Fatalf("scan: %+v", res)
	}
	// Only the unknown host is fingerprinted.
	if len(res.OSScans) != 1 || res.OSScans[0].MAC != "00:00:5e:00:53:30" {
		t.Errorf("os scans: %+v", res.OSScans)
	}
	if res.FinishedAt.Before(res.StartedAt) || !strings.HasPrefix(res.Scanner, "homelabmap-scanner") {
		t.Errorf("header: %+v", res)
	}

	p := Probe(ctx, cfg, obs.Job{ID: 8, Probe: []obs.ProbeTarget{{MAC: "00:00:5e:00:53:30", IPs: []string{"192.0.2.30", "2001:db8::30"}}}}, log)
	if !p.Probe || p.JobID != 8 || len(p.Sweep) != 2 || len(p.OSScans) != 1 || len(p.UniFi) != 1 || p.PVE == nil || p.Cosmos != nil {
		t.Errorf("probe: %+v", p)
	}
}

// fakeServer is the web frontend's agent API, as the scanner sees it.
type fakeServer struct {
	mu        sync.Mutex
	jobs      []obs.Job
	results   []obs.Result
	sightings []obs.Sighting
	failPolls int
	settings  obs.ScannerSettings
	settingsN int
	legacy    []obs.LegacySettings
	imported  bool
	srv       *httptest.Server
}

func newFakeServer(t *testing.T) *fakeServer {
	f := &fakeServer{}
	mux := http.NewServeMux()
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer tok" {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /agent/v1/job", auth(func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.failPolls > 0 {
			f.failPolls--
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		if len(f.jobs) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(f.jobs[0])
		f.jobs = f.jobs[1:]
	}))
	mux.HandleFunc("POST /agent/v1/result", auth(func(w http.ResponseWriter, r *http.Request) {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, "gzip", http.StatusBadRequest)
			return
		}
		var res obs.Result
		if err := json.NewDecoder(zr).Decode(&res); err != nil {
			http.Error(w, "json", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.results = append(f.results, res)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("GET /agent/v1/settings", auth(func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.settingsN++
		_ = json.NewEncoder(w).Encode(f.settings)
	}))
	mux.HandleFunc("POST /agent/v1/legacy-settings", auth(func(w http.ResponseWriter, r *http.Request) {
		var l obs.LegacySettings
		_ = json.NewDecoder(r.Body).Decode(&l)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.legacy = append(f.legacy, l)
		_ = json.NewEncoder(w).Encode(map[string]bool{"imported": f.imported})
	}))
	mux.HandleFunc("POST /agent/v1/sightings", auth(func(w http.ResponseWriter, r *http.Request) {
		var body obs.Sightings
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.sightings = append(f.sightings, body.Sightings...)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeServer) count() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.results), len(f.sightings)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAgentRun(t *testing.T) {
	fs := newFakeServer(t)
	settings := &obs.ScannerSettings{Subnets: []string{"192.0.2.0/24"}, JobTimeoutSeconds: 60}
	fs.jobs = []obs.Job{
		{ID: 3, Settings: settings, Probe: []obs.ProbeTarget{{MAC: "00:00:5e:00:53:30", IPs: []string{"203.0.113.9"}}}},
		{ID: 4}, // from an older web: no settings
		{ID: 5, Settings: &obs.ScannerSettings{}},
	}
	cfg := Config{Server: fs.srv.URL, AgentToken: "tok"}
	a := NewAgent(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	waitFor(t, func() bool { n, _ := fs.count(); return n == 3 })
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("Run returned %v", err)
	}
	if fs.results[0].JobID != 3 || !fs.results[0].Probe || len(fs.results[0].Errors) != 0 {
		t.Errorf("posted %+v", fs.results[0])
	}
	if r := fs.results[1]; r.JobID != 4 || len(r.Errors) != 1 || !strings.Contains(r.Errors[0], "no settings") {
		t.Errorf("job without settings: %+v", r)
	}
	if r := fs.results[2]; len(r.Errors) != 1 || !strings.Contains(r.Errors[0], "no subnets") {
		t.Errorf("job without subnets: %+v", r)
	}

	// Wrong token: the poll fails with the status.
	bad := NewAgent(Config{Server: fs.srv.URL, AgentToken: "nope"}, a.log)
	if _, err := bad.poll(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("bad token poll: %v", err)
	}
	if err := bad.post(context.Background(), &obs.Result{}); err == nil {
		t.Error("bad token post accepted")
	}
	if err := bad.postSightings(context.Background(), []obs.Sighting{{MAC: "m"}}); err == nil {
		t.Error("bad token sightings accepted")
	}
}

func TestWatchForwardsSightings(t *testing.T) {
	fs := newFakeServer(t)
	dir := t.TempDir()
	listener := filepath.Join(dir, "listen")
	script := "#!/bin/sh\n" +
		`echo '{"mac":"00:00:5e:00:53:30","ip":"192.0.2.30","via":"arp","at":"2026-01-01T00:00:00Z"}'` + "\n" +
		`echo '{"mac":"00:00:5e:00:53:31","ip":"203.0.113.1","via":"arp"}'` + "\n" + // outside the subnets
		"echo 'not json'\nsleep 30\n"
	if err := os.WriteFile(listener, []byte(script), 0o700); err != nil { //nolint:gosec // test executable
		t.Fatal(err)
	}
	cfg := Config{Server: fs.srv.URL, AgentToken: "tok", ListenPath: listener,
		Subnets: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
	a := NewAgent(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	batch := make(chan obs.Sighting, 10)
	go a.forward(ctx, batch)
	go func() {
		_ = a.runListener(ctx, "eth-test", func(s obs.Sighting) {
			if keepSighting(cfg, map[string]bool{}, s) {
				batch <- s
			}
		})
	}()
	waitFor(t, func() bool { _, n := fs.count(); return n == 1 })
	cancel()
	if fs.sightings[0].IP != "192.0.2.30" {
		t.Errorf("forwarded %+v", fs.sightings)
	}

	// A listener that can't start is reported, not fatal.
	a.cfg.ListenPath = filepath.Join(dir, "missing")
	if err := a.runListener(context.Background(), "x", func(obs.Sighting) {}); err == nil {
		t.Error("missing listener accepted")
	}
}

func TestWatchWithoutLANInterface(t *testing.T) {
	a := NewAgent(Config{Subnets: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	done := make(chan struct{})
	go func() { a.Watch(context.Background()); close(done) }()
	select {
	case <-done: // returns at once: nothing to listen on
	case <-time.After(5 * time.Second):
		t.Fatal("Watch did not return without a LAN interface")
	}
}

func TestFetchDescription(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing.xml" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `<root><device><friendlyName>Media Box</friendlyName><manufacturer>Example</manufacturer><modelName>MB-1</modelName></device></root>`)
	}))
	defer srv.Close()
	d := &obs.SSDPDevice{Location: srv.URL + "/desc.xml"}
	fetchDescription(context.Background(), srv.Client(), d)
	if d.FriendlyName != "Media Box" || d.ModelName != "MB-1" {
		t.Errorf("description: %+v", d)
	}
	gone := &obs.SSDPDevice{Location: srv.URL + "/missing.xml"}
	fetchDescription(context.Background(), srv.Client(), gone)
	if gone.FriendlyName != "" {
		t.Errorf("404 parsed: %+v", gone)
	}
}

func TestHTTPClientAndRedaction(t *testing.T) {
	if c := httpClient(true); c.Transport.(*http.Transport).TLSClientConfig == nil {
		t.Error("insecure TLS not applied")
	}
	if got := redactURL("https://h/p?token=secret"); got != "https://h/p" {
		t.Errorf("redact: %q", got)
	}
}

func TestImportLegacy(t *testing.T) {
	cleanEnv(t)
	fs := newFakeServer(t)
	a := NewAgent(Config{Server: fs.srv.URL, AgentToken: "tok"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	a.importLegacy(context.Background()) // nothing set: nothing offered
	if len(fs.legacy) != 0 {
		t.Fatalf("offered an empty environment: %+v", fs.legacy)
	}
	t.Setenv("HOMELABMAP_SUBNETS", "192.0.2.0/24")
	t.Setenv("HOMELABMAP_SNMP_COMMUNITY", "x")
	for _, imported := range []bool{true, false} {
		fs.imported = imported
		a.importLegacy(context.Background())
	}
	if len(fs.legacy) != 2 || fs.legacy[0].Settings.SNMP.Default.Community != "x" || len(fs.legacy[0].Set) != 2 {
		t.Errorf("offered %+v", fs.legacy)
	}
	// An older web without the endpoint: given up at once.
	old := NewAgent(Config{Server: fs.srv.URL + "/old", AgentToken: "tok"}, a.log)
	done := make(chan struct{})
	go func() { old.importLegacy(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("importLegacy kept retrying a 404")
	}
}

func TestWatchLoopFollowsSettings(t *testing.T) {
	fs := newFakeServer(t)
	fs.settings = obs.ScannerSettings{Subnets: []string{"203.0.113.0/24"}, Passive: true} // no interface there
	a := NewAgent(Config{Server: fs.srv.URL, AgentToken: "tok", ListenPath: "/nonexistent"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	a.settingsEvery = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.WatchLoop(ctx); close(done) }()
	waitFor(t, func() bool { fs.mu.Lock(); defer fs.mu.Unlock(); return fs.settingsN >= 3 })
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("WatchLoop did not stop")
	}
}
