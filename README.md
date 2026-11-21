# homelabmap

A home network topology map: an hourly scan of the LAN, stored in SQLite, shown
as an interactive map with network gear, end devices (with OS icons), and VMs.

Built because SNMP-only discovery tools miss everything that isn't SNMP
gear, and trip over buggy SNMP agents.

## Architecture

Two containers on the Cosmos host, built from one Go module:

| | `homelabmap-scanner` | `homelabmap-web` |
|---|---|---|
| Job | Observe: nmap sweep + OS detection, SNMP, UniFi API, PVE API, SSDP/UPnP, reverse DNS, passive ARP/NDP listening | Everything else: schedule, store, infer topology, UI, OIDC login |
| Network | **host** (needs the LAN segment for ARP) | Cosmos bridge network, behind the Cosmos route |
| Listens | **nothing** | `:8080` UI (route target), `:8081` agent API (published on host **127.0.0.1:8097** only) |
| Privileges | non-root; `cap_drop ALL`, `cap_add NET_RAW, NET_ADMIN`; only `nmap` and `homelabmap-listen` (NET_RAW only) carry file caps | non-root, `cap_drop ALL` |
| Secrets | SNMP community, UniFi key, PVE token, agent token | OIDC client, agent token |

The scanner long-polls `GET /agent/v1/job` and posts results to
`POST /agent/v1/result` (bearer token, gzip JSON). Raw observations are
stored with each scan, so improved inference (`topo.Version`) rebuilds old
maps on startup without rescanning.

```
cmd/homelabmap-scanner   cmd/homelabmap-web   cmd/homelabmap-listen (raw-socket helper)
internal/obs         wire format between the two; probe merging
internal/scanner     collectors: nmap.go snmp.go unifi.go pve.go dns.go; probe.go watch.go
internal/sniff       ARP/NDP frame parsing, AF_PACKET listener
internal/topo        inference: entities by MAC, links, placement, OS id
internal/store       SQLite (modernc, pure Go), migrations via user_version
internal/web         HTTP, OIDC+PKCE, scheduler, agent API, embedded UI
```

## How the map is built

* **Identity is the MAC address**, never the IP: gear is on DHCP on purpose.
  Every source's records are merged by union-find over MACs.
* **Cables** come from LLDP and CDP (both ends merged), and UniFi uplinks
  (including wireless mesh). Port names are normalised (`gi19` ↔
  `GigabitEthernet19`) and LAG members are folded into their aggregate.
* **End devices** are placed on the switch port where their MAC is learned on
  a non-uplink port (the quietest port wins). Wi-Fi clients go under their AP
  (UniFi). MACs seen only on uplinks toward a device without a MAC table
  (USW-Lite-8, APs) are *inferred* to be behind it (dashed line). MACs on a
  hypervisor's port are its guests; PVE data makes that exact.
* **OS** is the strongest of: PVE guest type / UniFi device (95–90) > SNMP
  `sysDescr` (85) > SSDP/UPnP self-description for appliances (80: TVs,
  consoles, receivers, NAS) > nmap fingerprint (75/65/45 by accuracy) >
  hostname rules (50) > MAC vendor (30) > randomized Wi-Fi MAC (20). nmap
  runs only for hosts whose OS is still a guess, at most every 7 days per MAC.
* **Names**, best first: UniFi device name, the alias set in UniFi, PVE/SNMP
  names, the SSDP friendly name, DHCP hostname (UniFi), LLDP/CDP, reverse DNS.
* **Secondary MACs**: a MAC seen only in tables (never answering itself) that
  matches an answering device's burned-in MAC in the first five bytes, after
  clearing the local bit, belongs to it (bond members, bridge/bond-derived
  addresses: hv1's `da:3b:42:…`).
* **Rotating private MACs**: devices whose MACs are all private and that share
  a specific name are one device; earlier MACs are listed on it. Generic
  names ("iPhone") never link, nor do two such devices present at once.
* **Absent devices**: devices from the previous map that a scan didn't see,
  and named clients from the UniFi controller's 30-day history, stay on the
  map greyed out as "not seen since …" (VMs excepted: PVE lists those), until
  unseen for `HOMELABMAP_FORGET_AFTER` (30 days).

## New devices between scans

The scanner runs `homelabmap-listen` on the LAN interface: two AF_PACKET sockets,
one for ARP and one for IPv6 neighbour discovery (a BPF filter passes only
ICMPv6 types 133–136; all-multicast so solicited-node traffic is heard).
Each MAC/IP pair is reported at most every 10 minutes and forwarded to
`POST /agent/v1/sightings`.

The web records every sighting (the **Heard** table, IPv6 addresses and
"last seen" on devices). A MAC never seen before with an IPv4 address gets
a **probe**: a job for just that device (ARP ping, OS fingerprint, reverse
DNS, fresh UniFi and PVE data) whose result is merged into the latest full
scan, so it appears on the map within a minute. SNMP is left to the next
hourly scan, so a new *wired* device gets its switch port then; Wi-Fi
devices are placed right away from UniFi. Each MAC is probed once, at most
`HOMELABMAP_PROBE_MAX_PER_HOUR` (default 30) devices an hour; probes never delay
full scans.
IPv6-only devices are listed but not probed until they use IPv4.

Limits: the listener hears only what reaches the scanner host's port:
broadcast ARP from everyone, but replies and NDP between other hosts only
if switches flood them (MLD snooping can hide some NDP).

## Device quirks handled

* **Cisco small-business switches (some firmware):** `lldpRemManAddrTable` truncates or drops addresses
  (shown as a data-quality warning); Q-BRIDGE FDB index carries an extra length
  octet; LLDP advertises short port names. Its own nmap fingerprint says
  "Android", which SNMP outranks.
* **Some UniFi switches:** LLDP capabilities sent in the second of two octets.
* **Small UniFi switches and APs:** no MAC table over SNMP; placement is inferred or comes
  from UniFi.
* **Routers that speak CDP:** CDP can give the only usable address for a link
  whose LLDP address is broken.

## Configuration

`homelabmap/.env` (gitignored; template in `.env.example`) feeds
`deploy/render.py`, which renders `deploy/cosmos-compose.json` into
`deploy/cosmos-compose.rendered.json` (also gitignored). All variables are
`HOMELABMAP_*`; see `internal/scanner/config.go` and `internal/web/config.go`.
Passive listening is on by default (`HOMELABMAP_PASSIVE=false` turns it off);
`HOMELABMAP_PROBE_MAX_PER_HOUR=0` keeps listening but never probes. SSDP search
is on by default (`HOMELABMAP_SSDP=false`); description documents are fetched
only from the address that answered.

Sign-in: anonymous visitors get a landing page with a "Sign in with
`HOMELABMAP_OIDC_PROVIDER_NAME`" button. Sign-out ends the IdP session too and
asks it to return to `https://<host>/signin?signed-out=1`; add that URL to the
identity provider's redirect URIs for the round trip to complete.

## Development

```sh
task test                      # all unit tests (also run inside the image build)
task build                     # binaries in out/
HOMELABMAP_REAL_RESULT=result.json go test ./internal/topo -run Real -v   # inference on a real scan
```

Local end-to-end run without login (`HOMELABMAP_INSECURE_NO_AUTH=true` is refused
unless the UI listens on loopback):

```sh
HOMELABMAP_INSECURE_NO_AUTH=true HOMELABMAP_LISTEN=127.0.0.1:8090 HOMELABMAP_AGENT_LISTEN=127.0.0.1:8097 \
HOMELABMAP_PUBLIC_URL=http://127.0.0.1:8090 HOMELABMAP_DB=/tmp/homelabmap.db HOMELABMAP_AGENT_TOKEN=$TOKEN out/homelabmap-web &
HOMELABMAP_SERVER=http://127.0.0.1:8097 HOMELABMAP_AGENT_TOKEN=$TOKEN HOMELABMAP_SUBNETS=10.20.20.0/22 \
HOMELABMAP_SNMP_COMMUNITY=... out/homelabmap-scanner
```

Without root, nmap sees no MACs and can't fingerprint; run the scanner image
with `--network host --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN` for
the real thing (`-once` prints one result as JSON).

## Deploying

1. `task push VERSION=x.y.z` (builds with docker, pushes with `crane`; needs
   credentials for registry.example.net in `~/.docker/config.json`).
2. Set `HOMELABMAP_VERSION=x.y.z` in `.env`, then `task render`.
3. POST `deploy/cosmos-compose.rendered.json` to the Cosmos API
   (`/cosmos/api/docker-service`).

Third-party files: `internal/web/static/vendor/LICENSES.txt`; icons are
generated by `tools/genicons.py` from pinned `@tabler/icons` (MIT) and
`simple-icons` (CC0).
