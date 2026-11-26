# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/liorokman/homelabmap/security/advisories/new),
not in public issues. Fixes go into the latest release; there are no
long-term support branches.

## Security model

homelabmap is two containers with deliberately different exposure.

| | `homelabmap-scanner` | `homelabmap-web` |
|---|---|---|
| Network | **host network** (it needs the LAN segment) | ordinary container network |
| Listens on | **nothing** | UI on `:8080`; scanner API on `:8081` |
| Privileges | non-root; `CAP_NET_RAW` + `CAP_NET_ADMIN` only, held as file capabilities by `nmap` and by `homelabmap-listen` (raw sockets only) | non-root, no capabilities |
| Holds | the current job's settings, in memory only | the settings, with SNMP, UniFi, Proxmox and Cosmos credentials encrypted; OIDC client or the local account's password hash; session store; scan history |

* **The scanner never accepts connections.** It long-polls the web
  container for work and posts results back, authenticated with a shared
  bearer token (`HOMELABMAP_AGENT_TOKEN`, at least 32 characters, compared in
  constant time).
* **Keep the scanner API on loopback.** Publish the web container's `:8081`
  only as `127.0.0.1:8097` (as `compose.yaml` does). Anyone who can reach it
  with the token can feed the map false data.
* **The UI requires login.** OpenID Connect authorization code flow with PKCE
  (S256), state and nonce checks, and optional group restriction.
* **Without OIDC, one local account.** It is created on first run, which
  requires a one-time setup code printed in the web container's log, so a
  visitor who reaches the page first can't claim it. The password (at least
  12 characters) is stored as an Argon2id hash (64 MiB, 2 passes, random
  salt). Unknown usernames take as long to reject as wrong passwords. After
  10 failed attempts within 15 minutes, sign-in is refused until the window
  passes; this counts globally, because behind a reverse proxy every client
  shares the proxy's address. Changing the password requires the current
  one and signs out the account's other sessions.
* **Password reset needs host access, not email.** `homelabmap-web
  reset-code`, run in the web container, prints a one-time code (60 bits,
  valid 15 minutes, only the newest one works, stored as a hash) that the
  sign-in page's "Forgot password?" form accepts. Wrong codes count as
  failed sign-ins. A reset signs out every session of the account.
* **Sessions** (both kinds of login) are random tokens stored hashed;
  cookies are `__Host-`, `HttpOnly`, `Secure`, `SameSite=Lax`. State-changing requests are refused unless
  same-origin (`Sec-Fetch-Site`/`Origin`). A strict Content-Security-Policy
  allows only the app's own scripts. `HOMELABMAP_INSECURE_NO_AUTH` exists for
  local development and is refused unless the UI listens on loopback.
* **Put the UI behind HTTPS.** Run a reverse proxy in front of `:8080`; the
  login refuses a non-https public URL.

## Settings and stored credentials

The SNMP, Proxmox, UniFi and Cosmos credentials are entered on the Settings
page and stored by the web container, which hands them to the scanner with
each job over the loopback scanner API. **This is a trade-off:** the web
container faces your reverse proxy, and it now holds the credentials the
scanner uses. What limits the damage:

* **Encrypted at rest.** Each secret is encrypted with AES-256-GCM under a
  key derived (HKDF-SHA256) from `HOMELABMAP_AGENT_TOKEN`, and bound to its
  field, so a copy of the database or a backup reveals nothing without the
  token, and ciphertexts can't be moved between fields. Rotating the token
  makes them unreadable; the Settings page marks them for re-entry.
* **Write-only in the browser.** The API never returns a secret: saved
  secrets come back as a placeholder, which, sent back, keeps the stored
  value. A page can replace or remove a secret, never read it.
* **Administrators only.** With OIDC, only members of
  `HOMELABMAP_OIDC_ADMIN_GROUPS` can open the Settings page (every user who
  can sign in, if it is empty). The password account always can. Changes
  require the same-origin checks as every other change, and two editors
  can't silently overwrite each other (a stale save is refused).
* **Logged.** Every change is logged with who made it.

Read-only credentials (below) keep a leak from becoming more than that.

## Credentials: least privilege

Give the scanner read-only credentials, and nothing more:

* **SNMP:** a read-only community or SNMPv3 user.
* **Proxmox:** an API token for a user with the `PVEAuditor` role (see the
  README).
* **UniFi:** an API key; the scanner only reads.
* **Cosmos:** an API token with *only* "Resources Read" and "Configuration
  Read", restricted to the scanner host's IP. Configuration Read lets the
  token holder read Cosmos's whole configuration, including its TLS and CA
  private keys; homelabmap keeps only the proxy routes, but protect the token
  accordingly, or omit Configuration Read (containers are then shown without
  links).

The agent token and the OIDC client secret live in `.env` (never in images
or git) and reach the containers as environment variables. Collector errors
redact URL query strings.

## What the scanner does on your network

* An nmap ping/ARP sweep of `HOMELABMAP_SUBNETS` every scan interval, and nmap
  OS detection (`-O`, top 200 ports) of hosts whose OS is unknown, at most
  once a week per device and capped per scan. Intrusion detection systems
  may notice this.
* SNMP reads of every host that answers.
* An SSDP search on the LAN. UPnP description documents are fetched only
  from the address that answered, over plain HTTP(S), without following
  redirects, and size-limited.
* Passive listening for ARP and IPv6 neighbour discovery (no packets sent).

homelabmap sends no telemetry and contacts nothing outside your network,
other than the identity provider you configure.
