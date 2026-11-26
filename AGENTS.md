# AGENTS.md

Guidance for AI coding agents working on homelabmap. Read `README.md` for
what the app does and how it is configured, and `SECURITY.md` for the
security model; this file covers how to work on the code.

## Project

- Go module `github.com/liorokman/homelabmap`; the Go version is in `go.mod`.
- Environment variables use the prefix `HOMELABMAP_`.
- Two images from one `Dockerfile` (`--target web`, `--target scanner`) and
  three binaries:

| Binary | Role |
|---|---|
| `cmd/homelabmap-web` | Scheduler, storage, topology inference, UI, login, scanner API |
| `cmd/homelabmap-scanner` | Collectors; listens on no port and long-polls the web for jobs |
| `cmd/homelabmap-listen` | Passive ARP/NDP listener run by the scanner (raw sockets only) |

| Package | Contents |
|---|---|
| `internal/obs` | Wire format between scanner and web (observations, settings) |
| `internal/scanner` | Collectors: nmap, SNMP, UniFi, Proxmox, Cosmos, SSDP, DNS; probes; passive watch |
| `internal/sniff` | ARP/NDP frame parsing, AF_PACKET listener |
| `internal/topo` | Inference: entities by MAC, links, placement, OS, history |
| `internal/store` | SQLite (pure Go, no cgo) with ordered migrations |
| `internal/web` | HTTP, OIDC + PKCE, password login, scheduler, scanner API, Settings API |
| `internal/web/static` | Embedded UI: plain JS/CSS/HTML, Cytoscape.js vendored under `vendor/` |
| `tools/demo` | Fictional demo network for running the UI without scanning |
| `tools/genicons.py` | Generates `internal/web/static/icons.js` from pinned icon packages |
| `deploy/` | Cosmos-Compose template and `render.py` |

## Commands

Run everything through [Task](https://taskfile.dev):

| Command | Does |
|---|---|
| `task check` | `go vet`, golangci-lint and tests with coverage. **Must pass before you call work done.** |
| `task test` | `go test -race ./...` |
| `task cover` | Coverage of `internal/...`; fails below 80% |
| `task lint` / `task lint:install` | golangci-lint, at the version pinned in `Taskfile.yml` |
| `task build` | Static binaries (`CGO_ENABLED=0`) into `out/` |
| `task demo` | UI on demo data at http://127.0.0.1:8090 (`go run ./tools/demo -no-auth` skips login) |
| `task images` | Both images for this machine |
| `task render` | `deploy/cosmos-compose.rendered.json` from `.env` |

`task push` publishes images to a registry and `task render` output can be
deployed to a server. Both reach outside this machine: don't run them, or
deploy anything, unless you've been asked to.

## Releasing a new version

Before a release, take up-to-date screenshots and replace
`docs/screenshot-light.png` and `docs/screenshot-dark.png`, which the README
shows. Take them **only with demo data**: run `go run ./tools/demo -no-auth`
and capture the map in the light and the dark theme, at the size of the current
images (1600 × 1000). Never take them from a
real deployment.

## Code conventions

- Lint config is `.golangci.yml` (standard set plus `gosec`, `errorlint`,
  `bodyclose`, …). Fix findings rather than adding `//nolint`; if a
  suppression is truly needed, give the reason on the same line.
- Wrap errors with `%w` and context (`fmt.Errorf("migrating %s: %w", …)`).
- **Identity is the MAC address, never the IP.** Keep it that way in `topo`.
- **Schema changes** go as a new entry appended to `migrations` in
  `internal/store/store.go`. Never edit or reorder an existing migration.
- Raw observations are stored with each scan and maps are rebuilt from them,
  so `obs` changes must keep reading older stored data.
- Keep the security properties in `SECURITY.md` intact: the scanner never
  listens; the web and scanner run as non-root; secrets are write-only in the
  UI and encrypted at rest; the strict CSP allows only the app's own scripts
  (no inline scripts, no CDNs). If a change affects any of these, update
  `SECURITY.md`.
- User-facing changes (settings, variables, behaviour) update `README.md`
  and, for variables, `.env.example`.
- Don't edit files under `internal/web/static/vendor/` or the generated
  `icons.js` by hand.

## Tests

- New code needs tests; `internal/...` coverage must stay at or above 80%.
- Run with the race detector (`task test`).
- Tests that touch real systems are **opt-in** and skip unless their
  variable is set (`HOMELABMAP_REAL_RESULT`, `HOMELABMAP_LIVE_COSMOS_OUT`,
  `HOMELABMAP_LIVE_SSDP`). Follow that pattern for any new live test, and
  never commit their output.

## Privacy: this repository is public

**No data from a real environment may enter git:** not in code, tests,
fixtures, docs, screenshots or commit messages. That includes hostnames and
domains, IP addresses and subnets, MAC addresses, device, room and person
names, models and firmware versions of real gear, time zones, the identity
provider in use, and container names.

- Real values belong only in the gitignored `.env`. Templates use
  `<PLACEHOLDER>`s, and `render.py` fails on any left unset.
- Fixtures and examples use documentation or made-up values: `example.net`,
  `home.arpa`, `10.20.20.0/22`, `192.0.2.0/24`, `2001:db8::/32`, invented
  MACs. Never build them from scan output, and don't mirror a real network's
  layout or port assignments.
- Before committing, review the diff for anything copied from a real scan,
  log or `.env`.

## Scope and commits

- Build what was asked. Don't add CI workflows, Dependabot, multi-arch
  builds or other tooling on your own initiative; suggest them instead.
- Commit only when asked. Use a short imperative subject, optionally
  prefixed with the area (`topo: …`, `task push: …`), and a body that
  explains what changed and why.
