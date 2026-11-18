# Go → Rust port

meshgate is being rewritten in Rust (`rust/`) next to the Go version (`go/`).
The Rust build replaces the Go one **in place**: same release file names,
same config and state files, same command line, same network protocols, so
every node switches by its normal update and keeps running.

## The release switch

Releases are the Rust build only (`make release` in `rust/`), under the
file names the Go build used, and only when the `rust` workflow passed on
that commit. Go nodes update to it by their normal update (`meshgate update`
or "update all"); both builds read the same files and speak the same
protocols, so a mesh can run Go and Rust nodes together while updating.
A node keeps its Go binary next to the new one as `meshgate.old`.

## The contract: what the Rust build must keep exactly

A node updated to Rust reads what Go wrote, and talks to Go nodes that have not
updated yet. Each item is defined by the Go code named.

| What | Defined in (go/) |
|---|---|
| Release assets `meshgate-{linux,freebsd}-{arch}`, `meshgate-windows-{arch}.zip`, `SHA256SUMS` | `Makefile`, `internal/update` |
| Command line: commands, flags (Go style: `-config x` and `--config x`), exit codes (3 = restart after update) | `cmd/meshgate` |
| Node config `node.json` (keys, ports, data dir, anchors) | `internal/config` |
| Replicated state `state.json` and its merge rules | `internal/store` |
| Records and their JSON (nodes, forwards, routes, ACLs, monitors, …) | `internal/model` |
| Join tokens (`mg1.…`) and the TLS join API with certificate pinning | `internal/join` |
| Mesh API between nodes: `/v1/ping`, `/v1/sync`, `/v1/traffic`, `/v1/update`, `/v1/history`, `/v1/history/import`, `/v1/events`, `/v1/rawlog`, `/admin/` (phone app) | `internal/syncer`, `internal/agent`, `internal/webui/appapi.go` |
| Local API on the socket (`/v1/<op>`, used by the TUI and pfSense pages) | `internal/ops` |
| Path probes (UDP packet format, boot IDs) and path decisions (both ends must agree) | `internal/probe`, `internal/pathsel` |
| WireGuard config per peer (allowed IPs, endpoints, keepalives) | `internal/meshcfg` |
| Firewall rules: nftables, iptables, pf anchors (same rules, same counter names) | `internal/fw` |
| Traffic history day files (binary format), labels, moving between log servers | `internal/history` |
| Event log files (`events-YYYY-MM-DD.jsonl`) | `internal/events` |
| Web UI certificate and CA files | `internal/webtls` |
| Web UI files (served as they are), login sessions | `internal/webui` (static files are shared, not ported) |
| pfSense GUI pages (PHP, installed as they are) | `internal/pfsense/files` (shared) |
| Changelog shown in the UIs | `internal/changelog/CHANGELOG.md` (shared) |
| Tunnel kept across restarts; `tunnel-id` file | `internal/wg`, `internal/agent/linkwatch.go` |

## Port order and status

Each step ends with its Go unit tests ported (same inputs, same expected
output) and passing.

| # | Go package | Rust module | Status |
|---|---|---|---|
| 1 | model, config, changelog, ports | `model`, `config`, `changelog`, `ports` | done |
| 1 | store (state.json, merge) | `store` | done |
| 1 | join (tokens, TLS join, keys) | `join` | done |
| 2 | pathsel, probe | `pathsel`, `probe` | done |
| 2 | meshcfg | `meshcfg` | done |
| 2 | wg (Linux: netlink, underlay, keep across restart, userspace fallback) | `wg`, `netlink`, `wgu` | done |
| 2 | fw (nftables, iptables), hostfw (ufw, firewalld) | `fw`, `hostfw` | done |
| 2 | syncer | `syncer` | done |
| 2 | agent core (reconcile, link watch, status) | `agent` | done |
| 3 | ops (local API), localapi, traffic, history, events, raw log | `ops`, `history`, `events` | done |
| 3 | update (self-update), diag (checks, test service) | `update`, `diag` | done |
| 4 | webtls, webui (server, auth, app API) | `webtls`, `webui` | done |
| 4 | proxy (HTTPS routes, Let's Encrypt) | `proxy` | done |
| 5 | cmd: init/join wizard, status, token, leave, start/stop, ports, diag, update, webui, pfsense | `main`, `cli` | done |
| 5 | tui | `tui` (crossterm, same views as bubbletea) | done |
| 6 | FreeBSD/pfSense: pf anchors, `wg` tool, beep, rc script, GUI install | `fw::pf`, `wg::freebsd`, `pfsense` | ported, type-checked; needs a pfSense test |
| 6 | Windows: Wintun + userspace WireGuard, service | `wg::user` + `wg::windows`, `winsvc`, `winnet` | ported; clippy-clean cross build; CI starts a real node (adapter, service, local API) on a Windows runner; needs a run on a real mesh |
| 7 | End-to-end lab passes against the Rust binary (`test/e2e/lab.sh`) | | done |
| 7 | Mixed mesh: Go and Rust nodes in one lab, both ways round (`make mixed-lab`) | | done |
| 7 | In-place upgrade Go → Rust → Go on one node (`make upgrade-test`) | | done |
| 7 | Benchmark recorded (`bench/bench.sh compare`) | | done |
| 8 | Portable userspace WireGuard (boringtun noise + own UDP/TUN loops) for platforms without kernel WireGuard | `wgdev` | done (phones, Windows, macOS) |
| 8 | macOS nodes (new; Go had none): utun + userspace WireGuard, launchd service, installer | `wg::macos`, `cli::service` | built and smoke-tested in CI only (macOS runner); no Mac to test on |
| 8 | Phone engine (`go/mobile/core`) and phone simulator | `mobile`, `bin/phonesim` | done; the lab passes with the Rust phonesim |
| 8 | Android app on the Rust engine (JNI, same Java API as gomobile) | `meshcore` (`android.rs`), `make android-core` | native libs built for all ABIs; APK built in CI, not yet run on a device |
| 8 | iOS app on the Rust engine (C API + Swift wrapper with gomobile's names) | `meshcore` (`capi.rs`, `include/`), `make ios-core` | C API unit-tested on Linux; xcframework and app build only in CI (macOS) |

The phone apps' core is now Rust (`rust/meshcore`, over `meshgate::mobile`):
libmeshcore.so for Android (JNI classes in `dev.meshgate.meshcore`, same API
the gomobile .aar had) and Meshcore.xcframework for iOS (C API wrapped by
`go/mobile/ios/Shared/Meshcore.swift` with gomobile's Swift names). The app
code itself is unchanged. The Go core in `go/mobile/core` is no longer built.

## Feature checklist

Nothing ships as Rust until every line here works in the Rust build exactly
as in Go. Taken from the Go code (`go/`); keep it in sync when Go gains a
feature before the switch.

**Command line** (`cmd/meshgate`)
- [x] `init`: interactive wizard and `-y`; roles controller / standalone / node; flags `--role --name --admin-user --admin-pass --data-dir --port --public --relay --no-routes --lan-policy --cidr --web-port --web-public --http --webui --userspace --acme-email`; busy-port detection and moving (web UI 8080→8081, WireGuard 51820→51830, mesh port); auto endpoints (skipping VPN tunnels) and auto subnets; host firewall setup
- [x] `join <token>`: `--kind server|client --name --port --data-dir -y`; refuses an explicitly busy `--port`
- [x] `agent` / `up`; `-config path` before any command
- [x] `status` (nodes, paths, handshakes, forwards, web UI fingerprints)
- [x] `token --kind --uses --note` (+ TTL)
- [x] `tui`
- [x] `leave [-y]` (tunnel, firewall, host firewall, data removed)
- [x] `webui enable [--public] [--http] | disable | ca [--pem] [--new]`
- [ ] `pfsense install | remove` — ported (same PHP files and config helper); needs a run on a real pfSense
- [x] `diag ping|trace|tcp|udp|http <target> [port]` and `myip`
- [x] `update [--check]` (root check, wrong-copy warning, checksum, `.old` kept, exit 3)
- [x] `start | stop | restart` (state kept across reboots; stop takes the tunnel down)
- [ ] `service install | uninstall` (Windows; also macOS launchd in Rust) — ported (SCM service with recovery restarts 3 s / 10 s / 30 s, auto vs manual start for start/stop); CI installs and starts it on a Windows runner
- [x] `ports`, `version`, `help`

**Mesh core**
- [x] Replicated store: last-writer-wins records, hybrid logical clock, local overrides (`local` scope, "use cluster value")
- [x] Sync: push on change + 5 s anti-entropy between servers; phone sync endpoint
- [x] Join API (TLS, pinned certificate), tokens with uses and expiry, server and client kinds
- [x] Path probes every 3 s, RTT, restart detection by tunnel ID; direct vs relay, home relay, anchor rule
- [x] WireGuard: kernel on Linux (netlink) with a userspace fallback (boringtun instead of wireguard-go, same UAPI socket); peers, allowed IPs, keepalives, endpoints learned from handshakes; MTU 1280
- [x] Tunnel kept running across restarts and updates; recreated if something deletes it; `tunnel-id`
- [x] Underlay: mesh traffic never inside another VPN (fwmark 0x4d46 → table 51824, throw routes, connmark rules), linkdown routes skipped
- [x] Subnet routes (table 51820), preserve-client-IP replies (table 51821), LAN exits (51822/51823)
- [x] Peer reset when a peer's tunnel was recreated

**Features**
- [x] Port forwards: tcp/udp/both, port ranges, target LAN IP, enable/disable (disabled port blocked), real client IPs (one edge per target), overlap check
- [ ] HTTPS routes: hostname → target, backend TLS, force HTTPS, Let's Encrypt (ACME email), recent requests log, 403 when disabled — proxying, counting, 403 and redirects tested; Let's Encrypt issuance (HTTP-01, certificates reused from the Go build's certmagic folder) not yet run against Let's Encrypt
- [x] Access rules (restricted LAN policy): from devices, to self / IP / subnet, tcp/udp/both/icmp/any, ports; counters
- [x] LAN policies: open / restricted / pfSense rules
- [x] Exit nodes for devices (allowed exits, default exit, exit only) and exit routes for LAN devices (automatic router, failover, exit only)
- [x] Relays; static devices for the official WireGuard app (config + QR, private key shown once)
- [x] Monitors (count only, server end after DNAT)
- [x] Test service (TCP+UDP responder)
- [x] Shared subnets with detection of LAN/VLAN subnets (skipping bridges and tunnels)

**Firewall**
- [x] nftables table `inet meshgate` (DNAT, masquerade, MSS clamp, anti-spoofing, blocked ports, counters, monitors) identical to Go's output
- [x] iptables `MESHGATE` chain in FORWARD (ufw / Docker)
- [x] ufw / firewalld ports opened and closed with forwards and routes
- [ ] pf anchors on FreeBSD/pfSense (nat, rdr, filter; pfSense anchor layout; reply-to for real client IPs) — rules byte-identical to Go (golden test); loading needs a run on a real pfSense

**Background**
- [x] Reconcile every 3 s and on every change
- [x] Status published (paths, LANs, version, OS)
- [x] Latest release checked every 30 min ("update available")
- [x] Remote update of other nodes (`/v1/update`), phones refused
- [x] Web UI certificate renewed (12 h)
- [x] Traffic counters every 5 s; history points every 5 min to the log server; history moved when the log server changes; retention
- [x] Event log: RAM buffer, delivery every 10 s, log server storage and retention, flushed before an update restart
- [x] Link watch (DOWN / UP again / path changes / warnings) and the pfSense beep (per-node switch)

**APIs** (same paths, same JSON)
- [x] Local socket: `view update history history-settings events rawlog changelog traffic diag forward route exitroute acl monitor node delete toggle clear-local token static-device network admin qr`
- [x] Mesh: `/v1/ping /v1/sync /v1/traffic /v1/update /v1/history /v1/history/import /v1/events /v1/rawlog`
- [x] Join and phone: `/v1/join /v1/client/sync`, `/admin/login`, `/admin/api/*`
- [x] Web UI: `/auth/login /auth/logout /auth/me /api/*`, sessions, CSRF header, login rate limit, security headers, HTTPS with http→https redirect, CA download

**Web UI** — the same files are served (`go/internal/webui/static`), so every screen works once the APIs above do: nodes, traffic (live, history, CSV/JSON download, monitors), forwards, HTTPS, access rules, exit routes, add devices, tools, logs (event log, full log file), settings, changelog.

**TUI** (`go/internal/tui`): tabs NODES FORWARDS HTTPS RULES EXITS DEVICES TRAFFIC TOOLS LOGS SETTINGS CHANGES; every form (node, forward, route, rule, exit route, monitor, token, WireGuard app, network, log server, admin login, checks, log search); keys and themes; update / update all; live and history traffic with CSV export.

**Platforms**
- [x] Linux amd64 / arm64 / arm (systemd) — amd64 verified by the lab, the mixed meshes and the benchmark; arm64/arm are the same code, cross-built
- [ ] FreeBSD / pfSense amd64 / arm64 (rc script, `wg` tool, if_wg out of the `wg` group, pfSense GUI pages, `/var/log/meshgate.log`) — ported; amd64 and arm64 (pinned nightly + build-std against a FreeBSD 14.4 sysroot, `rust/build-extra.sh`) each run the FreeBSD lab in a VM in CI; needs a run on a real pfSense
- [ ] Windows amd64 / arm64 (Wintun, service, recovery restart) — amd64 ported (Wintun + userspace WireGuard like Go's wireguard-go; the local API is a named pipe for SYSTEM/Administrators instead of a socket file); CI smoke test on a Windows runner; not yet run in a real mesh. arm64 is cross-built with llvm-mingw (`rust/build-extra.sh`) and smoke-tested on a Windows on Arm runner.
- [ ] macOS amd64 / arm64 (new platform) — utun, launchd (`meshgate service install`), `install.sh`; CI smoke test only

## Measuring

    bench/bench.sh compare dist/meshgate-go dist/meshgate-rust   # same mesh, both builds
    bench/bench.sh watch                                          # a live server (Linux or pfSense)

Go baseline (lab mesh, 2026-11-16): agent about 20–21 MB RAM, about 0.1 % of
one core while idle, carrying traffic or answering the UI. A live VPS: 22 MB.

Rust vs Go (lab mesh, 2026-11-17, `bench/bench.sh compare`, 20 s phases):

| node | phase | Go RAM | Rust RAM | CPU (both) |
|---|---|---|---|---|
| vps | idle / traffic / ui | 24.2–24.5 MB | 9.6–9.7 MB | ≈0.05–0.2 % |
| home | idle / traffic / ui | 23.7–24.1 MB | 9.1–9.2 MB | ≈0.05–0.1 % |

About 60 % less memory; the binary is 7.0 MB instead of 13.5 MB.
