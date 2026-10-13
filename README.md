# meshgate

Self-hosted WireGuard mesh with built-in port forwarding (for game servers),
HTTPS publishing (like Cloudflare Tunnels), smart path switching, per-IP/port/VLAN
access rules, a web UI, a TUI and an Android app. One Go binary runs
everything on Linux, on FreeBSD/pfSense and on Windows.

```
           friends                       your phone / laptop
              │ 203.0.113.10:25565          │ (home Wi-Fi → direct, LTE → nearest VPS)
              ▼                             ▼
   ┌────────────────────┐  WireGuard  ┌────────────────────┐
   │ VPS (relay, edge)  │◄───────────►│ VPS 2 (relay)      │
   │ forwards, HTTPS    │             └────────────────────┘
   └─────────┬──────────┘
             │ WireGuard (home dials out; no open ports at home)
   ┌─────────▼──────────┐
   │ home server        │──► game server, Jellyfin, NAS, 192.168.1.0/24 …
   └────────────────────┘
```

## What it does

| Feature | How |
|---|---|
| Installs/configures WireGuard | Kernel module when present, built-in wireguard-go otherwise. Keys, IPs, peers and routes are automatic. |
| Game/port forwarding | Edge node (VPS) DNATs a public port through the mesh to a target node or a LAN host behind it. Replaces hand-written iptables. Optional **real client IPs** for the game server. |
| HTTPS tunnels | Edge node terminates TLS with automatic Let's Encrypt certs and reverse-proxies through the mesh. HTTP→HTTPS redirect + HSTS per route. |
| Smart paths | Every node probes every endpoint every 3 s. Direct when reachable (e.g. phone on home Wi-Fi), otherwise through the lowest-latency relay, with hysteresis and failover. Both ends of a pair always agree on the path. |
| Works with the web UI down | Every node keeps the full config on disk and syncs peer-to-peer. The web UI is just another view of the same data. |
| Web UI is its own role | Installed only where you choose it (new mesh, or added to an existing one, e.g. on pfSense). `meshgate webui enable/disable` moves it later. |
| Edit anywhere | TUI on every server node. Each change is either **all nodes** (replicated, last-write-wins) or **only this node** (local override). |
| Lock down LANs | A node's LAN policy is *open* or *restricted*. Restricted: mesh devices reach only what access rules allow (device → IP/subnet/VLAN, protocol, ports). Forwards and HTTPS routes stay allowed automatically. |
| pfSense | Runs as a node and/or web UI on pfSense (FreeBSD). Rules go into pf anchors pfSense already provides; your own pfSense rules are untouched. |
| Devices | meshgate app (Android, automatic switching, full admin through the web UI) or the official WireGuard app (fixed relay, QR code). Windows PCs run meshgate.exe. |
| On/off switches | Forwards, HTTPS routes and access rules each have Enable/Disable. A disabled forward **blocks** its public port, a disabled site answers 403, and the name and settings are kept for later. |

## Install

On the first machine (usually your VPS):

```sh
curl -fsSL https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.sh | sudo sh
```

The installer installs WireGuard tools (and nftables on Linux), then asks:

```
What is this machine?
  1) Web UI   - start a new mesh and host the dashboard here
  2) Web UI   - add the dashboard to an existing mesh (needs a server token)
  3) Node     - join an existing mesh (managed with the TUI or the web UI)
  4) Node     - start a new mesh without a web UI (TUI only)
```

Every node has the TUI. The web UI only runs where you install it, and
nothing depends on it being online.

Add your home server:

```sh
# on the VPS
sudo meshgate token --kind server
# on the home server (prints the full command for you)
curl -fsSL https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.sh | sudo sh -s -- join mg1.…
```

Add your phone: web UI → **Add devices** → Join token (phone) → scan the QR code
with the meshgate app. Or `sudo meshgate token` in a terminal.

### Ports

| Port | Where | Why |
|---|---|---|
| UDP 51820 | relays (VPS) | WireGuard |
| UDP 51822 | relays (VPS) | path probes |
| TCP 51821 | relays (VPS) | joins and phone sync (TLS, pinned) |
| TCP 80/443 | edge with HTTPS routes | Let's Encrypt + HTTPS |
| your game ports | edge with forwards | the forwarded services |

These are the defaults. If one is already taken on a machine during setup
(an existing WireGuard on 51820, pfSense's WireGuard package, something on
8080), meshgate picks the next free one:

- WireGuard moves in steps of 10 (51830, 51840, ...) so probes stay on +2.
- The new ports are published to the other nodes.
- The setup output says what moved.
- The Linux installer opens whatever ports were chosen in firewalld/ufw.
- A port you set yourself (`--port`, `--web-port`) is never moved; setup stops
  with an error instead.

`meshgate ports` lists the ports a node actually uses.

Home nodes need **no open ports**. Optionally forward UDP 51820 and 51822 on
your router for direct connections from outside.

### Web UI

Listens on `127.0.0.1:8080` and the node's mesh IP (`http://100.88.x.y:8080`),
so you reach it through the mesh from any joined device. Use `--web-public` at
init to bind all interfaces (only behind a firewall).

## pfSense

No SSH needed. In the web UI (or `meshgate token --kind server`) create a
**server** token. It gives you a pfSense command. Paste that into
*Diagnostics → Command Prompt → Execute Shell Command*:

```sh
fetch -qo - https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.sh | sh -s -- join mg1.…
```

It installs meshgate, joins the mesh and starts it, without asking anything:

- LAN and VLAN interfaces are shared automatically. The WAN is not.
- Phones on your home Wi-Fi or a VLAN connect straight to pfSense.
- **VPN → meshgate** shows the full dashboard inside the pfSense GUI, behind
  your pfSense login.
- **Firewall → Rules → MESHGATE** decides what mesh devices may reach. It
  starts with one rule that allows everything; replace it with rules for the
  hosts and ports you want (e.g. pass TCP to VM 1 port 443, pass TCP to VM 2
  port 22). Anything without a rule is blocked by pfSense's default deny.

To make pfSense the **web UI** (a new mesh) instead:

```sh
fetch -qo - https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.sh | sh -s -- init --role controller --admin-pass 'choose-a-password'
```

Remove it again with `… | sh -s -- uninstall`. From an SSH shell
(console option 8) the same script asks its questions interactively instead.

If `wg` is missing, install **WireGuard** from *System → Package Manager*
first (it provides `wireguard-tools` and the `if_wg` kernel module), then
rerun.

What meshgate changes on pfSense:

| | |
|---|---|
| Interface | `tun_mg0` (kernel `if_wg`), assigned as **MESHGATE** (type None), separate from pfSense's own WireGuard tunnels |
| GUI | VPN → meshgate (`/usr/local/www/vpn_meshgate.php`, `meshgate_api.php`, `meshgate/`), menu entry in `config.xml` |
| Rules | pf anchors pfSense always includes: `natrules/meshgate` (NAT), `tftp-proxy/meshgate` (port-forward redirects), `userrules/meshgate` (filter). They survive pfSense filter reloads; meshgate also re-applies them every minute. |
| WAN | Opens UDP 51820/51822 (and TCP 51821 on relays) to the WAN address, inside its anchor |
| Files | `/usr/local/etc/meshgate/` (survives "Use RAM Disks"), service `/usr/local/etc/rc.d/meshgate.sh`, log `/var/log/meshgate.log` |

The node's LAN policy is **firewall**: meshgate adds no access rules of its
own and pfSense's MESHGATE rules decide (meshgate only keeps its own sync and
web UI ports reachable). `meshgate pfsense remove` takes the page, interface
and its rules out again and switches back to meshgate's **restricted** policy
(only meshgate access rules). To skip the GUI integration at install time, set
`MESHGATE_PFSENSE_GUI=0`. Every `config.xml` change is a normal pfSense
revision, so *Diagnostics → Backup & Restore → Config History* can undo it.

Already installed? Rerun the install command (it updates meshgate and adds
the GUI), or run `meshgate pfsense install` in a shell.

Notes:
- The pfSense GUI uses ports 80/443, so don't make pfSense the edge for HTTPS
  routes unless you move its GUI port. Port forwards work fine.
- Rules on the MESHGATE tab see the mesh device's own address (e.g.
  `100.88.12.34`) as the source, so you can allow single devices.
- If pfSense itself is a relay and you narrow the MESHGATE rules, keep a rule
  passing mesh net (`100.88.0.0/16`) to mesh net, or relayed traffic stops.

## Windows

In an **elevated PowerShell** (the web UI/TUI shows this command with your
token):

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.ps1))) join mg1.… --kind client
```

It installs `meshgate.exe` + `wintun.dll` to `C:\Program Files\meshgate`,
allows meshgate in Windows Firewall, sets the tunnel network to *Private*,
joins, and runs meshgate as a Windows service. `meshgate tui` and
`meshgate status` work in an Administrator terminal.

A Windows PC can be a client, or a server that hosts a game behind a VPS
forward. Allow the game's port in Windows Defender Firewall. Windows nodes
cannot share their LAN, be a forward edge, enforce a restricted LAN policy or
receive real client IPs: use Linux or pfSense for that.

## Phone app (Android)

- Join by scanning a token's QR code, then tap the switch to connect.
- Choosing the path is automatic: direct at home, nearest relay elsewhere.
- **Admin** opens the full web UI through the mesh: forwards, rules, devices,
  everything. It needs the web UI admin login, so only admins can change
  anything.

## Access rules (lock down)

On a node that shares subnets (home server, pfSense), set **LAN policy →
restricted** (web UI → Nodes → Edit, or TUI → Nodes → `e`). From then on,
mesh devices can reach only:

- what access rules allow (web UI → *Access rules*, TUI → tab 4),
- the targets of port forwards and HTTPS routes,
- meshgate's own sync port.

Each rule says: **from** which devices (or any), **to** a host IP, a subnet or
VLAN (the UI lists the node's VLAN interfaces, e.g. `192.168.20.0/24 — igb1.20`)
or the node itself, **protocol** (tcp/udp/icmp/any) and **ports**
(`443`, `80,443`, `8000-8100`).

Examples:

| From | To | Allow | Effect |
|---|---|---|---|
| laptop | 192.168.1.20 | tcp 445 | laptop can use the NAS shares, nothing else |
| any | 192.168.20.0/24 (VLAN 20) | udp 53 | DNS on the IoT VLAN for everyone |
| phone | this node | icmp | phone may ping pfSense |

Like every edit, a rule applies to **all nodes** or **only this node**.
On Linux the rules are an nftables table, on pfSense a pf anchor.

## Using it

```sh
sudo meshgate status     # nodes, paths (direct / via relay), handshakes
sudo meshgate tui        # forwards, HTTPS routes, rules, nodes, tokens
```

TUI keys: `1`-`5`/`TAB` sections, `A` add, `E` edit, `T` on/off, `D` remove,
`C` drop a local-only override, `Y` theme (Classic, Readable, Light terminal,
Ocean, Plain), `Q` quit. The look follows
[iptable-UI](https://github.com/HeresJohnny320/iptable-UI).

**Minecraft example** (TUI → Forwards → `n`, or web UI → Port forwards):
edge `vps`, TCP 25565 → target `home` port 25565, *show players' real IPs* on.
Friends connect to the VPS IP; nothing at home is exposed.

**HTTPS example**: set the Let's Encrypt email (TUI `s` / web UI Settings),
point `jellyfin.example.com` at the VPS, add route → target `home`, port 8096.

## How it works

- `internal/store`: replicated config. LWW registers with a hybrid logical
  clock, local-scope overrides, atomic JSON file.
- `internal/syncer`: push-on-change + 5 s anti-entropy between server nodes over
  the mesh. Clients may only write their own status.
- `internal/pathsel`: path decision (direct / which relay). Pure and tested.
- `internal/meshcfg`: turns paths into WireGuard peers/AllowedIPs/routes.
- `internal/fw`: nftables ruleset (one `inet meshgate` table, replaced atomically).
- `internal/probe`: UDP probes with RTT and restart detection (boot IDs).
- `internal/join`: tokens, pinned-TLS join API, phone sync endpoint.
- `internal/agent`: runs it all; `internal/webui`, `internal/tui`: UIs.
- `mobile/core`: the same engine for phones (gomobile), on wireguard-go.

Real client IPs use policy routing on the target: connections arriving from the
edge are marked and their replies routed back through the tunnel. This needs
the service to run on the target node itself (Docker on that host is fine) and
one preserve-IP edge per target node.

## Development

```sh
make test     # unit tests
make lab      # Linux end-to-end: 9 network namespaces, real WireGuard + nftables,
              # VPS + 2nd relay + home NAT + NAS + laptop + simulated phone + friend
make release  # linux amd64/arm64/arm, freebsd amd64/arm64, windows zips in dist/
```

### Releases (GitHub Actions)

- `.github/workflows/ci.yml` runs on every push: it vets for every OS, then
  runs the unit tests and the Linux lab.
- `.github/workflows/release.yml` releases every push to `main` whose `ci`
  run passed, bumping the patch version (v0.2.0 → v0.2.1). For a bigger step,
  push a tag yourself; automatic releases continue from it:

  ```sh
  git tag v0.3.0 && git push origin v0.3.0
  ```

  It builds the Linux, FreeBSD/pfSense and Windows binaries and the Android
  APK, then publishes them as a GitHub release with checksums and the
  install scripts.

To release-sign the APK, add the repository secrets
`ANDROID_KEYSTORE_BASE64` (base64 of your `.jks`), `ANDROID_KEYSTORE_PASSWORD`,
`ANDROID_KEY_ALIAS` and `ANDROID_KEY_PASSWORD`. Without them the APK is signed
with a debug key: it installs fine, but you can't upgrade it in place from a
differently signed build.

`make lab` needs unprivileged user namespaces (default on Fedora/Ubuntu).

`test/freebsd/lab.sh` is the FreeBSD/pfSense end-to-end test. Run it as root on
FreeBSD 14+. It uses vnet jails, real `if_wg` and pf with pfSense's anchor
layout: a VPS edge, a pfSense-style router with LAN + VLAN 20 and a restricted
policy, a client, and a friend connecting to a forwarded game port.

### Mobile apps

```sh
go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init
make android-core   # → mobile/android/app/libs/meshcore.aar (needs Android NDK)
make ios-core       # → mobile/ios/Meshcore.xcframework (needs macOS + Xcode)
```

- **Android**: `cd mobile/android && ./gradlew assembleDebug` (or open it in
  Android Studio). Needs JDK 17 and the Android SDK.
- **iOS** (on hold): `cd mobile/ios && xcodegen`, then open
  `MeshGate.xcodeproj`, set your team, and enable the Network Extension + App
  Group capabilities. A paid Apple developer account is required.

## Status

Early but working. What is tested here:

| Area | How |
|---|---|
| Linux | Unit tests and the namespace lab (42 checks) |
| FreeBSD nodes | The jail lab on FreeBSD 14.5 (19 checks), using pfSense's pf anchor layout from pfSense's source |
| pfSense install | `test/freebsd/pfsense_install.sh`: a no-terminal install, a reboot and an uninstall (19 checks) |
| Phone engine | `mobile/phonesim` in the Linux lab |
| Android | The APK compiles. It has not run on a device or emulator (the emulator crashes on the dev machine). |
| Windows | Compiles and vets. It has not run on Windows. |

Not tested yet: an actual pfSense install, the Android app on a phone,
Windows, and iOS.

Not yet: IPv6 inside the mesh, MagicDNS-style names, exit nodes, rules between
two mesh devices (rules cover traffic into LANs and to nodes), NAT hole
punching between two NATed homes (relays are used instead).
