# meshgate

meshgate connects your machines (a VPS, your home server or pfSense router,
your phone, your laptop, Windows PCs) into one private WireGuard network.
Then it lets you:

- **share game servers** with friends through your VPS, without opening any
  ports at home,
- **publish websites** at home over HTTPS through your VPS (like Cloudflare
  Tunnels, with free Let's Encrypt certificates),
- **reach your home network** from your phone or laptop, wherever you are,
- **control who can reach what** on your home network.

It is one program. It sets up WireGuard, picks the fastest path for every
connection, and gives you a web dashboard, a terminal UI (TUI) and an Android
app to manage everything.

```
           friends                       your phone / laptop
              │ 203.0.113.10:25565          │ (home Wi-Fi → direct, mobile data → via VPS)
              ▼                             ▼
   ┌────────────────────┐  WireGuard  ┌────────────────────┐
   │ VPS (relay, edge)  │◄───────────►│ VPS 2 (optional)   │
   │ forwards, HTTPS    │             └────────────────────┘
   └─────────┬──────────┘
             │ WireGuard (home connects out; no open ports at home)
   ┌─────────▼──────────┐
   │ home server or     │──► game server, Jellyfin, NAS, VMs, 192.168.1.0/24 …
   │ pfSense router     │
   └────────────────────┘
```

**Contents:** [Quick start](#quick-start) ·
[Install](#install) ([VPS](#vps-first-machine) · [Linux](#linux-home-server-or-pc) ·
[pfSense](#pfsense) · [Windows](#windows) · [Android](#android-phone) ·
[WireGuard app](#any-device-with-the-official-wireguard-app)) ·
[Web UI or TUI](#managing-the-mesh-web-ui-or-tui) ·
[Common tasks](#common-tasks) · [Update and uninstall](#update-and-uninstall) ·
[Troubleshooting](#troubleshooting) · [Advanced](#advanced)

## Quick start

The usual setup is a cheap VPS plus your home machine, plus your phone.

**1. On the VPS** (Linux with a public IP), install and pick option **1**:

```sh
curl -fsSL https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.sh | sudo sh
```

Choose an admin password when it asks. Open UDP 51820, UDP 51822 and TCP 51821
in your VPS provider's firewall.

**2. Add your home machine.** On the VPS, make a join token:

```sh
sudo meshgate token --kind server
```

It prints the command to run at home. On a Linux home server:

```sh
curl -fsSL https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.sh | sudo sh -s -- join mg1.…
```

On pfSense, see [pfSense](#pfsense).

**3. Add your phone.** Install the Android app from the
[latest release](https://github.com/HeresJohnny320/meshgate/releases/latest)
(`meshgate-android.apk`), make a phone token (`sudo meshgate token` on the VPS,
or **Add devices** in the web UI), scan its QR code in the app and switch it on.

That's it. `sudo meshgate status` on any machine shows every device and how it
is connected.

## Install

Every install uses the same scripts. They download the latest release, set up
WireGuard and start meshgate as a service. Running the same command again
later **updates** meshgate and keeps your settings.

When you install on a machine, the installer asks what it is:

```
What is this machine?
  1) Web UI   - start a new mesh and host the dashboard here
  2) Web UI   - add the dashboard to an existing mesh (needs a server token)
  3) Node     - join an existing mesh (managed with the TUI or the web UI)
  4) Node     - start a new mesh without a web UI (TUI only)
```

- Your **first** machine starts the mesh: option 1 (with the web dashboard) or
  4 (terminal only).
- Every **other** machine joins with a token: option 3, or 2 if it should also
  host the dashboard.

### VPS (first machine)

```sh
curl -fsSL https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.sh | sudo sh
```

- Pick **1** to host the web dashboard on the VPS, or **4** if you only want the
  TUI (you can host the dashboard on pfSense or another machine later).
- A VPS with a public IP automatically becomes a **relay**: devices that cannot
  reach each other directly (your phone on mobile data and your home server)
  talk through it.
- Open these in your **VPS provider's firewall / security group** (the installer
  handles ufw and firewalld on the VPS itself, but not your provider's panel):

  | Port | Why |
  |---|---|
  | UDP 51820 | WireGuard |
  | UDP 51822 | path probes |
  | TCP 51821 | joining new devices |
  | TCP 80 and 443 | only if you publish websites (HTTPS routes) |
  | your game ports | only for port forwards, e.g. TCP 25565 for Minecraft |

### Linux home server or PC

Make a token on any server node (`sudo meshgate token --kind server`, or the
web UI → **Add devices**), then:

```sh
curl -fsSL https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.sh | sudo sh -s -- join mg1.…
```

- A **home server** needs no open ports: it connects out to the VPS. Its local
  network (e.g. `192.168.1.0/24`) is shared with the mesh, so your phone can
  reach your NAS or VMs.
- For a **laptop or desktop** that should only connect (not share anything),
  use a client token (`sudo meshgate token`) and add `--kind client`.

Supported: any systemd Linux (Debian, Ubuntu, Fedora, Arch, Alpine with
systemd, …) on amd64, arm64 or 32-bit ARM (Raspberry Pi).

### pfSense

No SSH needed.

1. Install **WireGuard** from *System → Package Manager* (it provides the `wg`
   tool and the kernel module).
2. Make a **server** token on the VPS (`sudo meshgate token --kind server`) or
   in the web UI.
3. Paste this into *Diagnostics → Command Prompt → Execute Shell Command*:

   ```sh
   fetch -qo - https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.sh | sh -s -- join mg1.…
   ```

   If your mesh has no dashboard login yet (the VPS was set up TUI-only), add
   `--admin-pass 'choose-a-password'` at the end.

After install you get:

- **VPN → meshgate**: the full meshgate dashboard inside the pfSense GUI,
  behind your normal pfSense login.
- **Firewall → Rules → MESHGATE**: a normal pfSense rules tab that decides what
  mesh devices (your VPS, phone, laptop) may reach on your network. It starts
  with one rule that allows everything. Replace it with rules for what you
  want, for example *pass TCP to VM 1 port 443* and *pass TCP to VM 2 port 22*.
  Anything without a rule is blocked.
- The dashboard is also reachable for mesh devices (pfSense's mesh IP, not your
  LAN or WAN), so the phone app's **Admin** button works.
- Your LAN and VLANs are shared with the mesh automatically (not the WAN).
- Phones and laptops on your home Wi-Fi connect straight to pfSense; away from
  home they go through the VPS.

To make pfSense the **first** machine of a new mesh (with the dashboard)
instead of joining one:

```sh
fetch -qo - https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.sh | sh -s -- init --role controller --admin-pass 'choose-a-password'
```

From an SSH shell (console menu option 8) the same commands ask their
questions interactively instead.

### Windows

In **PowerShell as Administrator** (the web UI and TUI show this command with
your token filled in):

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.ps1))) join mg1.… --kind client
```

It installs to `C:\Program Files\meshgate`, adds the Windows Firewall rule,
joins and runs meshgate as a Windows service. Then `meshgate status` and
`meshgate tui` work in an Administrator terminal.

A Windows PC can be a client, or a server hosting a game behind a VPS port
forward (use `--kind server`; also allow the game's port in Windows Defender
Firewall). Windows cannot share its LAN, be a forward edge, lock down a LAN
or show players' real IPs; use Linux or pfSense for those.

### Android phone

1. Download `meshgate-android.apk` from the
   [latest release](https://github.com/HeresJohnny320/meshgate/releases/latest)
   and install it (allow installing from your browser when Android asks).
2. Make a **phone** token: web UI → **Add devices** → *Phone / laptop (client)*,
   or `sudo meshgate token` on any server.
3. In the app, tap **Scan QR code**, then **Join**, then turn on the switch.

The app picks the path by itself: straight to your home network when you're
on home Wi-Fi, through the nearest VPS otherwise.

**Admin from the phone:** the **Admin** card opens the full dashboard through
the tunnel. Sign in with the dashboard admin login. It needs a node with the
web UI turned on; if there is none, the card tells you how
(`meshgate webui enable` on that node).

An iPhone app exists in the source but is not released yet (it needs a paid
Apple developer account). Use the official WireGuard app on iPhone meanwhile.

### Any device with the official WireGuard app

For iPhones, Macs, routers or anything else with the official WireGuard app:
web UI → **Add devices** → *Official WireGuard app* (or TUI → `w`). Pick a
name and a relay; you get a config file and a QR code. These devices always
connect through that relay and don't switch paths automatically.

## Managing the mesh: web UI or TUI

Both show and change the same settings. Every server node keeps the whole
configuration, so **the mesh keeps working when the web UI's machine is
offline**, and you can make changes from any server node in the meantime.

### Web UI (dashboard)

Runs only on the machines you chose (installer option 1 or 2, `--webui`, or
`meshgate webui enable`). You sign in with the admin username and password.

| Where you are | Open |
|---|---|
| On that machine | `http://127.0.0.1:8080` |
| On any device in the mesh (phone, laptop) | `http://<that node's mesh IP>:8080` (mesh IPs are shown by `meshgate status`) |
| pfSense | *VPN → meshgate* in the pfSense GUI |
| Android app | the **Admin** card |
| From outside the mesh, on a VPS | `ssh -L 8080:127.0.0.1:8080 you@vps`, then `http://localhost:8080` |

The dashboard is not on the public internet by default. Tabs: **Nodes**,
**Port forwards**, **HTTPS**, **Access rules**, **Add devices**, **Settings**
(Let's Encrypt email, admin login).

- Turn it on or off on a server node: `sudo meshgate webui enable` /
  `sudo meshgate webui disable`.
- Change the admin password: *Settings → Admin login*, or
  `sudo meshgate webui enable --admin-pass 'new-password'` (at least 8
  characters). It applies to every dashboard in the mesh.

### TUI (terminal)

On every server node:

```sh
sudo meshgate tui
```

Sections: `1` Nodes, `2` Forwards, `3` HTTPS, `4` Rules, `5` Devices (or
`Tab`). Keys: `a` add, `e` edit, `t` turn on/off, `d` delete, `c` drop a
local-only override, `w` WireGuard app config, `s` settings, `y` theme, `r`
refresh, `q` quit.

### Commands

| Command | Does |
|---|---|
| `meshgate status` | devices, mesh IPs, path (direct / via relay), last handshake |
| `meshgate tui` | the terminal UI |
| `meshgate token [--kind server] [--uses N] [--ttl 24h]` | join token (default: one phone/laptop, valid 24 h) |
| `meshgate webui enable \| disable` | host the dashboard on this node, or stop |
| `meshgate pfsense install \| remove` | pfSense GUI integration (VPN menu, MESHGATE rules tab) |
| `meshgate ports` | ports this node uses |
| `meshgate leave` | remove meshgate's config from this machine |
| `meshgate version` | version |

On Linux run them with `sudo`; on pfSense in the root shell; on Windows in an
Administrator terminal.

## Common tasks

### Share a game server (port forward)

Example: Minecraft at home, friends connect to your VPS.

Web UI → **Port forwards** → **New forward** (or TUI → `2` → `a`):

- **Edge:** your VPS (where friends connect)
- **Protocol / port:** TCP 25565
- **Target:** your home server, port 25565 (or any LAN IP behind it, e.g. a VM)
- **Show players' real IPs:** on, if the game server runs on the target node
  itself and should see real player addresses

Friends connect to `<VPS IP>:25565`. Nothing at home is exposed. Port ranges
work too (e.g. `2456-2458` for Valheim). Turning a forward off closes the port
and keeps its settings.

### Publish a website over HTTPS

1. Point a DNS name (e.g. `jellyfin.example.com`) at your VPS IP.
2. Set your Let's Encrypt email: web UI → **Settings** (TUI: `s`).
3. Web UI → **HTTPS** → **New route**: hostname `jellyfin.example.com`, edge =
   VPS, target = home server, port 8096.

The VPS gets the certificate, redirects HTTP to HTTPS and passes requests to
your home server through the mesh. Needs TCP 80 and 443 open on the VPS.

### Control what mesh devices can reach

- **pfSense:** use *Firewall → Rules → MESHGATE* (see [pfSense](#pfsense)).
  Rules see each device's mesh IP (e.g. `100.88.12.34`) as the source, so you
  can allow single devices.
- **Linux home server:** web UI → **Nodes** → **Edit** → *LAN policy:
  Restricted* (TUI: `1`, `e`). Then add **Access rules**: from which devices,
  to which host / subnet / VLAN / this node, which protocol and ports.

| From | To | Allow | Effect |
|---|---|---|---|
| laptop | 192.168.1.20 | tcp 445 | laptop can use the NAS shares, nothing else |
| any | 192.168.20.0/24 (VLAN 20) | udp 53 | DNS on the IoT VLAN for everyone |
| phone | this node | icmp | phone may ping the home server |

Port forwards and HTTPS routes keep working automatically.

### Add or remove devices

- **Add:** make a token (web UI → **Add devices**, or `meshgate token`) and use
  it on the new device. A token is single-use and valid 24 hours unless you
  choose otherwise.
- **Remove:** web UI → **Nodes** → **Remove** (TUI: `1`, `d`), and uninstall
  it on that device.

### Relays

A **relay** is a node with a public IP that forwards traffic for devices that
cannot reach each other directly. A VPS becomes one automatically. A home
router normally should not (it would use your home upload), but you can turn
it on later: web UI → **Nodes** → **Edit** → tick *Relay* and make sure its
public address is in *Endpoints*. Add a second VPS as another relay for
failover; devices switch to it automatically.

### Every change: all nodes or only this node

When you save something you choose **all nodes** (shared with the whole mesh,
the default) or **only this node** (a local override, e.g. to test a change on
one machine). `c` in the TUI drops a local override again.

## Update and uninstall

**Update:** run the same install command again (no token needed). It downloads
the newest release, keeps your settings and restarts meshgate:

```sh
# Linux
curl -fsSL https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.sh | sudo sh
# pfSense (Diagnostics → Command Prompt)
fetch -qo - https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.sh | sh
```

On Windows rerun the PowerShell command. On Android install the new APK over
the old one.

**Uninstall:**

```sh
# Linux
curl -fsSL https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.sh | sudo sh -s -- uninstall
# pfSense (also removes VPN → meshgate, the MESHGATE interface and its rules)
fetch -qo - https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.sh | sh -s -- uninstall
```

Windows: run the PowerShell command with `uninstall` instead of `join …`.
Then remove the device from the mesh in the web UI or TUI of another node.

## Troubleshooting

| Problem | Try |
|---|---|
| A device shows `via <relay>` instead of `direct` | Normal when it's away from home or behind NAT. Forward UDP 51820 and 51822 on your router for direct connections from outside. |
| Join fails / times out | The token may be used up or expired: make a new one. On the VPS, check TCP 51821 is open in your provider's firewall. |
| Friends can't connect to a forward | Open the port in your VPS provider's firewall. With ufw: `sudo ufw route allow proto tcp to any port 25565`. Check the forward is on. |
| No **Admin** button in the phone app | Turn the tunnel on. If the card says no node hosts the web UI, run `meshgate webui enable` on one. |
| Forgot the dashboard password | On a node with the web UI: `sudo meshgate webui enable --admin-pass 'new-password'` |
| pfSense: "install the WireGuard package first" | *System → Package Manager* → install **WireGuard**, then rerun. |
| pfSense: *VPN → meshgate* missing | Run `meshgate pfsense install` in *Diagnostics → Command Prompt*, or open `https://<pfsense>/vpn_meshgate.php` directly. |
| meshgate does not start | Logs: `journalctl -u meshgate -n 50` (Linux), `/var/log/meshgate.log` (pfSense), Event Viewer (Windows). |
| "port already in use" during setup | meshgate picks the next free port by itself; it only stops when you set a port with `--port` / `--web-port`. `meshgate ports` shows what it uses. |

---

## Advanced

### How it works

- **WireGuard:** every node gets a mesh IP (default range `100.88.0.0/16`) and
  a key. meshgate configures the peers, allowed IPs and routes itself, using
  the kernel module when there is one and its built-in wireguard-go otherwise.
- **Paths:** every node probes every endpoint every 3 seconds. A pair connects
  directly when either side can reach the other; otherwise both use the same
  relay (the home relay of the more mobile device). Switching has hysteresis,
  so paths don't flap, and fails over when a relay goes offline.
- **Config sync:** every server node stores the full configuration on disk and
  syncs it peer to peer over the mesh (on change, plus every 5 seconds). Edits
  are last-write-wins with a hybrid logical clock. Clients (phones, laptops)
  only receive config and publish their own status. That is why there is no
  single point of failure: the web UI is just another view of the same data.
- **Joining:** a token contains the join address and the certificate
  fingerprint of a relay, so the join is TLS-pinned and needs no CA.

### Ports

| Port | Where | Why |
|---|---|---|
| UDP 51820 | every node (open on relays) | WireGuard |
| UDP 51822 | every node (open on relays) | path probes (WireGuard port + 2) |
| TCP 51821 | relays | joins and phone config sync (TLS, pinned) |
| TCP 51823 | every server, mesh only | config sync between servers |
| TCP 8080 | web UI nodes, localhost + mesh IP | dashboard |
| TCP 80/443 | edge with HTTPS routes | Let's Encrypt + HTTPS |

These are defaults. When one is taken during setup (an existing WireGuard on
51820, pfSense's WireGuard package, something on 8080), meshgate picks the
next free one, publishes it to the other nodes and says so: WireGuard moves in
steps of 10 (51830, 51840, …) so probes stay on +2. A port you set yourself
(`--port`, `--web-port`) is never moved; setup stops instead.

### Firewall and routing

meshgate doesn't use iptables commands or ufw. It writes its own rules
directly:

- **Linux:** one nftables table, `inet meshgate`, replaced atomically on every
  change. Port forwards are DNAT rules, masquerading hides mesh sources behind
  the target's LAN address, and restricted LAN policies are filter chains.
  Your own rules, Docker's and ufw's are untouched
  (`sudo nft list table inet meshgate` shows meshgate's). Routes to shared
  subnets live in routing table 51820, selected by `ip rule`.
- **ufw / firewalld:** they still filter traffic alongside meshgate, so the
  installer opens meshgate's ports and allows traffic on the mesh interface
  `mg0` in them.
- **pfSense / FreeBSD:** pf anchors that pfSense already loads:
  `natrules/meshgate` (NAT), `tftp-proxy/meshgate` (port-forward redirects),
  `userrules/meshgate` (filter). They survive pfSense filter reloads and are
  re-applied every minute. Forwards therefore don't appear on pfSense's
  *Firewall → NAT* page (`pfctl -a natrules/meshgate -s nat` shows them).

### Real client IPs

With *show players' real IPs*, the VPS does not masquerade the forward, so
packets reach the target with the player's address. The target marks those
connections and routes replies back through the tunnel with policy routing
(table 51821 on Linux, `reply-to` on pfSense). The service must run on the
target node itself (Docker on that host is fine), and a target node accepts
real client IPs from one edge.

### LAN policies

A node that shares subnets has a LAN policy:

| Policy | Who decides | Default on |
|---|---|---|
| open | everyone in the mesh may reach the node and its LANs | Linux |
| restricted | only meshgate access rules (plus forward and HTTPS targets) | FreeBSD |
| firewall | the host firewall's own rules (pfSense MESHGATE tab) | pfSense with the GUI integration |

In every policy meshgate keeps its own sync and dashboard ports reachable for
mesh devices, so you can't lock yourself out.

### pfSense details

| | |
|---|---|
| Interface | `tun_mg0` (kernel `if_wg`), assigned as **MESHGATE** with IPv4 type *None* (meshgate manages the address). The `tun_` prefix keeps pfSense's boot-time interface check from tripping. Separate from pfSense's own WireGuard tunnels. |
| GUI | `/usr/local/www/vpn_meshgate.php` (the page), `meshgate_api.php` (passes the dashboard's requests to meshgate's local socket, behind the pfSense login), `/usr/local/www/meshgate/` (dashboard files), a VPN menu entry in `config.xml`. |
| Rules | The MESHGATE tab is seeded with one *pass any* rule on the first install only, so a rule you narrowed is never widened again. |
| Web UI | meshgate's own dashboard listens on pfSense's mesh IP and localhost (not LAN or WAN) for the phone app. |
| WAN | Opens UDP 51820/51822 (and TCP 51821 on relays) on the WAN address inside its anchor. |
| Files | `/usr/local/etc/meshgate/` (survives "Use RAM Disks"), service `/usr/local/etc/rc.d/meshgate.sh`, log `/var/log/meshgate.log`. |

Every `config.xml` change is a normal pfSense revision, so *Diagnostics →
Backup & Restore → Config History* can undo it. `meshgate pfsense remove`
takes the page, interface and its rules out again (the interface stays
assigned if other rules still use it) and switches back to the restricted
policy. Notes:

- The pfSense GUI uses ports 80/443, so don't make pfSense the edge for HTTPS
  routes unless you move its GUI port. Port forwards work fine.
- If pfSense is a relay and you narrow the MESHGATE rules, keep a rule passing
  mesh net (`100.88.0.0/16`) to mesh net, or relayed traffic stops.

### Installer options

Linux / pfSense (`install.sh`), as arguments after `sh -s --`:

| Argument | Does |
|---|---|
| `join <token> [flags]` | join without the questions; flags as for `meshgate join` |
| `init --role controller\|standalone [--admin-pass …]` | start a new mesh without questions |
| `uninstall` | remove meshgate |

Useful `join` / `init` flags: `--kind server|client`, `--name`, `--webui`,
`--web-public` (dashboard on all interfaces; only behind a firewall),
`--admin-pass`, `--relay`, `--port`, `--web-port`, `--no-routes`,
`--lan-policy open|restricted|firewall`, `--cidr` (init only), `-y` (no
questions).

Environment variables:

| Variable | Does |
|---|---|
| `MESHGATE_BIN=/path/to/meshgate` | install a local binary instead of downloading |
| `MESHGATE_VERSION=v0.2.0` | install a specific release instead of the latest |
| `MESHGATE_PFSENSE_GUI=0` | pfSense: skip VPN → meshgate and the MESHGATE rules tab |
| `MESHGATE_ZIP=…` (Windows) | install from a local `meshgate-windows-<arch>.zip` |

### Code layout

- `internal/store`: replicated config (LWW registers, hybrid logical clock,
  local-scope overrides, atomic JSON file).
- `internal/syncer`: push-on-change + 5 s anti-entropy between server nodes.
- `internal/pathsel`: path decision (direct / which relay). Pure and tested.
- `internal/meshcfg`: turns paths into WireGuard peers, AllowedIPs and routes.
- `internal/fw`: firewall plan, rendered as nftables (Linux) or pf (FreeBSD).
- `internal/probe`: UDP probes with RTT and restart detection.
- `internal/join`: tokens, pinned-TLS join API, phone sync endpoint.
- `internal/pfsense`: pfSense GUI integration.
- `internal/agent`: runs it all; `internal/webui`, `internal/tui`: the UIs.
- `mobile/core`: the same engine for phones (gomobile, wireguard-go);
  `mobile/android`, `mobile/ios`: the apps.

### Development

```sh
make test     # unit tests
make lab      # Linux end-to-end: 9 network namespaces, real WireGuard + nftables,
              # VPS + 2nd relay + home NAT + NAS + laptop + simulated phone + friend
make release  # linux amd64/arm64/arm, freebsd amd64/arm64, windows zips in dist/
```

`make lab` needs unprivileged user namespaces (default on Fedora/Ubuntu).
`test/freebsd/lab.sh` is the FreeBSD/pfSense end-to-end test: run it as root on
FreeBSD 14+. It uses vnet jails, real `if_wg` and pf with pfSense's anchor
layout.

Mobile builds:

```sh
go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init
make android-core   # → mobile/android/app/libs/meshcore.aar (needs the Android NDK)
make ios-core       # → mobile/ios/Meshcore.xcframework (needs macOS + Xcode)
```

- **Android:** `cd mobile/android && ./gradlew assembleDebug` (or Android
  Studio). Needs JDK 17 and the Android SDK.
- **iOS** (on hold): `cd mobile/ios && xcodegen`, open `MeshGate.xcodeproj`,
  set your team and enable the Network Extension + App Group capabilities.
  Needs a paid Apple developer account.

### Releases

- `.github/workflows/ci.yml` runs on every push: vet for every OS, unit tests
  and the Linux lab.
- `.github/workflows/release.yml` releases every push to `main` whose CI
  passed, bumping the patch version (v0.2.0 → v0.2.1). For a bigger step,
  push a tag yourself; automatic releases continue from it:

  ```sh
  git tag v0.3.0 && git push origin v0.3.0
  ```

  It builds the Linux, FreeBSD/pfSense and Windows binaries and the Android
  APK, and publishes them with checksums and the install scripts.

To release-sign the APK, add the repository secrets `ANDROID_KEYSTORE_BASE64`
(base64 of your `.jks`), `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS` and
`ANDROID_KEY_PASSWORD`. Without them the APK is signed with a debug key: it
installs fine, but you can't upgrade it in place from a differently signed
build.

### Status and limits

Early but working.

| Area | Tested with |
|---|---|
| Linux | unit tests and the namespace lab (every push) |
| FreeBSD / pfSense | the jail lab on FreeBSD 14.5 and `test/freebsd/pfsense_install.sh` (install, reboot, uninstall), using pfSense's anchor layout; first real pfSense installs are in use |
| Phone engine | `mobile/phonesim` in the Linux lab; the Android app is in early use on real phones |
| Windows | compiles and vets; not yet run on real Windows |
| iOS | not released |

Not yet: IPv6 inside the mesh, MagicDNS-style names, exit nodes, rules between
two mesh devices (rules cover traffic into LANs and to nodes), NAT hole
punching between two NATed homes (relays are used instead).
