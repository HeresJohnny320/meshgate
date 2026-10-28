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
- Open these in your **VPS provider's firewall / security group**. ufw and
  firewalld on the VPS itself are handled automatically (meshgate opens its
  ports, 80/443 for HTTPS routes and each port forward there, and closes them
  again when you delete one), but your provider's panel is not:

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

Leave the switch on all the time. The app picks the path by itself:

- **At home** (it reaches your pfSense or home server directly on its LAN):
  your home network is used normally, no detour.
- **Anywhere else** (mobile data, a café, work Wi-Fi): your home network and
  mesh devices are reached through the nearest VPS, so `192.168.1.x` works as
  if you were home. A network that only *looks* like home (same address range)
  doesn't count; the app checks that your home node actually answers there.
- **Exit node** (optional): away from home, all internet traffic can leave
  through one of your VPSs; see [Exit nodes](#exit-nodes-browse-through-a-vps).

**Admin from the phone:** the **Admin** card opens the full dashboard, which is
built into the app. Sign in with the dashboard admin login. The app manages
the mesh through **any of your servers** (pfSense, the VPS, …): if the one it
uses goes down, it moves on to the next without logging in again. No server
needs the web UI turned on for this, and the VPS serves no web pages: servers
only answer logged-in management requests from mesh devices, on the mesh-only
sync port. To keep a server out of it: **Nodes** → **Edit** → untick *Phone app
may manage the mesh through this node*.

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
| On that machine | `https://127.0.0.1:8080` |
| On any device in the mesh (phone, laptop) | `https://<that node's mesh IP>:8080` (mesh IPs are shown by `meshgate status`) |
| pfSense | *VPN → meshgate* in the pfSense GUI |
| Android app | the **Admin** card (built into the app; works through any server) |
| From outside the mesh, on a VPS | `ssh -L 8080:127.0.0.1:8080 you@vps`, then `https://localhost:8080` |

The dashboard is not on the public internet by default. Tabs: **Nodes**,
**Traffic**, **Port forwards**, **HTTPS**, **Access rules**, **Exit routes**, **Add devices**, **Tools**, **Settings**
(traffic history, Let's Encrypt email, admin login, web UI certificate).

**HTTPS, set up by itself:** the web UI always uses HTTPS. Each server makes
its own small certificate authority (`/var/lib/meshgate/webui-ca.crt`) and
uses it to sign a certificate for its mesh IP, localhost, its name and the
addresses it listens on (`webui.crt`), renewed a month before it expires or
when an address changes. Old `http://` links still work: they're sent to
`https://` on the same port. No public authority signs certificates for
private and mesh IPs, so the browser warns until you **install the server's
CA** on the device, once: `meshgate webui ca` shows how, and *Settings → Web
UI certificate* has a download link. After that there is no warning, and a
man in the middle gets a hard error instead of a warning to click through.
The CA can only vouch for that server's names and addresses and the mesh
range, not for other websites. Before installing it, compare its fingerprint
with `meshgate webui ca`. Without the CA installed, compare the SHA-256
fingerprint the browser shows with `meshgate status` on a server (or
*Settings → Web UI certificate* on a page opened over a mesh IP). Over a
mesh IP, WireGuard already checks you're talking to your server; on LAN or
public addresses (`--public`) the fingerprint check is what stops a man in the
middle, so do it before typing the admin password. To serve plain http
instead: `sudo meshgate webui enable --http`.

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

The TUI can do everything the web UI can. Sections: `1` Nodes, `2` Forwards,
`3` HTTPS, `4` Rules, `5` Exit routes, `6` Devices, `7` Traffic, `8` Tools,
`9` Logs, `0` Settings, then Changes (`Tab` moves through all of them). Keys: `a` add, `e`/`Enter` edit or run,
`t` turn on/off, `d` delete, `c` drop a local-only override, `w` WireGuard app
config, `s` Let's Encrypt email, `y` theme, `r` refresh, `q` quit.

- **Nodes:** `u` updates the selected node, `Ctrl+U` every node behind the
  latest release. Editing a server offers the LAN/VLAN subnets it has that
  are not shared yet.
- **Traffic:** live speeds and totals per monitor, target IP, forward, site,
  device and rule, plus recent HTTPS requests; `a` adds a monitor. `m`
  switches to history (`v` changes the period, `o` saves it as CSV).
- **Tools:** ping, traceroute, TCP/UDP port, HTTP and "my public IP" checks
  from this node, with quick picks for devices, forwards and sites.
- **Logs:** every node's meshgate log in one place (`i` important/all, `f`
  node, `v` period, `/` search, `Enter` the full line).
- **Settings:** traffic history storage, the web UI admin login and the web
  UI certificate fingerprints.

### Event log

Every node copies its meshgate log lines to the log server (the one that
keeps traffic history) every 10 seconds; read them under **Logs** in the web
UI or TUI. A node that cannot reach the log server keeps the newest 2,000
undelivered lines in RAM and sends them, with their original times, once it
can; meanwhile that node's own dashboard or TUI shows them, marked *in RAM*.
Lines are kept as long as traffic history (365 days by default).

Links between servers are watched: a link with no WireGuard handshake for 3
minutes is logged as `DOWN` (with whether the other side still answers), and
`UP again after …` when it returns. pfSense/FreeBSD nodes also play a falling
tune on the PC speaker when a link drops and a rising one when it is back
(turn it off per node: Nodes → Edit → Beep).

### Commands

| Command | Does |
|---|---|
| `meshgate status` | devices, mesh IPs, path (direct / via relay), last handshake |
| `meshgate tui` | the terminal UI |
| `meshgate token [--kind server] [--uses N] [--ttl 24h]` | join token (default: one phone/laptop, valid 24 h) |
| `meshgate webui enable \| disable` | host the dashboard on this node, or stop |
| `meshgate webui ca [--pem] [--new]` | the dashboard's CA and how to install it (no more certificate warnings) |
| `meshgate pfsense install \| remove` | pfSense GUI integration (VPN menu, MESHGATE rules tab) |
| `meshgate diag myip \| ping \| trace \| tcp \| udp \| http …` | test connectivity from this node (see [Testing](#testing-that-everything-works)) |
| `meshgate ports` | ports this node uses |
| `meshgate leave` | remove meshgate's config from this machine |
| `meshgate update [--check]` | install the latest release (verified) and restart |
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
2. Web UI → **HTTPS** → **New route**: hostname `jellyfin.example.com`, edge =
   VPS, target = home server, port 8096.

A Let's Encrypt email is optional (web UI → **Settings**, TUI: `s`):
certificates are issued without one; with one, Let's Encrypt can reach you
about your account.

The VPS gets the certificate, redirects HTTP to HTTPS and passes requests to
your home server through the mesh. Needs TCP 80 and 443 open on the VPS.

### Control what mesh devices can reach

- **pfSense:** use *Firewall → Rules → MESHGATE* (see [pfSense](#pfsense)).
  Rules see each device's mesh IP (e.g. `100.88.12.34`) as the source, so you
  can allow single devices.
- **Linux home server:** web UI → **Nodes** → **Edit** → *LAN policy:
  Restricted* (TUI: `1`, `e`). Then add **Access rules**: from which devices,
  to which host / subnet / VLAN / this node, which protocol (tcp, udp, tcp + udp, icmp or any) and ports.

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

### Exit nodes (browse through a VPS)

An **exit node** sends a device's internet traffic out through one of your
servers, so websites see that server's IP instead of the network you're on.
With several VPSs, each device can use a different one.

1. Web UI → **Nodes** → **Edit** on the VPS → tick *Exit node* (TUI: `1`, `e`).
2. **Edit** on the phone → *Internet traffic away from home* → *Through vps*.

The phone shows *Internet: through vps* when it's active. If that exit goes
down, the phone moves to another exit node within seconds. **Exit only**
(on the phone's Edit) decides what happens when *no* exit is reachable: off
(default) uses the phone's own connection, on blocks internet until an exit is
back.

**Kill switch** (in the app, kept on the phone): the same as *Exit only*, but
you flip it yourself. While meshgate runs, internet only goes through an exit
node; with none reachable, or if the tunnel can't start, it's blocked. Turning
meshgate off is your deliberate choice and gives normal internet again. To also
block while the app is not running at all (crashed, killed), turn on Android's
*Always-on VPN* + *Block connections without VPN* (the card has a shortcut);
note that Android then blocks even when you switch meshgate off on purpose. Its DNS lookups go
through the exit too. At home the phone uses your own connection, and your
home network stays reachable everywhere. Turn it off again with *Its own
connection*.

- Supported in the Android app. Linux and Windows clients don't use exit nodes
  yet.
- Exit traffic only goes to the internet: it can't reach the exit node's own
  LANs or private networks.
- All browsing then uses the VPS's bandwidth, and some sites challenge VPS IPs
  more often.

### Watch live traffic

Web UI or app → **Traffic** (refreshes every 3 seconds):

- **By target IP:** every port forward and HTTPS route to the same machine
  added up (e.g. `192.168.1.205` = minecraft + valheim), busiest first, with
  live speed to and from it and the total. Handy for spotting which game or
  machine is using a lot.
- **Port forwards:** speed and totals per forward, both directions.
- **HTTPS routes:** requests per minute, errors, speed, totals, and the last
  requests (time, visitor IP, path, status, size, how long it took).
- **Devices:** live speed of each mesh device's link.
- **Access rules:** how many connections each rule let through.

Forwards and rules are counted by the server that runs them (the edge VPS for
forwards); the dashboard gathers every server's numbers over the mesh, so you
see them from pfSense or the phone too. Totals count since meshgate last
started on that server. Port-forward and rule counters come from Linux servers;
on pfSense use *Status → Traffic Graph* and the MESHGATE rules tab for its side.

### Traffic history (graphs over time)

Every server counts the exact bytes of everything it handles and every 5
minutes hands one point per series (bytes in, bytes out and the peak speed) to
the mesh's **log server**, which keeps one file per day under
`/var/lib/meshgate/history` (past days gzip-compressed) plus `labels.json`.
Kept 365 days by default: about 10-40 MB a year for a home mesh.

What gets logged, each on its own:

- every **port forward**: its public port(s), protocol, target IP and port,
  and which node it runs on;
- every site, with **HTTPS and HTTP counted separately**: hostname, target IP
  and port;
- every **device link** (WireGuard traffic between a server and each device or
  node).

Totals are never stored, they are added up when shown: the graph and the
downloads can show any target IP, any public port, any node (all its links)
or everything together. The labels are kept with the history, so a forward
you deleted still shows up (marked *deleted*) with its port and target.

- **Pick the log server:** web UI → **Settings → Traffic history**: choose the
  server (e.g. your VPS) and how many days to keep. Left on *automatic*, it's
  the first relay. Other servers send their points to it over the mesh and
  keep them in memory while it's unreachable (about a day's worth).
- **View it:** web UI or app → **Traffic → History**: 6 hours, day, week,
  month or year, for everything together, per target IP, per public port,
  per node, one forward, one site (HTTPS or HTTP) or one device link. In the
  TUI: `8`, `v` for the period.

Changing the log server moves the history: within 5 minutes the old log
server sends its day files to the new one (merged with anything already
there) and deletes each file once the new server has it. If the old server is
offline at the time, it moves them when it comes back.

The graph shows the total, peak and average for the period above it. Hover it
(or tap it on a phone, arrow keys on a keyboard) to read the exact speeds,
peaks and amount sent for any point. The *To target / From target / Peaks*
buttons hide or show each line; the period and choice are remembered.

**Download it:** **Traffic → History → Download…**: pick the days (Today,
Yesterday, Last 7 days, This month, Last month, This year, … or any From/To
days), the detail (5 minutes, 15 minutes, 1 hour or 1 day), the format (CSV for
Excel or Sheets, JSON, or a readable text table) and either what the graph
shows or every series separately. Each row has the time, what the series is
(kind, name, hostname, protocol, port, target IP and port, target node, the
node that measured it), the exact **bytes** in, out and total, and the peak
speed in bytes per second. Totals per series come at the end (CSV: `TOTAL`
rows; JSON: `total`; text: a `TOTAL` line), plus overall totals when several
series are in the file: forwards and sites apart from device links, since a
forward's traffic also crosses a link. One download holds up to 9000 rows per
series (a month at 5 minutes, a year at 1 hour). In the app it opens Android's
*Save as*.

### Testing that everything works

meshgate has a small built-in test kit, so you can check each piece without
setting up real services first.

**Test service.** Web UI → **Nodes** → **Edit** on a server → *Test service
port*, e.g. `8099` (TUI: `1`, `e`). That node now answers on TCP and UDP 8099
and tells you which node answered and which address you came from. Turn it off
again by clearing the field.

- **Port forward:** forward a VPS port (TCP and UDP) to that node, port 8099,
  then open `http://<VPS IP>:<port>` from outside, e.g. your phone on mobile
  data with the tunnel off. With *show players' real IPs* on, it shows your
  real address.
- **HTTPS route:** point a route at that node, port 8099, and open
  `https://<hostname>`. It shows the original client address the VPS passed on.

**Checks.** Run them from the dashboard (**Tools** tab, runs on the node
serving the page), the command line, or the phone (**Tests** in the app, runs on
the phone through the tunnel). In the dashboard, **Quick pick** lists your
mesh devices, servers' public addresses, both ends of every port forward and
your HTTPS sites; picking one fills in the target (and port), or type any
address yourself:

| Check | Command | Shows |
|---|---|---|
| My public IP | `meshgate diag myip` | the IP websites see; on the phone it also says whether that's your exit node |
| Ping | `meshgate diag ping 100.88.x.y` | reachability and latency |
| Traceroute | `meshgate diag trace 192.168.1.20` | the hops on the way (not on phones) |
| TCP port | `meshgate diag tcp <host> 25565` | whether a port is open |
| UDP | `meshgate diag udp <host> 8099` | an answer from a meshgate test service (UDP has no handshake) |
| HTTP/HTTPS | `meshgate diag http https://jellyfin.example.com` | status, timing, certificate issuer and expiry |

The phone's public-IP check uses `api.ipify.org`.

### Permissions: which exits a device may use

On a phone or laptop's **Edit**, *May use exit nodes* lists what that device is
allowed: specific exit nodes, or *any exit node* (including ones added later).
The exit nodes enforce it: they only pass internet traffic for devices allowed
to use them. *Default* is the admin's pick; the device can change it itself
among its allowed exits (app → *Change exit node*), and failover only moves
between allowed exits. With nothing ticked, a device that has a default exit
may use any exit (as before).

Each device sees its permissions live in the app (*Your access*): the exit
nodes it may use with their up/down state, and what it may reach on each
router (the whole subnet on an open policy, exactly its access rules on a
restricted one, or "as pfSense's MESHGATE rules allow"). Devices only receive
the access rules that concern them. In the TUI the node list shows
`may use vps/vps2`.

### Send LAN devices (VMs, a VLAN) through an exit node: Exit routes

Devices behind your router that don't run meshgate (VMs, consoles, a whole
VLAN) can use an exit node too, one route each, like port forwards:

1. Tick *Exit node* on the VPS (**Nodes → Edit**).
2. **Exit routes → New exit route** (TUI: `5`, `a`): a name, the device's IP or
   subnet (e.g. `192.168.200.11` or `192.168.20.0/24`) and the exit node. The
   router is picked automatically: the node whose *Shared LAN subnets* contain
   that IP (pfSense, or a Linux server sharing the LAN).

That device's internet traffic then leaves through the VPS (websites see its
IP), while everything else on your network keeps using your normal connection
and every device can still reach the mesh. Each route can be switched off,
edited or deleted on its own. If the exit goes down the router fails over to
another exit node; with none left, routes marked *Exit only* get no internet and
the others use your normal connection. For a VLAN that should *only* reach the
internet through the exit, tick *Exit only* and block its normal internet in
pfSense as well; meshgate's rules come first, so the exit keeps working. One
router uses one exit node at a time. If those devices use pfSense for DNS,
their lookups still leave from your home IP; point them at a public resolver
(e.g. `1.1.1.1`) to send DNS through the exit too.

### Every change: all nodes or only this node

When you save something you choose **all nodes** (shared with the whole mesh,
the default) or **only this node** (a local override, e.g. to test a change on
one machine). `c` in the TUI drops a local override again.

## Update and uninstall

**Update:**

- **One machine:** `sudo meshgate update` (`meshgate update` on pfSense or in an
  Administrator terminal on Windows). It downloads the latest release, checks it
  against the release's `SHA256SUMS`, swaps it in and restarts meshgate.
  `meshgate update --check` only tells you whether one is available.
- **From the dashboard or the app's Admin:** **Nodes** shows every device's
  version and marks outdated ones; **Update** updates that node remotely and
  **Update all** does every outdated server and Linux/Windows client. In the TUI,
  select a node and press `u`. Only servers can trigger updates, and nodes only
  ever install the official, checksum-verified release.
- **Phone:** the app's **Updates** card shows when a new version is out;
  **Update** downloads and verifies it, then Android asks you to confirm the
  install (Android never lets apps update silently, so phones can't be updated
  remotely). This needs the APK release-signed (see *Releases*), otherwise
  Android refuses to install it over the old one.
- Running the install command again also still works, and keeps your settings.

**What changed:** the dashboard's **Changelog** tab, the TUI's **CHANGES** tab
(`7`) and the app's **Updates → What's new** show the changes of the version
you run (`+` added, `-` removed, `~` changed or fixed). The file is
[internal/changelog/CHANGELOG.md](internal/changelog/CHANGELOG.md); new entries go
under `## Unreleased`, which each release build stamps with its version.

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
| Friends can't connect to a forward | Open the port in your VPS provider's firewall and check the forward is on. ufw, firewalld and Docker are handled automatically: meshgate adds a `meshgate: forward <name>` rule to ufw or firewalld for each forward (`sudo ufw status` / `sudo firewall-cmd --list-ports` shows them), and each Linux server keeps a `MESHGATE` chain in iptables' FORWARD chain with exactly its own forwards (its ports and protocol, gone when you disable the forward), relaying and exit traffic; `sudo iptables -S MESHGATE` shows it, and **Nodes → Edit** can switch it off per server. `sudo meshgate diag tcp <target IP> <port>` on the VPS tells you whether the game server answers through the mesh. |
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
| TCP 51823 | every server, mesh only | config sync between servers; the phone app's management requests |
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
- **ufw / firewalld:** they still filter traffic alongside meshgate. The
  installer allows traffic on the mesh interface `mg0` in them, and every
  Linux server keeps them open for what it needs from outside: its WireGuard,
  probe and join ports, 80 and 443 when it is an HTTPS edge, and each port
  forward it is the edge of (ufw: a `route allow` rule to the forward's
  target). Every rule is commented `meshgate: …`, is removed again when the
  forward or route goes away or is switched off, and is checked every minute,
  so a firewall you turn on later is picked up. Rules you added yourself are
  never removed. Switch it off per server: **Nodes → Edit** → *Open ports in
  ufw / firewalld automatically*.
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

### Security

| Area | Protection |
|---|---|
| Joining | Tokens are random 192-bit secrets, stored only as SHA-256 hashes, single-use and expiring by default; the join API uses TLS pinned by the token. A token only admits its own kind of device (a phone token can never become or impersonate a server). |
| Who can change config | Only server nodes. Phones and laptops can only publish their own status; servers identify each other by mesh IP, which WireGuard authenticates, and mesh addresses arriving on any other interface are dropped (anti-spoofing). |
| Admin login | bcrypt password hash; 5 wrong tries lock an address out for 10 minutes. Browser sessions: `HttpOnly`, `SameSite=Strict` cookie, CSRF header, strict Content-Security-Policy, no framing. Phone app: a 12-hour token signed with a key derived from the password hash, kept in memory only; changing the password revokes all tokens. |
| Exposure | The dashboard and management API listen on localhost and mesh IPs only (never the internet unless you pass `--web-public`). The test service is off unless you turn it on, and its UDP replies are never larger than the request (no amplification). |
| Input | Device and item names reject control and invisible characters (no terminal or display tricks); endpoints, hostnames, subnets and ports are validated; everything shown in the dashboard is escaped. |
| Install | The installers verify each download against the release's `SHA256SUMS`. Key and state files are readable by root only. |

What's left to you: keep server tokens to yourself (a server can change
everything), use a strong admin password, and keep meshgate updated. Found
something? Please open an issue.

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

Not yet: IPv6 inside the mesh, MagicDNS-style names, exit nodes for Linux and
Windows clients, rules between
two mesh devices (rules cover traffic into LANs and to nodes), NAT hole
punching between two NATed homes (relays are used instead).
