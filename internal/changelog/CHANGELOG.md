# Changelog

`+` added · `-` removed · `~` changed or fixed

## Unreleased
~ Port forwards, relays and exit nodes work on Linux servers running ufw or Docker (their FORWARD policy DROP used to block them silently)
+ iptables MESHGATE chain with exact rules: each forward only on its edge node, for its own ports and protocol, removed when the forward is disabled or deleted
+ Per-server switch to keep meshgate out of iptables (Nodes → Edit)
+ Traffic history: 5-minute averages and peaks per forward, HTTPS route, target IP and device link, kept a year (Traffic → History in the dashboard and app: 6 hours to 1 year)
+ Log server setting (Settings → Traffic history): pick which server stores the history (e.g. the VPS) and how many days to keep
+ TUI: TRAFFIC tab (8) with the history, `v` changes the period

## v0.2.13 · 2026-10-17
+ Changelog in the dashboard (Changelog tab), the TUI (CHANGES tab) and the app (Updates → What's new)

## v0.2.12 · 2026-10-17
~ Android: the APK is signed with the permanent release key, so in-app updates install over the old app (one last reinstall needed when coming from an older APK)

## v0.2.11 · 2026-10-17
~ Dashboard: browsers no longer keep an old copy after an update (pfSense page and web UI)

## v0.2.10 · 2026-10-17
+ Exit routes tab: send a LAN device or subnet (e.g. 192.168.200.11) through an exit node, one route each with on/off, edit, delete and its own Exit only
+ TUI: EXITS tab (5); Devices moved to 6
+ pfSense VPN → meshgate: fills the whole window, uses the full width, Full screen button
~ Routers' exit routes are no longer blocked by device exit permissions
~ Reinstalling or updating on pfSense keeps the LAN policy you chose
~ Servers check for new releases every 30 minutes (was 6 hours)
~ Long subnet lists wrap in the Nodes table
~ The router's Edit dialog points to the Exit routes tab (the old LAN-exit box only shows while it still has entries)

## v0.2.9 · 2026-10-17
+ Updates: `meshgate update` (checksum-verified, restarts by itself), Version column and Update / Update all in the dashboard, `u` in the TUI, Updates card in the app
+ Exit failover: devices move to another exit node when theirs goes down
+ Exit only: no internet instead of the normal connection when no exit node is reachable (devices and routers)
+ Kill switch in the app, plus a fail-closed tunnel when the app cannot start
+ Permissions: which exit nodes each device may use (enforced by the exits); devices pick among them in the app
+ App: Your access card (allowed exits with live state, what the device can reach), exit picker
+ LAN exits: send devices behind pfSense or a Linux router through an exit node
~ Path selection tracks which peers answer, so dead relays and exits are noticed
~ Devices receive the access rules that concern them (for Your access)
~ Release workflow warns when the APK is not release-signed

## v0.2.8 · 2026-10-13
+ Tools: Quick pick of devices, public addresses, forwards and sites, or type any target
+ Access rules: tcp + udp in one rule
~ Security: a phone token can no longer fetch a server's config by reusing its public key
~ Security: mesh addresses arriving from outside the tunnel are dropped (anti-spoofing)
~ Security: names reject control and invisible characters; endpoints, hostnames and LAN policies are validated
~ Security: the test service's UDP replies are never larger than the request
~ Installers verify every download against the release's SHA256SUMS

## v0.2.7 · 2026-10-13
+ Traffic tab: live speed and totals per target IP, port forward, HTTPS route (with recent requests), device and access rule
+ App: the admin dashboard is built into the app and works through any server; logging in once is enough when one goes down
+ Phone app may manage the mesh through this node: per-server switch
+ Test service and checks: ping, traceroute, TCP, UDP, HTTP(S) and My public IP, in the Tools tab, `meshgate diag` and the app's Tests screen

## v0.2.6 · 2026-10-13
~ App: forms (new forward, rule, route) no longer open squashed to a sliver; they open as a bottom sheet with Save/Cancel always visible

## v0.2.5 · 2026-10-13
~ Android: connecting no longer fails with "operation not permitted"

## v0.2.4 · 2026-10-13
+ Exit nodes for the phone app: away from home, internet traffic leaves through a chosen server
+ Home detection: a network counts as home only when the home node answers on it
+ App: redesigned main screen (connection card, devices list with status dots, dynamic colours)
~ Setup no longer treats VPN tunnel interfaces (another WireGuard, OpenVPN, Tailscale) as LANs

## v0.2.3 · 2026-10-13
+ Dashboard on phones: compact sticky header, swipeable tabs, tables as cards
~ App: admin dashboard uses the full width; join screen scrolls

## v0.2.2 · 2026-10-13
+ App: Admin card always shown, explaining what is missing
~ pfSense install turns on the web UI for mesh devices only, so the phone's Admin works

## v0.2.1 · 2026-10-13
+ Every push to main that passes CI is released automatically
~ README rewritten: quick start, per-platform install, web UI vs TUI, common tasks, troubleshooting, advanced

## v0.2.0 · 2026-10-12
+ pfSense: VPN → meshgate page with the full dashboard behind the pfSense login
+ pfSense: MESHGATE interface with its own Firewall → Rules tab (firewall LAN policy)
~ pfSense: mesh interface renamed tun_mg0

## v0.1.1 · 2026-10-12
~ Android build: create the libs folder before building the Go core

## v0.1.0 · 2026-10-12
+ First release: WireGuard mesh with automatic paths and relays, port forwarding, HTTPS routes, access rules, web UI, TUI, Android app, pfSense and Windows nodes
~ Test lab: the game-server test no longer resets connections
