//! `meshgate init` and `meshgate join` (Go: cmd/meshgate/setup.go).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;

use super::flags::Flags;
use super::term::{ask, ask_password, ask_yes};
use crate::config;
use crate::fw;
use crate::join;
use crate::model::{self, Network, Node};
use crate::netx;
use crate::ops;
use crate::ports;
use crate::probe;
use crate::store::{Scope, Store};

/// Ports chosen during setup.
#[derive(Default)]
struct PortPlan {
    wg: i64,
    join: i64,
    mesh: i64,
    web: i64,
}

/// What both init and join collect about this machine.
#[derive(Default)]
pub struct Answers {
    pub name: String,
    pub endpoints: Vec<String>,
    pub relay: bool,
    pub routes: Vec<String>,
    pub port: i64,
    pub join_port: i64,
    pub lan_policy: String,
}

fn add_machine_flags(f: &mut Flags) {
    f.str("name", "", "node name (default: hostname)")
        .bool("no-routes", false, "do not share any LAN subnet")
        .bool("relay", false, "act as relay (this node has a public endpoint)")
        .int("port", model::DEFAULT_WG_PORT, "WireGuard UDP port (probes use port+2)")
        .str("data-dir", &config::default_data(), "state directory")
        .bool("userspace", false, "always use built-in userspace WireGuard")
        .str(
            "lan-policy",
            "",
            "open | restricted | firewall: who may reach shared subnets (default: restricted on pfSense/FreeBSD, open on Linux)",
        )
        .int("web-port", model::DEFAULT_WEB_PORT, "web UI TCP port")
        .bool("y", false, "do not ask questions; use flags and defaults")
        .list("endpoint", "host:port others can reach this node at (repeatable)")
        .list("route", "LAN subnet to share, e.g. 192.168.1.0/24 (repeatable)");
}

/// Picks free ports: busy default ports move to the next free one; a port
/// given explicitly is never moved silently.
fn choose_ports(f: &Flags, port: &mut i64, kind: &str, webui: bool) -> Result<PortPlan, String> {
    let mut p = PortPlan::default();
    let want = *port;
    let wg = ports::wireguard(want).ok_or_else(|| format!("no free UDP port pair found near {want}"))?;
    if wg != want && f.explicit("port") {
        return Err(format!(
            "UDP port {want} (or {} for probes) is already in use; choose another --port, or leave it out to pick one automatically",
            want + probe::OFFSET
        ));
    }
    if wg != want {
        println!("UDP {want} is already in use (another WireGuard?); using {wg} instead (probes on {}).", wg + probe::OFFSET);
    }
    p.wg = wg;
    *port = wg;
    let mut taken = HashSet::new();
    let mut pick = |want: i64, what: &str, explicit: bool| -> Result<i64, String> {
        let got = ports::tcp(want, &taken).ok_or_else(|| format!("no free TCP port found near {want} for {what}"))?;
        if got != want && explicit {
            return Err(format!("TCP port {want} for {what} is already in use; choose another, or leave it out to pick one automatically"));
        }
        if got != want {
            println!("TCP {want} is already in use; {what} will use {got} instead.");
        }
        taken.insert(got);
        Ok(got)
    };
    p.mesh = pick(model::DEFAULT_MESH_PORT, "mesh sync", false)?;
    if kind == model::NODE_SERVER {
        p.join = pick(model::DEFAULT_JOIN_PORT, "joins", false)?;
    }
    if webui {
        p.web = pick(f.get_int("web-port"), "the web UI", f.explicit("web-port"))?;
    }
    Ok(p)
}

fn new_node_config(f: &Flags, kind: &str, pp: &PortPlan) -> Result<(config::Node, [u8; 32]), String> {
    let key = crate::wg::generate_private_key();
    let data = f.get_str("data-dir");
    let mut cfg = config::Node {
        private_key: crate::wg::key_string(&key),
        kind: kind.into(),
        data_dir: data.clone(),
        userspace: f.get_bool("userspace"),
        ..Default::default()
    };
    if data != config::default_data() {
        cfg.socket = Path::new(&data).join("meshgate.sock").to_string_lossy().into_owned();
    }
    cfg.mesh_port = pp.mesh;
    cfg.defaults();
    if kind == model::NODE_SERVER {
        cfg.join_listen = format!(":{}", pp.join);
    }
    config::secure_dir(Path::new(&cfg.data_dir)).map_err(|e| e.to_string())?;
    Ok((cfg, key))
}

pub async fn cmd_init(cfg_path: &str, args: &[String]) -> Result<(), String> {
    let mut f = Flags::new("init");
    f.str("role", "", "controller (web UI, new mesh) | webui (web UI, join mesh) | server (node, join mesh) | standalone (node, new mesh)")
        .str("cidr", "100.88.0.0/16", "mesh address range")
        .str("admin-user", "admin", "web UI admin username")
        .str("admin-pass", "", "web UI admin password (prompted if empty)")
        .str("acme-email", "", "Let's Encrypt email for HTTPS routes")
        .bool("web-public", false, "serve the web UI on all interfaces");
    add_machine_flags(&mut f);
    f.parse(args);
    if Path::new(cfg_path).exists() {
        return Err(format!("{cfg_path} already exists; this machine is already set up (use `meshgate leave` to start over)"));
    }
    let mut r = f.get_str("role");
    if r.is_empty() {
        println!(
            "Welcome to meshgate. What is this machine?
  1) Web UI   - start a new mesh and host the dashboard here
  2) Web UI   - add the dashboard to an existing mesh (needs a server token)
  3) Node     - join an existing mesh (managed with the TUI or the web UI)
  4) Node     - start a new mesh without a web UI (TUI only)

Every node has the TUI (sudo meshgate tui); the web UI only runs where you
install it, and nodes keep working when it is offline."
        );
        r = match ask("Choose 1-4", "1").as_str() {
            "1" => "controller",
            "2" => "webui",
            "3" => "server",
            "4" => "standalone",
            _ => return Err("invalid choice".into()),
        }
        .into();
    }
    match r.as_str() {
        "server" | "webui" => {
            let mut extra = vec![ask("Paste the join token (server type)", ""), "--kind".into(), "server".into()];
            if r == "webui" {
                extra.push("--webui".into());
                if f.get_bool("web-public") {
                    extra.push("--web-public".into());
                }
            }
            extra.extend(args.iter().cloned());
            return Box::pin(cmd_join(cfg_path, &extra)).await;
        }
        "controller" | "standalone" => {}
        _ => return Err(format!("unknown role {r:?}")),
    }
    let webui = r == "controller";
    let mut port = f.get_int("port");
    let pp = choose_ports(&f, &mut port, model::NODE_SERVER, webui)?;
    let mut a = gather_machine(model::NODE_SERVER, &f, port);
    a.join_port = pp.join;
    let yes = f.get_bool("y");
    let mut cidr = f.get_str("cidr");
    if !yes {
        cidr = ask("Mesh address range", &cidr);
    }
    if netx::parse_prefix(&cidr).is_none() {
        return Err(format!("mesh range: netip.ParsePrefix({cidr:?}): invalid prefix"));
    }
    let (mut admin_user, mut admin_pass) = (f.get_str("admin-user"), f.get_str("admin-pass"));
    if webui && admin_pass.is_empty() {
        if !yes {
            admin_user = ask("Web UI admin username", &admin_user);
        }
        admin_pass = ask_password("Web UI admin password")?;
    }
    let mut acme = f.get_str("acme-email");
    if !yes && acme.is_empty() {
        acme = ask("Email for Let's Encrypt certificates (optional, for notices about HTTPS routes)", "");
    }
    let (mut cfg, key) = new_node_config(&f, model::NODE_SERVER, &pp)?;
    cfg.node_id = join::random_id();
    let (_, fp) = join::ensure_cert(&cfg.cert_path(), &cfg.key_path())?;
    let s = Arc::new(Store::open(Some(cfg.state_path()), &cfg.node_id)?);
    let now = crate::util::now_unix();
    let netw = Network { name: "main".into(), cidr: cidr.clone(), acme_email: acme, created_at: now, ..Default::default() };
    s.put("network/main", &netw, Scope::Cluster)?;
    // The first node is registered directly; everyone else uses a token.
    let ip = join::allocate_ip(&netw, &[])?;
    let mut me = Node {
        id: cfg.node_id.clone(),
        name: a.name.clone(),
        kind: model::NODE_SERVER.into(),
        public_key: crate::wg::key_string(&crate::wg::public_key(&key)),
        mesh_ip: ip.to_string(),
        listen_port: a.port,
        endpoints: a.endpoints.clone(),
        relay: a.relay,
        routes: a.routes.clone(),
        lan_policy: a.lan_policy.clone(),
        webui,
        web_port: pp.web,
        mesh_port: pp.mesh,
        created_at: now,
        ..Default::default()
    };
    let addr = join_addr(&a);
    if !addr.is_empty() {
        me.join_addr = addr;
        me.join_fp = fp;
    }
    s.put(&model::key(model::KIND_NODE, &me.id), &me, Scope::Cluster)?;
    if webui {
        ops::Service::new(s.clone(), &me.id).set_admin(&admin_user, &admin_pass)?;
        cfg.web_listen = web_listen(&me.mesh_ip, pp.web, f.get_bool("web-public"), yes);
    }
    config::save(cfg_path, &cfg).map_err(|e| e.to_string())?;
    println!("\nCreated mesh {cidr}. This node is {} ({}).", me.name, me.mesh_ip);
    print_next_steps(&me, &cfg, &a);
    Ok(())
}

pub async fn cmd_join(cfg_path: &str, args: &[String]) -> Result<(), String> {
    let mut f = Flags::new("join");
    f.str("kind", "", "server or client (default: ask)")
        .bool("webui", false, "also host the web UI on this node")
        .bool("web-public", false, "serve the web UI on all interfaces")
        .str("admin-user", "admin", "web UI admin username (only if the mesh has none yet)")
        .str("admin-pass", "", "web UI admin password");
    add_machine_flags(&mut f);
    // The token may come before or after the flags.
    let (mut tok_str, rest) = match args.first() {
        Some(a) if !a.starts_with('-') => (a.clone(), &args[1..]),
        _ => (String::new(), args),
    };
    f.parse(rest);
    if tok_str.is_empty() {
        tok_str = f.arg(0);
    }
    if tok_str.is_empty() {
        tok_str = ask("Paste the join token", "");
    }
    let tok = join::decode(&tok_str)?;
    if Path::new(cfg_path).exists() {
        return Err(format!("{cfg_path} already exists; this machine is already set up"));
    }
    let yes = f.get_bool("y");
    let webui = f.get_bool("webui");
    let mut k = f.get_str("kind");
    if webui {
        k = model::NODE_SERVER.into();
    }
    if k.is_empty() && !yes && ask("Is this a server (VPS / home server) or a client (laptop)? s/c", "s").starts_with('c') {
        k = model::NODE_CLIENT.into();
    }
    if k.is_empty() {
        k = model::NODE_SERVER.into();
    }
    let mut port = f.get_int("port");
    let pp = choose_ports(&f, &mut port, &k, webui)?;
    let mut a = gather_machine(&k, &f, port);
    a.join_port = pp.join;
    let (mut cfg, key) = new_node_config(&f, &k, &pp)?;
    let mut req = join::Request {
        name: a.name.clone(),
        kind: k.clone(),
        public_key: crate::wg::key_string(&crate::wg::public_key(&key)),
        endpoints: a.endpoints.clone(),
        routes: a.routes.clone(),
        relay: a.relay,
        listen_port: a.port,
        lan_policy: a.lan_policy.clone(),
        webui,
        mesh_port: pp.mesh,
        web_port: pp.web,
        ..Default::default()
    };
    if k == model::NODE_SERVER {
        let (_, fp) = join::ensure_cert(&cfg.cert_path(), &cfg.key_path())?;
        let addr = join_addr(&a);
        if !addr.is_empty() {
            req.join_addr = addr;
            req.join_fp = fp;
        }
    }
    println!("Joining...");
    let resp = tokio::time::timeout(std::time::Duration::from_secs(30), join::redeem(&tok, req))
        .await
        .unwrap_or_else(|_| Err("context deadline exceeded".into()))
        .map_err(|e| format!("join failed: {e}"))?;
    cfg.node_id = resp.node.id.clone();
    let s = Arc::new(Store::open(Some(cfg.state_path()), &cfg.node_id)?);
    s.merge(resp.entries.clone())?;
    if webui {
        cfg.web_listen = web_listen(&resp.node.mesh_ip, pp.web, f.get_bool("web-public"), yes);
        ensure_admin(&s, &resp.node.id, &f.get_str("admin-user"), &f.get_str("admin-pass"))?;
    }
    config::save(cfg_path, &cfg).map_err(|e| e.to_string())?;
    println!("Joined as {} ({}).", resp.node.name, resp.node.mesh_ip);
    print_next_steps(&resp.node, &cfg, &a);
    Ok(())
}

/// How this machine is reached, from flags and (unless -y) questions.
fn gather_machine(kind: &str, f: &Flags, port: i64) -> Answers {
    let host = crate::webtls::hostname().unwrap_or_default();
    let mut a = Answers {
        port,
        name: f.get_str("name"),
        relay: f.get_bool("relay"),
        endpoints: f.get_list("endpoint"),
        routes: f.get_list("route"),
        ..Default::default()
    };
    let interactive = !f.get_bool("y");
    if a.name.is_empty() {
        a.name = if interactive { ask("Name for this node", &host) } else { host };
    }
    if kind != model::NODE_SERVER {
        return a;
    }
    // Windows and macOS nodes cannot route into their LAN; share nothing.
    let no_routes = f.get_bool("no-routes") || cfg!(any(windows, target_os = "macos"));
    let lan_flag = f.get_str("lan-policy");
    if !a.endpoints.is_empty() || !interactive {
        // Explicit flags (or -y): auto-detect only what was not given.
        let auto_endpoints = a.endpoints.is_empty();
        if auto_endpoints && let Some(src) = outbound_ip() {
            a.endpoints = vec![netx::join_host_port(&src.to_string(), a.port)];
            // A VPS with a public IP becomes a relay. A home router
            // (pfSense) does not unless asked: relaying uses its upload.
            a.relay = a.relay || (!src.is_private() && !is_cgnat(src) && !fw::is_pfsense());
        }
        if a.routes.is_empty() && !no_routes && !a.relay {
            a.routes = auto_routes();
        }
        if no_routes {
            a.routes.clear();
        }
        if auto_endpoints {
            a.endpoints = append_lan_endpoints(a.endpoints, &a.routes, a.port);
        }
        a.lan_policy = default_policy(&lan_flag);
        return a;
    }
    let src = outbound_ip();
    let mut public = String::new();
    if let Some(s) = src.filter(|s| !s.is_private() && !is_cgnat(*s)) {
        public = s.to_string();
    }
    println!("\nHow can other devices reach this machine?");
    public = ask("Public IP or DNS name (leave empty if behind home NAT with no port forward)", &public);
    if !public.is_empty() {
        a.endpoints.push(netx::join_host_port(&public, a.port));
        a.relay = ask_yes("Use this node as a relay for devices that cannot connect directly (recommended for a VPS)", true);
    }
    if let Some(s) = src.filter(|s| s.is_private() || is_cgnat(*s)) {
        let lan = netx::join_host_port(&s.to_string(), a.port);
        if ask_yes(&format!("Add LAN address {lan} so devices on the same network connect directly"), true) {
            a.endpoints.push(lan);
        }
    }
    if no_routes {
        return a;
    }
    println!("\nShare LAN subnets (VLANs) so mesh devices can reach other machines on this network.");
    let mut sugg = vec![];
    for l in fw::local_lans(config::DEFAULT_IFACE) {
        println!("  {:<18} on {}", l.cidr, l.iface);
        sugg.push(l.cidr);
    }
    let def = if a.relay { String::new() } else { sugg.join(",") };
    for r in ask("Subnets to share (comma separated, empty for none)", &def).split(',') {
        let r = r.trim();
        if !r.is_empty() {
            a.routes.push(r.to_string());
        }
    }
    let before = a.endpoints.len();
    a.endpoints = append_lan_endpoints(a.endpoints, &a.routes, a.port);
    for e in &a.endpoints[before..] {
        println!("  devices on that network will connect directly via {e}");
    }
    a.lan_policy = default_policy(&lan_flag);
    if !a.routes.is_empty() && lan_flag.is_empty() {
        println!(
            "
Who may reach these subnets (and this machine) through the mesh?
  1) Any mesh device
  2) Only what access rules allow (lock down: add rules per IP/port/VLAN
     in the TUI or web UI; port forwards and HTTPS routes keep working)"
        );
        let def = if a.lan_policy == model::POLICY_RESTRICTED { "2" } else { "1" };
        a.lan_policy = if ask("Choose 1 or 2", def) == "2" { model::POLICY_RESTRICTED } else { model::POLICY_OPEN }.into();
    }
    a
}

/// The local private networks to share (on pfSense not the WAN's).
fn auto_routes() -> Vec<String> {
    let wan = if fw::is_pfsense() { fw::detect_wan() } else { String::new() };
    fw::local_lans(config::DEFAULT_IFACE).into_iter().filter(|l| l.iface != wan).map(|l| l.cidr).collect()
}

/// Adds this machine's own address in every shared subnet.
fn append_lan_endpoints(mut eps: Vec<String>, routes: &[String], port: i64) -> Vec<String> {
    let mut have: HashSet<String> = eps.iter().cloned().collect();
    let ifs = crate::ifaces::list();
    for r in routes {
        let Some(pfx) = netx::parse_prefix(r) else { continue };
        for i in &ifs {
            for (a, _) in &i.addrs {
                if a.is_ipv4() && pfx.contains(*a) {
                    let e = netx::join_host_port(&a.to_string(), port);
                    if have.insert(e.clone()) {
                        eps.push(e);
                    }
                }
            }
        }
    }
    eps
}

/// Restricted on pfSense/FreeBSD (a firewall), open on Linux unless asked.
fn default_policy(flag: &str) -> String {
    match flag {
        model::POLICY_OPEN | model::POLICY_RESTRICTED | model::POLICY_FIREWALL => flag.into(),
        _ if cfg!(target_os = "freebsd") => model::POLICY_RESTRICTED.into(),
        _ => model::POLICY_OPEN.into(),
    }
}

pub fn web_listen(mesh_ip: &str, port: i64, public: bool, yes: bool) -> Vec<String> {
    if public || (!yes && ask_yes("Also serve the web UI on all interfaces (0.0.0.0)? Only do this behind a firewall", false)) {
        return vec![format!(":{port}")];
    }
    vec![format!("127.0.0.1:{port}"), netx::join_host_port(mesh_ip, port)]
}

pub fn listen_port(addr: &str) -> i64 {
    netx::split_host_port(addr).ok().and_then(|(_, p)| p.parse().ok()).unwrap_or(0)
}

/// Makes sure the mesh has a web UI login.
fn ensure_admin(s: &Arc<Store>, self_id: &str, user: &str, pass: &str) -> Result<(), String> {
    if !s.keys(model::KIND_ADMIN).is_empty() && pass.is_empty() {
        return Ok(());
    }
    let pass = if pass.is_empty() { ask_password("Web UI admin password")? } else { pass.to_string() };
    ops::Service::new(s.clone(), self_id).set_admin(user, &pass)
}

/// Where new devices can redeem tokens: the public endpoint's host.
fn join_addr(a: &Answers) -> String {
    if !a.relay || a.endpoints.is_empty() {
        return String::new();
    }
    netx::split_host_port(&a.endpoints[0]).map(|(h, _)| netx::join_host_port(&h, a.join_port)).unwrap_or_default()
}

/// The address our traffic to the internet leaves from; when another VPN
/// carries the default route, a real interface's address instead.
pub fn outbound_ip() -> Option<Ipv4Addr> {
    let ip = std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|c| {
            c.connect("1.1.1.1:80")?; // no packets are sent
            c.local_addr()
        })
        .ok()
        .and_then(|a| match a.ip() {
            IpAddr::V4(v) => Some(v),
            _ => None,
        });
    let ifs = crate::ifaces::list();
    if let Some(ip) = ip {
        let on_tunnel = ifs
            .iter()
            .find(|i| i.addrs.iter().any(|(a, _)| *a == IpAddr::V4(ip)))
            .is_some_and(|i| fw::is_tunnel(&i.name, i.point_to_point));
        if !on_tunnel {
            return Some(ip);
        }
    }
    let mut lan = None;
    for i in &ifs {
        if !i.up || i.loopback || fw::is_tunnel(&i.name, i.point_to_point) || is_bridge(&i.name) {
            continue;
        }
        for (a, _) in &i.addrs {
            let IpAddr::V4(v) = a else { continue };
            if !v.is_loopback()
                && !v.is_link_local()
                && !v.is_unspecified()
                && !v.is_broadcast()
                && !v.is_multicast()
                && !v.is_private()
                && !is_cgnat(*v)
            {
                return Some(*v);
            }
            if lan.is_none() && v.is_private() {
                lan = Some(*v);
            }
        }
    }
    lan
}

/// Container/VM bridges are not how other machines reach us.
fn is_bridge(name: &str) -> bool {
    ["docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "lxc"].iter().any(|p| name.starts_with(p))
}

fn is_cgnat(a: Ipv4Addr) -> bool {
    let o = a.octets();
    o[0] == 100 && (64..128).contains(&o[1])
}

fn print_next_steps(me: &Node, cfg: &config::Node, a: &Answers) {
    let sudo = if cfg!(target_os = "linux") { "sudo " } else { "" };
    println!("\nNext steps:");
    println!("  {:<40} # start the node (the installer does this)", super::service::START_HINT);
    if me.kind == model::NODE_SERVER {
        println!("  {:<40} # manage forwards, HTTPS routes, rules, devices", format!("{sudo}meshgate tui"));
        println!("  {:<40} # add a phone or laptop", format!("{sudo}meshgate token --kind client"));
    }
    if let Some(first) = cfg.web_listen.first() {
        let wp = listen_port(first);
        let scheme = if cfg.web_plain_http { "http" } else { "https" };
        println!("  web UI: {scheme}://{}  (from this machine: {scheme}://127.0.0.1:{wp})", netx::join_host_port(&me.mesh_ip, wp));
        if !cfg.web_plain_http {
            println!("          its certificate is self-signed: the browser asks you to accept it once");
        }
    }
    if a.relay {
        println!(
            "\nOpen these ports on this machine's firewall / cloud security group:\n  UDP {} (WireGuard), UDP {} (probes), TCP {} (joins)",
            a.port,
            a.port + 2,
            a.join_port
        );
    } else if me.kind == model::NODE_SERVER && fw::is_pfsense() {
        println!("\nmeshgate opens UDP {} and {} on the WAN itself (pf anchor userrules/meshgate).", a.port, a.port + 2);
        if me.lan_policy == model::POLICY_RESTRICTED {
            println!("LAN policy is restricted: add access rules for what mesh devices may reach.");
        }
    } else if me.kind == model::NODE_SERVER {
        println!(
            "\nOptional: forward UDP {} and {} on your router to this machine for direct connections from outside.",
            a.port,
            a.port + 2
        );
    }
}
