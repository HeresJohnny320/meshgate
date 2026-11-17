//! Turns mesh config into firewall rules for one node (Go: internal/fw):
//! port forwards on edges, LAN masquerading on subnet routers, replies for
//! preserve-client-IP forwards and access rules. `build` produces an
//! OS-neutral plan; `render_nft` (Linux) and `render_pf` (FreeBSD/pfSense)
//! turn it into rules whose text is identical to the Go build's.

use std::collections::{HashMap, HashSet};
use std::fmt::Write;

use crate::model::{self, Acl, ExitRoute, Forward, HttpRoute, Network, Node};
use crate::netx::{self, Prefix};

#[cfg(target_os = "freebsd")]
mod load_freebsd;
#[cfg(target_os = "linux")]
mod load_linux;
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
mod load_other;
#[cfg(target_os = "freebsd")]
pub use load_freebsd::*;
#[cfg(target_os = "linux")]
pub use load_linux::*;
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
pub use load_other::*;

mod pf;
pub use pf::*;

pub const MARK_BYPASS: u32 = 0x4d46;
pub const MARK_PRESERVE: u32 = 0x4d47;
pub const MARK_EDGE_KEEP: u32 = 0x4d48;
pub const TABLE_ROUTES: u32 = 51820;
pub const TABLE_REPLY: u32 = 51821;
pub const TABLE_LAN_EXIT: u32 = 51822;
pub const TABLE_LAN_BLOCK: u32 = 51823;
pub const TABLE_UNDERLAY: u32 = 51824;

/// Never reachable through an exit node.
pub const PRIVATE_NETS: [&str; 5] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16"];

/// A traffic counter for connections whose server end matches.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Monitor {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub protos: Vec<String>,
    pub ports: Vec<String>,
}

/// What this node needs.
#[derive(Clone, Debug, Default)]
#[cfg_attr(test, derive(serde::Deserialize))]
#[cfg_attr(test, serde(default, rename_all = "PascalCase"))]
pub struct Input {
    pub iface: String,
    pub network: Network,
    #[cfg_attr(test, serde(rename = "Self"))]
    pub self_: Node,
    #[cfg_attr(test, serde(deserialize_with = "crate::gojson::nullable"))]
    pub nodes: Vec<Node>,
    #[cfg_attr(test, serde(deserialize_with = "crate::gojson::nullable"))]
    pub forwards: Vec<Forward>,
    #[cfg_attr(test, serde(deserialize_with = "crate::gojson::nullable"))]
    pub routes: Vec<HttpRoute>,
    #[cfg_attr(test, serde(rename = "ACLs", deserialize_with = "crate::gojson::nullable"))]
    pub acls: Vec<Acl>,
    #[cfg_attr(test, serde(deserialize_with = "crate::gojson::nullable"))]
    pub monitors: Vec<model::Monitor>,
    pub preserve_edge: String,
    #[cfg_attr(test, serde(rename = "WGPort"))]
    pub wg_port: i64,
    pub probe_port: i64,
    pub mesh_port: i64,
    pub join_port: i64,
    pub web_port: i64,
    pub test_port: i64,
    #[cfg_attr(test, serde(rename = "WANIface"))]
    pub wan_iface: String,
    #[cfg_attr(test, serde(rename = "LANExitSrcs", deserialize_with = "crate::gojson::nullable"))]
    pub lan_exit_srcs: Vec<String>,
    #[cfg_attr(test, serde(rename = "LANExitGW"))]
    pub lan_exit_gw: String,
    #[cfg_attr(test, serde(rename = "LANExitBlock", deserialize_with = "crate::gojson::nullable"))]
    pub lan_exit_block: Vec<String>,
    #[cfg_attr(test, serde(deserialize_with = "crate::gojson::nullable"))]
    pub exit_routes: Vec<ExitRoute>,
}

/// One forward on an edge node.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Dnat {
    pub id: String,
    pub name: String,
    pub protos: Vec<String>,
    pub lo: i64,
    pub hi: i64,
    pub dst: String,
    /// 0 = keep the original port (ranges).
    pub dst_port: i64,
    pub preserve: bool,
}

/// A port this host accepts from anywhere.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct HostPort {
    pub proto: String,
    pub port: i64,
    pub note: String,
}

impl HostPort {
    fn new(proto: &str, port: i64, note: &str) -> HostPort {
        HostPort { proto: proto.into(), port, note: note.into() }
    }
}

/// One accepted flow from the mesh into this node or its LANs.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Allow {
    pub comment: String,
    pub src: Vec<String>,
    pub self_: bool,
    pub dst: String,
    pub proto: String,
    pub ports: Vec<String>,
    pub counter: String,
}

/// A shared subnet and the interface it lives on.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LanRoute {
    pub cidr: String,
    pub iface: String,
}

/// The OS-neutral rule set (see the Go type for each field).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Plan {
    pub iface: String,
    pub mesh: String,
    pub wan_iface: String,
    pub dnat: Vec<Dnat>,
    pub monitors: Vec<Monitor>,
    pub blocked: Vec<Dnat>,
    pub lans: Vec<LanRoute>,
    pub exit_clients: Vec<String>,
    pub lan_exit_srcs: Vec<String>,
    pub lan_exit_gw: String,
    pub lan_exit_block: Vec<String>,
    pub preserve_edge_ip: String,
    pub preserve_in: Vec<Allow>,
    pub wan_open: Vec<Allow>,
    pub host_open: Vec<HostPort>,
    pub restricted: bool,
    pub relay: bool,
    pub firewall: bool,
    pub allow: Vec<Allow>,
    pub own: Vec<Allow>,
    pub warnings: Vec<String>,
}

fn valid_prefixes(v: &[String]) -> Vec<String> {
    v.iter().filter_map(|s| netx::parse_prefix(s)).filter(|p| p.is4()).map(|p| p.masked().to_string()).collect()
}

fn valid_ipv4(s: &str) -> bool {
    netx::parse_addr4(s).is_some()
}

/// The nft counter object for a forward ("f", id, "in"/"out"), a monitor
/// ("m", ...) or an access rule ("a", id, "").
pub fn counter_name(kind: &str, id: &str, dir: &str) -> String {
    let clean: String = id.chars().map(|r| if r.is_ascii_alphanumeric() { r } else { '_' }).collect();
    if dir.is_empty() { format!("{kind}_{clean}") } else { format!("{kind}_{clean}_{dir}") }
}

fn protos(p: &str) -> Vec<String> {
    match p {
        model::PROTO_TCP => vec!["tcp".into()],
        model::PROTO_UDP => vec!["udp".into()],
        _ => vec!["tcp".into(), "udp".into()],
    }
}

/// Removes quotes, backslashes and control characters (nft comments).
pub fn sanitize(s: &str) -> String {
    s.chars().filter(|&r| r != '"' && r != '\\' && (r as u32) >= 32).collect()
}

/// Computes the plan.
pub fn build(input: &Input) -> Plan {
    let mut p = Plan {
        iface: input.iface.clone(),
        mesh: input.network.cidr.clone(),
        wan_iface: input.wan_iface.clone(),
        restricted: input.self_.restricted(),
        firewall: input.self_.firewall_managed(),
        relay: input.self_.relay,
        ..Default::default()
    };
    let by_id: HashMap<&str, &Node> = input.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    for m in &input.monitors {
        if m.node != input.self_.id || m.validate().is_err() {
            continue;
        }
        let mut mon = Monitor { id: m.id.clone(), name: m.name.clone(), ip: m.ip.clone(), ports: m.port_list(), protos: vec![] };
        if m.proto != "any" {
            mon.protos = protos(&m.proto);
        }
        p.monitors.push(mon);
    }
    let target_addr = |node_id: &str, ip: &str| -> Option<String> {
        if !ip.is_empty() {
            return Some(ip.to_string());
        }
        by_id.get(node_id).filter(|n| !n.mesh_ip.is_empty()).map(|n| n.mesh_ip.clone())
    };

    // Forwards where we are the edge.
    let mut fwds = input.forwards.clone();
    fwds.sort_by(|a, b| a.id.cmp(&b.id));
    for f in &fwds {
        if !f.enabled {
            if f.edge_node == input.self_.id && f.validate().is_ok() {
                let (lo, hi) = f.ports();
                p.blocked.push(Dnat { name: f.name.clone(), protos: protos(&f.proto), lo, hi, ..Default::default() });
            }
            continue;
        }
        if let Err(e) = f.validate() {
            if f.edge_node == input.self_.id {
                p.warnings.push(format!("forward {} skipped: {e}", f.name));
            }
            continue;
        }
        if f.edge_node == input.self_.id {
            let Some(dst) = target_addr(&f.target_node, &f.target_ip) else {
                p.warnings.push(format!("forward {} skipped: unknown target node", f.name));
                continue;
            };
            let (lo, hi) = f.ports();
            let mut d = Dnat {
                id: f.id.clone(),
                name: f.name.clone(),
                protos: protos(&f.proto),
                lo,
                hi,
                dst,
                dst_port: f.target_port,
                preserve: f.preserve_client_ip,
            };
            if hi > lo {
                d.dst_port = 0;
            }
            p.dnat.push(d);
        }
        // Forwards that end here must get through a restricted policy.
        if f.target_node == input.self_.id {
            let (lo, hi) = f.ports();
            let port = if hi > lo { format!("{lo}-{hi}") } else { f.target_port.to_string() };
            for pr in protos(&f.proto) {
                let mut a = Allow { comment: format!("forward {}", f.name), proto: pr, ports: vec![port.clone()], ..Default::default() };
                if f.target_ip.is_empty() {
                    a.self_ = true;
                } else {
                    a.dst = format!("{}/32", f.target_ip);
                }
                if f.preserve_client_ip && f.edge_node == input.preserve_edge && a.self_ {
                    p.preserve_in.push(a.clone());
                }
                p.allow.push(a);
            }
        }
    }
    if let Some(e) = by_id.get(input.preserve_edge.as_str()) {
        p.preserve_edge_ip = e.mesh_ip.clone();
    }
    if input.self_.exit {
        let routers: HashSet<&str> = input.exit_routes.iter().filter(|r| r.enabled).map(|r| r.router.as_str()).collect();
        for n in &input.nodes {
            if n.id != input.self_.id && (n.may_use_exit(&input.self_.id) || routers.contains(n.id.as_str())) && valid_ipv4(&n.mesh_ip) {
                p.exit_clients.push(n.mesh_ip.clone());
            }
        }
        p.exit_clients.sort();
    }
    if valid_ipv4(&input.lan_exit_gw) {
        p.lan_exit_gw = input.lan_exit_gw.clone();
        p.lan_exit_srcs = valid_prefixes(&input.lan_exit_srcs);
    }
    p.lan_exit_block = valid_prefixes(&input.lan_exit_block);
    // Never block a port an enabled forward is using.
    let dnat = p.dnat.clone();
    p.blocked
        .retain(|b| !dnat.iter().any(|d| b.protos.iter().any(|bp| d.protos.iter().any(|dp| bp == dp && b.lo <= d.hi && d.lo <= b.hi))));

    // HTTPS routes whose backend is here.
    for r in &input.routes {
        if !r.enabled || r.target_node != input.self_.id {
            continue;
        }
        let mut a = Allow {
            comment: format!("https {}", r.hostname),
            proto: "tcp".into(),
            ports: vec![r.target_port.to_string()],
            ..Default::default()
        };
        if let Some(src) = by_id.get(r.edge_node.as_str()) {
            a.src = vec![src.mesh_ip.clone()];
        }
        if r.target_ip.is_empty() {
            a.self_ = true;
        } else {
            a.dst = format!("{}/32", r.target_ip);
        }
        p.allow.push(a);
    }

    // Ports this host must accept from anywhere.
    if input.wg_port > 0 {
        p.host_open.push(HostPort::new("udp", input.wg_port, "wireguard"));
    }
    if input.probe_port > 0 {
        p.host_open.push(HostPort::new("udp", input.probe_port, "path probes"));
    }
    if input.join_port > 0 {
        p.host_open.push(HostPort::new("tcp", input.join_port, "joins"));
    }
    if input.routes.iter().any(|r| r.enabled && r.edge_node == input.self_.id) {
        p.host_open.push(HostPort::new("tcp", 80, "https routes"));
        p.host_open.push(HostPort::new("tcp", 443, "https routes"));
    }

    // meshgate's own services over the mesh.
    let own = |comment: &str, src: Vec<String>, proto: &str, port: i64| Allow {
        comment: comment.into(),
        src,
        self_: true,
        proto: proto.into(),
        ports: vec![port.to_string()],
        ..Default::default()
    };
    if input.mesh_port > 0 {
        p.own.push(own("meshgate sync", vec![input.network.cidr.clone()], "tcp", input.mesh_port));
    }
    if input.web_port > 0 {
        p.own.push(own("meshgate web ui", vec![input.network.cidr.clone()], "tcp", input.web_port));
    }
    if input.test_port > 0 {
        for pr in ["tcp", "udp"] {
            p.own.push(own("meshgate test service", vec![], pr, input.test_port));
        }
    }
    p.allow.extend(p.own.clone());

    // User access rules enforced here.
    let mut acls = input.acls.clone();
    acls.sort_by(|a, b| a.id.cmp(&b.id));
    for a in &acls {
        if !a.enabled || a.node != input.self_.id {
            continue;
        }
        if let Err(e) = a.validate() {
            p.warnings.push(format!("rule {} skipped: {e}", a.name));
            continue;
        }
        let src: Vec<String> =
            a.from.iter().filter_map(|id| by_id.get(id.as_str())).filter(|n| !n.mesh_ip.is_empty()).map(|n| n.mesh_ip.clone()).collect();
        if !a.from.is_empty() && src.is_empty() {
            // Never widen a rule to "any" because its devices were removed.
            p.warnings.push(format!("rule {} skipped: none of its devices exist", a.name));
            continue;
        }
        let prs: Vec<String> = if a.proto == "both" { vec!["tcp".into(), "udp".into()] } else { vec![a.proto.clone()] };
        for pr in prs {
            let mut al = Allow {
                comment: format!("rule {}", a.name),
                src: src.clone(),
                proto: pr,
                ports: a.port_list(),
                counter: counter_name("a", &a.id, ""),
                ..Default::default()
            };
            match a.dest_prefix() {
                Some(d) => al.dst = d.to_string(),
                None => al.self_ = true,
            }
            p.allow.push(al);
        }
    }
    if !p.restricted {
        p.allow.clear();
    }

    // Subnet routing.
    for r in &input.self_.routes {
        if let Some(pfx) = netx::parse_prefix(r) {
            p.lans.push(LanRoute { cidr: pfx.masked().to_string(), iface: iface_for(&pfx) });
        }
    }

    // Public meshgate ports (pf).
    if input.self_.relay || !input.self_.endpoints.is_empty() {
        let udp = vec![input.wg_port.to_string(), input.probe_port.to_string()];
        p.wan_open.push(Allow { comment: "meshgate wireguard+probes".into(), proto: "udp".into(), ports: udp, ..Default::default() });
        if input.join_port > 0 {
            p.wan_open.push(Allow {
                comment: "meshgate joins".into(),
                proto: "tcp".into(),
                ports: vec![input.join_port.to_string()],
                ..Default::default()
            });
        }
    }
    p
}

/// The local interface with an IPv4 address inside pfx.
pub fn iface_for(pfx: &Prefix) -> String {
    for i in crate::ifaces::list() {
        if i.addrs.iter().any(|(a, _)| a.is_ipv4() && pfx.contains(*a)) {
            return i.name;
        }
    }
    String::new()
}

/// Whether an interface is a VPN tunnel (another WireGuard, NetBird,
/// OpenVPN, Tailscale, ...): its addresses are not a LAN.
pub fn is_tunnel(name: &str, point_to_point: bool) -> bool {
    point_to_point
        || ["wg", "wt", "tun", "tap", "ovpn", "tailscale", "zt", "ppp", "ipsec", "gif", "gre"].iter().any(|p| name.starts_with(p))
}

/// Private IPv4 networks on this machine with their interfaces.
pub fn local_lans(skip: &str) -> Vec<model::Lan> {
    let mut out = vec![];
    for i in crate::ifaces::list() {
        if i.name == skip || !i.up || i.loopback || is_tunnel(&i.name, i.point_to_point) {
            continue;
        }
        for (a, bits) in &i.addrs {
            let std::net::IpAddr::V4(v4) = a else { continue };
            if !v4.is_private() {
                continue;
            }
            out.push(model::Lan { iface: i.name.clone(), cidr: Prefix::new(*a, *bits).masked().to_string() });
        }
    }
    out
}

fn q(s: &str) -> String {
    format!("\"{s}\"")
}

/// Renders the plan as an nft script that replaces "inet meshgate"
/// atomically.
pub fn render_nft(p: &Plan) -> String {
    let (mut dnat, mut post, mut mark, mut inp, mut fwd, mut block, mut counters) =
        (vec![], vec![], vec![], vec![], vec![], vec![], Vec::<String>::new());
    let mut fwd_chain = vec![format!("\t\toifname {} tcp flags syn tcp option maxseg size set rt mtu", q(&p.iface))];

    for d in &p.blocked {
        let port = if d.hi > d.lo { format!("{}-{}", d.lo, d.hi) } else { d.lo.to_string() };
        for proto in &d.protos {
            block.push(format!(
                "\t\tiifname != {} fib daddr type local meta l4proto {proto} th dport {port} drop comment {}",
                q(&p.iface),
                q(&format!("disabled: {}", sanitize(&d.name)))
            ));
        }
    }

    for d in &p.dnat {
        let (port, to) = if d.hi > d.lo {
            (format!("{}-{}", d.lo, d.hi), d.dst.clone())
        } else {
            (d.lo.to_string(), format!("{}:{}", d.dst, d.dst_port))
        };
        let keep = if d.preserve { format!("ct mark set 0x{MARK_EDGE_KEEP:x} ") } else { String::new() };
        let (cin, cout) = (counter_name("f", &d.id, "in"), counter_name("f", &d.id, "out"));
        counters.push(cin.clone());
        counters.push(cout.clone());
        for proto in &d.protos {
            for (dir, c) in [("original", &cin), ("reply", &cout)] {
                fwd_chain.push(format!(
                    "\t\tmeta l4proto {proto} ct status dnat ct original proto-dst {port} ct direction {dir} counter name {}",
                    q(c)
                ));
            }
        }
        for proto in &d.protos {
            dnat.push(format!(
                "\t\tiifname != {} fib daddr type local meta l4proto {proto} th dport {port} {keep}dnat ip to {to} comment {}",
                q(&p.iface),
                q(&sanitize(&d.name))
            ));
        }
    }
    if !p.dnat.is_empty() {
        post.push(format!("\t\toifname {} ct status dnat ct mark != 0x{MARK_EDGE_KEEP:x} masquerade", q(&p.iface)));
    }
    if !p.lans.is_empty() {
        let cidrs: Vec<&str> = p.lans.iter().map(|l| l.cidr.as_str()).collect();
        post.push(format!("\t\tiifname {} oifname != {} ip daddr {{ {} }} masquerade", q(&p.iface), q(&p.iface), cidrs.join(", ")));
    }
    if !p.exit_clients.is_empty() {
        post.push(format!(
            "\t\tiifname {} oifname != {} ip saddr {{ {} }} masquerade comment {}",
            q(&p.iface),
            q(&p.iface),
            p.exit_clients.join(", "),
            q("exit node")
        ));
    }
    let priv_ = PRIVATE_NETS.join(", ");
    if !p.lan_exit_srcs.is_empty() {
        post.push(format!(
            "\t\toifname {} ip saddr {{ {} }} ip daddr != {{ {priv_} }} masquerade comment {}",
            q(&p.iface),
            p.lan_exit_srcs.join(", "),
            q("LAN exit")
        ));
    }
    let all: Vec<String> = p.lan_exit_srcs.iter().chain(&p.lan_exit_block).cloned().collect();
    if !all.is_empty() {
        fwd_chain.push(format!(
            "\t\toifname != {} ip saddr {{ {} }} ip daddr != {{ {priv_} }} drop comment {}",
            q(&p.iface),
            all.join(", "),
            q("LAN exit: internet only through the exit node")
        ));
    }
    if !p.preserve_edge_ip.is_empty() {
        mark.push(format!("\t\tiifname {} ip saddr != {} ct state new ct mark set 0x{MARK_PRESERVE:x}", q(&p.iface), p.mesh));
    }
    if p.restricted {
        inp.push(format!("\t\tiifname {} ct state established,related accept", q(&p.iface)));
        fwd.push(format!("\t\tiifname {} oifname {} accept comment {}", q(&p.iface), q(&p.iface), q("relay between mesh nodes")));
        fwd.push(format!("\t\tiifname {} ct state established,related accept", q(&p.iface)));
        if !p.exit_clients.is_empty() {
            fwd.push(format!(
                "\t\tiifname {} oifname != {} ip saddr {{ {} }} ip daddr != {{ {priv_} }} accept comment {}",
                q(&p.iface),
                q(&p.iface),
                p.exit_clients.join(", "),
                q("exit node: internet only")
            ));
        }
        for a in &p.allow {
            if !a.counter.is_empty() {
                counters.push(a.counter.clone());
            }
            let r = nft_allow(&p.iface, a);
            if a.self_ { inp.push(r) } else { fwd.push(r) }
        }
        inp.push(format!("\t\tiifname {} drop", q(&p.iface)));
        fwd.push(format!("\t\tiifname {} drop", q(&p.iface)));
    }

    // Monitors: count only, after every filter (priority 300).
    let (mut mon_in, mut mon_out, mut mon_fwd) = (vec![], vec![], vec![]);
    for m in &p.monitors {
        let (cin, cout) = (counter_name("m", &m.id, "in"), counter_name("m", &m.id, "out"));
        counters.push(cin.clone());
        counters.push(cout.clone());
        let prs: Vec<&str> = if m.protos.is_empty() { vec![""] } else { m.protos.iter().map(String::as_str).collect() };
        for proto in prs {
            let mut matches = vec![];
            if !proto.is_empty() {
                matches.push(format!("meta l4proto {proto}"));
            }
            if !m.ip.is_empty() {
                matches.push(format!("ct reply ip saddr {}", m.ip));
            }
            if !m.ports.is_empty() {
                matches.push(format!("ct reply proto-src {{ {} }}", m.ports.join(", ")));
            }
            for (dir, c) in [("original", &cin), ("reply", &cout)] {
                let r = format!(
                    "{} ct direction {dir} counter name {} comment {}",
                    matches.join(" "),
                    q(c),
                    q(&format!("monitor: {}", sanitize(&m.name)))
                );
                mon_in.push(format!("\t\tiifname != \"lo\" {r}"));
                mon_out.push(format!("\t\t{r}"));
                mon_fwd.push(format!("\t\t{r}"));
            }
        }
    }

    let mut b = String::from("table inet meshgate\ndelete table inet meshgate\ntable inet meshgate {\n");
    counters.sort();
    counters.dedup();
    for c in &counters {
        let _ = write!(b, "\tcounter {c} {{\n\t}}\n");
    }
    let chain = |b: &mut String, name: &str, hook: &str, lines: &[String]| {
        let _ = writeln!(b, "\tchain {name} {{\n\t\t{hook}; policy accept;");
        for l in lines {
            b.push_str(l);
            b.push('\n');
        }
        b.push_str("\t}\n");
    };
    // Anti-spoofing: mesh addresses only ever arrive through the tunnel.
    if !p.mesh.is_empty() {
        block.insert(
            0,
            format!("\t\tiifname != {{ {}, \"lo\" }} ip saddr {} drop comment \"mesh address from outside\"", q(&p.iface), p.mesh),
        );
    }
    if !block.is_empty() {
        chain(&mut b, "blocked", "type filter hook prerouting priority raw", &block);
    }
    chain(&mut b, "prerouting", "type nat hook prerouting priority dstnat", &dnat);
    chain(&mut b, "postrouting", "type nat hook postrouting priority srcnat", &post);
    chain(&mut b, "forward", "type filter hook forward priority mangle", &fwd_chain);
    if !mark.is_empty() {
        chain(&mut b, "premark", "type filter hook prerouting priority mangle", &mark);
        chain(
            &mut b,
            "outmark",
            "type route hook output priority mangle",
            &[format!("\t\tct mark 0x{MARK_PRESERVE:x} meta mark set 0x{MARK_PRESERVE:x}")],
        );
    }
    if !p.monitors.is_empty() {
        chain(&mut b, "monitor_in", "type filter hook input priority 300", &mon_in);
        chain(&mut b, "monitor_out", "type filter hook output priority 300", &mon_out);
        chain(&mut b, "monitor_fwd", "type filter hook forward priority 300", &mon_fwd);
    }
    if p.restricted {
        chain(&mut b, "lan_in", "type filter hook input priority filter", &inp);
        chain(&mut b, "lan_fwd", "type filter hook forward priority filter", &fwd);
    }
    b.push_str("}\n");
    b
}

fn nft_allow(iface: &str, a: &Allow) -> String {
    let mut parts = vec![format!("iifname \"{iface}\"")];
    if !a.src.is_empty() {
        parts.push(format!("ip saddr {{ {} }}", a.src.join(", ")));
    }
    if !a.self_ {
        parts.push(format!("ip daddr {}", a.dst));
    }
    if matches!(a.proto.as_str(), "tcp" | "udp" | "icmp") {
        parts.push(format!("meta l4proto {}", a.proto));
    }
    if !a.ports.is_empty() && (a.proto == "tcp" || a.proto == "udp") {
        parts.push(format!("th dport {{ {} }}", a.ports.join(", ")));
    }
    if !a.counter.is_empty() {
        parts.push(format!("counter name \"{}\"", a.counter));
    }
    parts.push("accept".into());
    parts.push(format!("comment \"{}\"", sanitize(&a.comment)));
    format!("\t\t{}", parts.join(" "))
}

impl Plan {
    /// iptables FORWARD rules for the MESHGATE chain that let exactly this
    /// node's meshgate traffic past a FORWARD policy of DROP (ufw, Docker).
    pub fn iptables_rules(&self) -> Vec<Vec<String>> {
        let wg = self.iface.as_str();
        let mut out: Vec<Vec<String>> = vec![];
        let mut add = |r: &[&str]| out.push(r.iter().map(|s| s.to_string()).collect());
        for d in &self.dnat {
            let ports = if d.hi > d.lo { format!("{}:{}", d.lo, d.hi) } else { d.lo.to_string() };
            let note = format!("meshgate forward {}", sanitize(&d.name));
            for proto in &d.protos {
                add(&[
                    "-o",
                    wg,
                    "-p",
                    proto,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "DNAT",
                    "--ctorigdstport",
                    &ports,
                    "-m",
                    "comment",
                    "--comment",
                    &note,
                    "-j",
                    "ACCEPT",
                ]);
                add(&[
                    "-i",
                    wg,
                    "-p",
                    proto,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "ESTABLISHED,RELATED",
                    "--ctorigdstport",
                    &ports,
                    "-m",
                    "comment",
                    "--comment",
                    &note,
                    "-j",
                    "ACCEPT",
                ]);
            }
        }
        if self.relay {
            add(&["-i", wg, "-o", wg, "-m", "comment", "--comment", "meshgate relay", "-j", "ACCEPT"]);
        }
        for c in &self.exit_clients {
            add(&["-i", wg, "-s", c, "-m", "comment", "--comment", "meshgate exit node", "-j", "ACCEPT"]);
            add(&[
                "-o",
                wg,
                "-d",
                c,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-m",
                "comment",
                "--comment",
                "meshgate exit node",
                "-j",
                "ACCEPT",
            ]);
        }
        for l in &self.lans {
            add(&["-i", wg, "-d", &l.cidr, "-m", "comment", "--comment", "meshgate shared LAN", "-j", "ACCEPT"]);
            add(&["-o", wg, "-s", &l.cidr, "-m", "comment", "--comment", "meshgate shared LAN", "-j", "ACCEPT"]);
        }
        for s in &self.lan_exit_srcs {
            add(&["-o", wg, "-s", s, "-m", "comment", "--comment", "meshgate exit route", "-j", "ACCEPT"]);
            add(&[
                "-i",
                wg,
                "-d",
                s,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-m",
                "comment",
                "--comment",
                "meshgate exit route",
                "-j",
                "ACCEPT",
            ]);
        }
        out
    }
}

#[cfg(test)]
mod tests;
