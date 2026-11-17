//! pf rules for FreeBSD/pfSense (Go: internal/fw/pf.go). pfSense always
//! generates `nat-anchor "natrules/*"`, `rdr-anchor "tftp-proxy/*"` and
//! `anchor "userrules/*"`, and leaves sub-anchors loaded with pfctl alone.

use std::sync::RwLock;

use super::{Allow, PRIVATE_NETS, Plan};

pub const DEFAULT_PF_NAT_ANCHOR: &str = "natrules/meshgate";
pub const DEFAULT_PF_FILTER_ANCHOR: &str = "userrules/meshgate";
pub const DEFAULT_PF_RDR_ANCHOR: &str = "natrules/meshgate";
pub const DEFAULT_PFSENSE_RDR_ANCHOR: &str = "tftp-proxy/meshgate";

/// The anchors in use (nat, rdr, filter), overridable from the node config.
pub static PF_ANCHORS: RwLock<(String, String, String)> = RwLock::new((String::new(), String::new(), String::new()));

pub fn pf_anchors() -> (String, String, String) {
    let g = PF_ANCHORS.read().unwrap();
    let pick = |s: &String, d: &str| if s.is_empty() { d.to_string() } else { s.clone() };
    (pick(&g.0, DEFAULT_PF_NAT_ANCHOR), pick(&g.1, DEFAULT_PF_RDR_ANCHOR), pick(&g.2, DEFAULT_PF_FILTER_ANCHOR))
}

pub fn set_pf_anchors(nat: &str, rdr: &str, filter: &str) {
    *PF_ANCHORS.write().unwrap() = (nat.into(), rdr.into(), filter.into());
}

/// Renders the plan as three pf rule sets: nat, rdr and filter.
pub fn render_pf(p: &Plan) -> (String, String, String) {
    let (mut n, mut r, mut f): (Vec<String>, Vec<String>, Vec<String>) = (vec![], vec![], vec![]);
    let mesh = &p.mesh;
    let wg = &p.iface;
    let private = PRIVATE_NETS.join(", ");

    for d in &p.dnat {
        if d.preserve {
            continue;
        }
        for proto in &d.protos {
            let port = if d.dst_port != 0 { d.dst_port.to_string() } else { pf_port(d.lo, d.hi) };
            n.push(format!("nat on {wg} inet proto {proto} from ! {mesh} to {} port {port} -> ({wg}:0) # {}", d.dst, pf_comment(&d.name)));
        }
    }
    if !p.lan_exit_srcs.is_empty() && !p.lan_exit_gw.is_empty() {
        n.push(format!("table <meshgate_private> const {{ {private} }}"));
        n.push(format!("nat on {wg} inet from {{ {} }} to ! <meshgate_private> -> ({wg}:0) # LAN exit", p.lan_exit_srcs.join(", ")));
    }
    if !p.exit_clients.is_empty() && !p.wan_iface.is_empty() {
        n.push(format!("nat on {} inet from {{ {} }} to any -> ({}:0) # exit node", p.wan_iface, p.exit_clients.join(", "), p.wan_iface));
    }
    for l in &p.lans {
        if l.iface.is_empty() {
            continue;
        }
        n.push(format!("nat on {} inet from {mesh} to {} -> ({}:0) # mesh to LAN", l.iface, l.cidr, l.iface));
    }
    if !p.wan_iface.is_empty() {
        for d in &p.dnat {
            for proto in &d.protos {
                let target = if d.hi > d.lo { format!("{} port {}:*", d.dst, d.lo) } else { format!("{} port {}", d.dst, d.dst_port) };
                r.push(format!(
                    "rdr pass on {} inet proto {proto} from any to ({}) port {} -> {target} # {}",
                    p.wan_iface,
                    p.wan_iface,
                    pf_port(d.lo, d.hi),
                    pf_comment(&d.name)
                ));
            }
        }
    }

    // Filter rules.
    if (!p.exit_clients.is_empty() && p.restricted) || !p.lan_exit_srcs.is_empty() || !p.lan_exit_block.is_empty() {
        f.push(format!("table <meshgate_private> const {{ {private} }}"));
    }
    f.push(format!("pass in quick on lo0 inet from {mesh} to any # local traffic"));
    f.push(format!("block drop in quick on ! {wg} inet from {mesh} to any # mesh address from outside"));
    if !p.lan_exit_srcs.is_empty() && !p.lan_exit_gw.is_empty() {
        f.push(format!(
            "pass in quick route-to ({wg} {}) inet from {{ {} }} to ! <meshgate_private> keep state # LAN exit",
            p.lan_exit_gw,
            p.lan_exit_srcs.join(", ")
        ));
    }
    let all: Vec<String> = p.lan_exit_srcs.iter().chain(&p.lan_exit_block).cloned().collect();
    if !all.is_empty() {
        f.push(format!(
            "block drop in quick inet from {{ {} }} to ! <meshgate_private> # LAN exit: internet only through the exit node",
            all.join(", ")
        ));
    }
    if !p.wan_iface.is_empty() {
        for a in &p.wan_open {
            f.push(format!(
                "pass in quick on {} inet proto {} from any to ({}) port {{ {} }} keep state # {}",
                p.wan_iface,
                a.proto,
                p.wan_iface,
                pf_ports(&a.ports),
                pf_comment(&a.comment)
            ));
        }
        for d in &p.blocked {
            for proto in &d.protos {
                f.push(format!(
                    "block drop in quick on {} inet proto {proto} from any to ({}) port {} # disabled: {}",
                    p.wan_iface,
                    p.wan_iface,
                    pf_port(d.lo, d.hi),
                    pf_comment(&d.name)
                ));
            }
        }
    }
    if !p.preserve_edge_ip.is_empty() {
        for a in &p.preserve_in {
            f.push(format!(
                "pass in quick on {wg} reply-to ({wg} {}) inet proto {} from ! {mesh} to self port {{ {} }} keep state # {}",
                p.preserve_edge_ip,
                a.proto,
                pf_ports(&a.ports),
                pf_comment(&a.comment)
            ));
        }
    }
    if p.firewall {
        for a in &p.own {
            f.push(pf_allow(wg, a));
        }
        return (join(&n), join(&r), join(&f));
    }
    if !p.restricted {
        f.push(format!("pass in quick on {wg} all keep state # LAN policy: open"));
        return (join(&n), join(&r), join(&f));
    }
    for a in p.allow.iter().filter(|a| a.self_) {
        f.push(pf_allow(wg, a));
    }
    f.push(format!("block in quick on {wg} inet from any to self # this node: only what rules allow"));
    if !p.exit_clients.is_empty() {
        f.push(format!(
            "pass in quick on {wg} inet from {{ {} }} to ! <meshgate_private> keep state # exit node: internet only",
            p.exit_clients.join(", ")
        ));
    }
    f.push(format!("pass in quick on {wg} inet from {mesh} to {mesh} keep state # relay between mesh nodes"));
    for a in p.allow.iter().filter(|a| !a.self_) {
        f.push(pf_allow(wg, a));
    }
    f.push(format!("block in quick on {wg} all # LAN policy: restricted"));
    (join(&n), join(&r), join(&f))
}

fn pf_allow(wg: &str, a: &Allow) -> String {
    let mut b = format!("pass in quick on {wg} inet");
    if matches!(a.proto.as_str(), "tcp" | "udp" | "icmp") {
        b.push_str(&format!(" proto {}", a.proto));
    }
    if a.src.is_empty() {
        b.push_str(" from any");
    } else {
        b.push_str(&format!(" from {{ {} }}", a.src.join(", ")));
    }
    if a.self_ {
        b.push_str(" to self");
    } else {
        b.push_str(&format!(" to {}", a.dst));
    }
    if !a.ports.is_empty() && (a.proto == "tcp" || a.proto == "udp") {
        b.push_str(&format!(" port {{ {} }}", pf_ports(&a.ports)));
    }
    b.push_str(&format!(" keep state # {}", pf_comment(&a.comment)));
    b
}

fn pf_port(lo: i64, hi: i64) -> String {
    if hi > lo { format!("{lo}:{hi}") } else { lo.to_string() }
}

/// "8000-8100" ranges become pf's "8000:8100".
fn pf_ports(ports: &[String]) -> String {
    ports.iter().map(|p| p.replacen('-', ":", 1)).collect::<Vec<_>>().join(", ")
}

fn pf_comment(s: &str) -> String {
    s.chars().map(|r| if r == '\n' || r == '\r' { ' ' } else { r }).collect()
}

fn join(lines: &[String]) -> String {
    if lines.is_empty() { String::new() } else { lines.join("\n") + "\n" }
}
