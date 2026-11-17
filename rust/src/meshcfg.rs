//! Turns cluster state plus path decisions into the exact WireGuard
//! interface config for one node (Go: internal/meshcfg). Pure.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

use crate::model::{ExitRoute, Forward, Network, Node};
use crate::netx::{self, Prefix};
use crate::pathsel::{self, Path};

/// Keeps NAT mappings open towards relays and direct peers.
pub const KEEPALIVE: i64 = 20;

/// One WireGuard peer.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Peer {
    pub node_id: String,
    pub public_key: String,
    /// "" = keep whatever WireGuard learned.
    pub endpoint: String,
    pub allowed_ips: Vec<Prefix>,
    pub keepalive: i64,
}

/// The full desired interface state (see the Go type for each field).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Config {
    pub address: Option<Prefix>,
    pub listen_port: i64,
    pub peers: Vec<Peer>,
    pub routes: Vec<Prefix>,
    pub default_via_peer: String,
    pub home: bool,
    pub exit_via: String,
    pub exit_blocked: bool,
    pub lan_exit_srcs: Vec<Prefix>,
    pub lan_exit_via: String,
    pub lan_exit_block: Vec<Prefix>,
    pub warnings: Vec<String>,
}

#[derive(Default)]
pub struct Input<'a> {
    pub network: Network,
    pub self_: Node,
    pub nodes: Vec<Node>,
    pub forwards: Vec<Forward>,
    pub paths: pathsel::Result,
    pub local_addrs: Vec<IpAddr>,
    pub exit_capable: bool,
    pub exit_choice: String,
    pub lan_exit_capable: bool,
    pub exit_routes: &'a [ExitRoute],
}

fn all4() -> Prefix {
    Prefix::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

fn path_of<'a>(input: &'a Input, id: &str) -> std::borrow::Cow<'a, Path> {
    match input.paths.paths.get(id) {
        Some(p) => std::borrow::Cow::Borrowed(p),
        None => std::borrow::Cow::Owned(Path::default()),
    }
}

/// Computes the config.
pub fn build(input: &Input) -> Result<Config, String> {
    let net_pfx = input.network.prefix().map_err(|e| format!("network cidr: {e}"))?;
    let self_ip = netx::parse_addr(&input.self_.mesh_ip)
        .ok_or_else(|| format!("self mesh ip: ParseAddr({:?}): unable to parse IP", input.self_.mesh_ip))?;
    let mut cfg = Config { address: Some(Prefix::new(self_ip, net_pfx.bits)), listen_port: input.self_.listen_port, ..Default::default() };

    let by_id: HashMap<&str, &Node> = input.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let mut peers: HashMap<String, Peer> = HashMap::new();
    let mut ids: Vec<String> = Vec::new();
    for n in &input.nodes {
        if n.id == input.self_.id || n.public_key.is_empty() {
            continue;
        }
        ids.push(n.id.clone());
        peers.insert(n.id.clone(), Peer { node_id: n.id.clone(), public_key: n.public_key.clone(), ..Default::default() });
    }
    ids.sort();
    ids.dedup();

    // Endpoints and keepalives.
    let self_relay = pathsel::is_relay(&input.self_);
    for id in &ids {
        let path = path_of(input, id);
        if path.direct() {
            let p = peers.get_mut(id).unwrap();
            p.endpoint = path.endpoint.clone();
            if !self_relay && !p.endpoint.is_empty() {
                p.keepalive = KEEPALIVE;
            }
        }
    }

    // AllowedIPs: each node's mesh IP and subnets go to the peer we reach it
    // through (itself if direct, otherwise its relay).
    let mut claimed: HashMap<Prefix, String> = HashMap::new();
    for id in &ids {
        let n = by_id[id.as_str()];
        let path = path_of(input, id);
        let mut holder = id.clone();
        if !path.direct() {
            if peers.contains_key(&path.via) {
                holder = path.via.clone();
            } else {
                cfg.warnings.push(format!("{}: relay {} unknown", n.name, path.via));
            }
        }
        let Some(ip) = netx::parse_addr(&n.mesh_ip) else {
            cfg.warnings.push(format!("{}: bad mesh ip {:?}", n.name, n.mesh_ip));
            continue;
        };
        peers.get_mut(&holder).unwrap().allowed_ips.push(Prefix::new(ip, 32));
        for r in &n.routes {
            let Some(pfx) = netx::parse_prefix(r) else {
                cfg.warnings.push(format!("{}: bad route {:?}", n.name, r));
                continue;
            };
            let pfx = pfx.masked();
            if pfx.overlaps(&net_pfx) {
                cfg.warnings.push(format!("{}: route {} overlaps the mesh", n.name, pfx));
                continue;
            }
            if own_route(&input.self_, &pfx) {
                continue;
            }
            if input.local_addrs.iter().any(|a| pfx.contains(*a)) && on_lan(&path, &pfx) {
                cfg.home = true;
                continue;
            }
            if let Some(other) = claimed.get(&pfx) {
                cfg.warnings.push(format!("route {pfx} advertised by {other} and {}; using {other}", n.name));
                continue;
            }
            claimed.insert(pfx, n.name.clone());
            peers.get_mut(&holder).unwrap().allowed_ips.push(pfx);
            cfg.routes.push(pfx);
        }
    }

    // Preserve-client-IP forwards targeting us: the edge peer must accept any
    // source. Only one peer can hold 0.0.0.0/0.
    let edge = preserve_edge(input);
    if !edge.is_empty() {
        if peers.contains_key(&edge) && path_of(input, &edge).direct() {
            peers.get_mut(&edge).unwrap().allowed_ips.push(all4());
            cfg.default_via_peer = edge.clone();
        } else {
            cfg.warnings.push(format!("preserve-client-IP: edge {edge} is not directly connected; disabled"));
        }
    }
    if !cfg.home && (!input.self_.exit_via.is_empty() || !input.exit_choice.is_empty() || !input.self_.exits_allowed.is_empty()) {
        cfg.device_exit(input, &by_id, &mut peers);
    }
    cfg.lan_exits(input, &by_id, &mut peers);
    for f in &input.forwards {
        if f.enabled && f.preserve_client_ip && f.target_node == input.self_.id && f.edge_node != edge {
            let ename = by_id.get(edge.as_str()).map(|n| n.name.as_str()).unwrap_or("");
            cfg.warnings.push(format!("forward {}: only one edge ({ename}) can preserve client IPs into this node", f.name));
        }
    }
    for id in &ids {
        let mut p = peers.remove(id).unwrap();
        p.allowed_ips.sort_by_key(|a| a.to_string());
        cfg.peers.push(p);
    }
    cfg.routes.sort_by_key(|a| a.to_string());
    Ok(cfg)
}

/// The edge allowed to deliver real client IPs to us.
fn preserve_edge(input: &Input) -> String {
    let mut edges: Vec<&str> = input
        .forwards
        .iter()
        .filter(|f| f.enabled && f.preserve_client_ip && f.target_node == input.self_.id)
        .map(|f| f.edge_node.as_str())
        .collect();
    edges.sort();
    edges.first().map(|s| s.to_string()).unwrap_or_default()
}

/// Whether path reaches its node directly on an endpoint inside pfx.
fn on_lan(path: &Path, pfx: &Prefix) -> bool {
    if !path.direct() || path.endpoint.is_empty() {
        return false;
    }
    path.endpoint.parse::<std::net::SocketAddr>().is_ok_and(|a| pfx.contains(a.ip()))
}

fn own_route(self_: &Node, p: &Prefix) -> bool {
    self_.routes.iter().any(|r| netx::parse_prefix(r).is_some_and(|q| q.masked() == *p))
}

/// The first usable exit node: preferred, then the others by name.
fn pick_exit(
    input: &Input,
    by_id: &HashMap<&str, &Node>,
    peers: &HashMap<String, Peer>,
    preferred: &str,
    only: &str,
    router: bool,
) -> String {
    let mut others: Vec<&Node> = input.nodes.iter().filter(|n| n.exit && n.id != preferred && n.id != input.self_.id).collect();
    others.sort_by(|a, b| a.name.cmp(&b.name));
    let cands = std::iter::once(preferred).chain(others.iter().map(|n| n.id.as_str()));
    for id in cands {
        let Some(n) = by_id.get(id) else { continue };
        let up = input.paths.up.as_ref().is_none_or(|u| u.get(id).copied().unwrap_or(false));
        if n.exit
            && peers.contains_key(id)
            && path_of(input, id).direct()
            && up
            && (only.is_empty() || id == only)
            && (router || input.self_.may_use_exit(id))
        {
            return id.to_string();
        }
    }
    String::new()
}

fn name(by_id: &HashMap<&str, &Node>, id: &str) -> String {
    match by_id.get(id) {
        Some(n) if !n.name.is_empty() => n.name.clone(),
        _ => id.to_string(),
    }
}

impl Config {
    /// Sends this device's internet traffic to an exit node (phones).
    fn device_exit(&mut self, input: &Input, by_id: &HashMap<&str, &Node>, peers: &mut HashMap<String, Peer>) {
        let mut want = input.self_.exit_via.clone();
        let c = input.exit_choice.as_str();
        if c == "off" {
            want.clear();
        } else if !c.is_empty() && input.self_.may_use_exit(c) {
            want = c.to_string();
        }
        if want.is_empty() && !input.self_.exit_only {
            return; // own connection, by choice
        }
        if !input.exit_capable {
            self.warnings.push("exit nodes are only supported in the phone app so far".into());
            return;
        }
        if !self.default_via_peer.is_empty() {
            self.warnings.push("exit node ignored: this node receives real client IPs, which needs the default route".into());
            return;
        }
        let mut ex = String::new();
        if !want.is_empty() || input.exit_choice != "off" {
            ex = pick_exit(input, by_id, peers, &want, "", false);
        }
        if ex.is_empty() {
            if input.self_.exit_only {
                self.exit_blocked = true;
                self.routes.push(all4());
                self.warnings.push("no exit node is reachable: internet blocked (exit only)".into());
            } else {
                self.warnings
                    .push(format!("no exit node is reachable ({} is down): using this device's own connection", name(by_id, &want)));
            }
            return;
        }
        if !want.is_empty() && ex != want {
            self.warnings.push(format!("{} is down: using exit node {}", name(by_id, &want), name(by_id, &ex)));
        }
        peers.get_mut(&ex).unwrap().allowed_ips.push(all4());
        self.routes.push(all4());
        self.exit_via = ex;
    }

    /// Routes LAN devices' internet traffic to one exit node with failover.
    fn lan_exits(&mut self, input: &Input, by_id: &HashMap<&str, &Node>, peers: &mut HashMap<String, Peer>) {
        let mut srcs: Vec<(Prefix, bool)> = Vec::new();
        let mut want = String::new();
        for e in &input.self_.lan_exits {
            if let Ok(p) = e.prefix() {
                srcs.push((p, input.self_.exit_only));
                if want.is_empty() {
                    want = e.via.clone();
                }
            }
        }
        for r in input.exit_routes {
            if r.router != input.self_.id || !r.enabled {
                continue;
            }
            if let Ok(p) = r.prefix() {
                srcs.push((p, r.exit_only));
                if want.is_empty() {
                    want = r.via.clone();
                }
            }
        }
        if srcs.is_empty() {
            return;
        }
        if !input.lan_exit_capable {
            self.warnings.push("exit routes need a Linux or pfSense router".into());
            return;
        }
        let ex = pick_exit(input, by_id, peers, &want, &self.default_via_peer, true);
        if ex.is_empty() {
            let mut why = format!("{} is not reachable", name(by_id, &want));
            if !self.default_via_peer.is_empty() && self.default_via_peer != want {
                why = format!(
                    "this node receives real client IPs through {}, which must then be the exit",
                    name(by_id, &self.default_via_peer)
                );
            }
            self.lan_exit_block.extend(srcs.iter().filter(|s| s.1).map(|s| s.0));
            self.warnings.push(format!("exit routes: {why}; exit-only devices have no internet, the others use the normal connection"));
            return;
        }
        if ex != want {
            self.warnings.push(format!("exit routes: {} is down: using exit node {}", name(by_id, &want), name(by_id, &ex)));
        }
        if ex != self.default_via_peer {
            peers.get_mut(&ex).unwrap().allowed_ips.push(all4());
        }
        self.lan_exit_srcs.extend(srcs.iter().map(|s| s.0));
        self.lan_exit_via = ex;
    }
}

/// Unique prefixes, for callers that compare sets.
pub fn prefix_set(v: &[Prefix]) -> HashSet<Prefix> {
    v.iter().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::LanExit;
    use std::collections::BTreeMap;

    fn n(id: &str, kind: &str, key: &str, ip: &str) -> Node {
        Node { id: id.into(), name: id.into(), kind: kind.into(), public_key: key.into(), mesh_ip: ip.into(), ..Default::default() }
    }
    fn phone() -> Node {
        n("phone", "client", "Kp", "100.88.0.4")
    }
    fn home() -> Node {
        let mut h = n("home", "server", "Kh", "100.88.0.2");
        h.endpoints = vec!["192.168.1.10:51820".into()];
        h.routes = vec!["192.168.1.0/24".into()];
        h
    }
    fn vps() -> Node {
        let mut v = n("vps", "server", "Kv", "100.88.0.1");
        v.relay = true;
        v.endpoints = vec!["1.1.1.1:51820".into()];
        v
    }
    fn vps2() -> Node {
        let mut v = n("vps2", "server", "Kv2", "100.88.0.9");
        v.relay = true;
        v.exit = true;
        v.endpoints = vec!["2.2.2.2:51820".into()];
        v
    }
    fn network() -> Network {
        Network { cidr: "100.88.0.0/16".into(), ..Default::default() }
    }
    fn direct(ep: &str) -> Path {
        Path { via: String::new(), endpoint: ep.into() }
    }
    fn via(r: &str) -> Path {
        Path { via: r.into(), endpoint: String::new() }
    }
    fn paths(p: &[(&str, Path)]) -> pathsel::Result {
        pathsel::Result { paths: p.iter().map(|(k, v)| (k.to_string(), v.clone())).collect::<BTreeMap<_, _>>(), ..Default::default() }
    }
    fn up(u: &[(&str, bool)]) -> Option<HashMap<String, bool>> {
        Some(u.iter().map(|(k, v)| (k.to_string(), *v)).collect())
    }
    fn peer<'a>(c: &'a Config, id: &str) -> &'a Peer {
        c.peers.iter().find(|p| p.node_id == id).unwrap_or_else(|| panic!("no peer {id}"))
    }
    fn ips(p: &Peer) -> String {
        p.allowed_ips.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(",")
    }
    fn strs(v: &[Prefix]) -> String {
        format!("[{}]", v.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(" "))
    }
    fn mc(edge: &str) -> Forward {
        Forward {
            id: "mc".into(),
            name: "minecraft".into(),
            proto: "tcp".into(),
            edge_node: edge.into(),
            listen_port: 25565,
            target_node: "home".into(),
            target_port: 25565,
            preserve_client_ip: true,
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn phone_via_relay_gets_home_subnet_on_relay_peer() {
        let c = build(&Input {
            network: network(),
            self_: phone(),
            nodes: vec![phone(), home(), vps()],
            paths: pathsel::Result { home_relay: "vps".into(), ..paths(&[("home", via("vps")), ("vps", direct("1.1.1.1:51820"))]) },
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ips(peer(&c, "vps")), "100.88.0.1/32,100.88.0.2/32,192.168.1.0/24");
        assert_eq!(ips(peer(&c, "home")), "");
        let p = peer(&c, "vps");
        assert!(p.keepalive != 0 && p.endpoint == "1.1.1.1:51820");
        assert_eq!(strs(&c.routes), "[192.168.1.0/24]");
        assert_eq!(c.address.unwrap().to_string(), "100.88.0.4/16");
    }

    #[test]
    fn phone_on_home_lan_skips_subnet() {
        let c = build(&Input {
            network: network(),
            self_: phone(),
            nodes: vec![phone(), home(), vps()],
            local_addrs: vec!["192.168.1.77".parse().unwrap()],
            paths: paths(&[("home", direct("192.168.1.10:51820")), ("vps", direct("1.1.1.1:51820"))]),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ips(peer(&c, "home")), "100.88.0.2/32");
        assert!(c.routes.is_empty());
    }

    #[test]
    fn preserve_client_ip_gives_edge_default() {
        let c = build(&Input {
            network: network(),
            self_: home(),
            nodes: vec![phone(), home(), vps()],
            forwards: vec![mc("vps")],
            paths: paths(&[("vps", direct("1.1.1.1:51820")), ("phone", via("vps"))]),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ips(peer(&c, "vps")), "0.0.0.0/0,100.88.0.1/32,100.88.0.4/32");
        assert_eq!(c.default_via_peer, "vps");
    }

    #[test]
    fn cafe_with_home_range_keeps_subnet_in_tunnel() {
        let c = build(&Input {
            network: network(),
            self_: phone(),
            nodes: vec![phone(), home(), vps()],
            local_addrs: vec!["192.168.1.77".parse().unwrap()],
            paths: paths(&[("home", via("vps")), ("vps", direct("1.1.1.1:51820"))]),
            ..Default::default()
        })
        .unwrap();
        assert!(!c.home, "café LAN taken for home");
        assert_eq!(ips(peer(&c, "vps")), "100.88.0.1/32,100.88.0.2/32,192.168.1.0/24");
        assert_eq!(strs(&c.routes), "[192.168.1.0/24]");
    }

    fn exit_input(local: &str, home_path: Path) -> Input<'static> {
        let mut p = phone();
        p.exit_via = "vps".into();
        let mut v = vps();
        v.exit = true;
        Input {
            network: network(),
            self_: p.clone(),
            nodes: vec![p, home(), v],
            exit_capable: true,
            paths: paths(&[("home", home_path), ("vps", direct("1.1.1.1:51820"))]),
            local_addrs: if local.is_empty() { vec![] } else { vec![local.parse().unwrap()] },
            ..Default::default()
        }
    }

    #[test]
    fn exit_node_away() {
        let c = build(&exit_input("10.20.0.5", via("vps"))).unwrap();
        assert!(c.exit_via == "vps" && !c.home);
        assert_eq!(ips(peer(&c, "vps")), "0.0.0.0/0,100.88.0.1/32,100.88.0.2/32,192.168.1.0/24");
        assert_eq!(c.routes[0].to_string(), "0.0.0.0/0");
    }

    #[test]
    fn exit_node_not_used_at_home() {
        let c = build(&exit_input("192.168.1.77", direct("192.168.1.10:51820"))).unwrap();
        assert!(c.home && c.exit_via.is_empty());
        assert!(c.routes.iter().all(|r| r.bits != 0));
    }

    #[test]
    fn exit_node_needs_capable_platform() {
        let mut i = exit_input("10.20.0.5", via("vps"));
        i.exit_capable = false;
        let c = build(&i).unwrap();
        assert!(c.exit_via.is_empty() && !ips(peer(&c, "vps")).contains("0.0.0.0/0") && !c.warnings.is_empty());
    }

    fn lan_exit_input(exit_on: bool) -> Input<'static> {
        let mut h = home();
        h.lan_exits =
            vec![LanExit { src: "192.168.1.205".into(), via: "vps".into() }, LanExit { src: "192.168.20.0/24".into(), via: "vps".into() }];
        let mut v = vps();
        v.exit = exit_on;
        Input {
            network: network(),
            self_: h.clone(),
            nodes: vec![phone(), h, v],
            lan_exit_capable: true,
            paths: paths(&[("vps", direct("1.1.1.1:51820")), ("phone", via("vps"))]),
            ..Default::default()
        }
    }

    #[test]
    fn lan_exit() {
        let c = build(&lan_exit_input(true)).unwrap();
        assert!(c.lan_exit_via == "vps" && c.lan_exit_block.is_empty() && c.lan_exit_srcs.len() == 2);
        assert!(ips(peer(&c, "vps")).starts_with("0.0.0.0/0,"));
        assert!(c.routes.iter().all(|r| r.bits != 0));
    }

    #[test]
    fn lan_exit_fails_closed() {
        let mut i0 = lan_exit_input(false);
        let c = build(&i0).unwrap();
        assert!(c.lan_exit_block.is_empty() && c.lan_exit_srcs.is_empty());
        i0.self_.exit_only = true;
        let c = build(&i0).unwrap();
        assert!(c.lan_exit_via.is_empty() && c.lan_exit_block.len() == 2 && !ips(peer(&c, "vps")).contains("0.0.0.0/0"));

        let mut i = lan_exit_input(true);
        i.self_.exit_only = true;
        let mut v2 = vps2();
        v2.exit = false;
        i.nodes.push(v2);
        i.paths.paths.insert("vps2".into(), direct("2.2.2.2:51820"));
        let mut f = mc("vps2");
        f.name = "mc".into();
        i.forwards = vec![f];
        let c = build(&i).unwrap();
        assert!(c.lan_exit_via.is_empty() && !c.lan_exit_block.is_empty(), "conflict not caught");

        let mut i = lan_exit_input(true);
        i.lan_exit_capable = false;
        let c = build(&i).unwrap();
        assert!(c.lan_exit_via.is_empty() && c.lan_exit_block.is_empty() && c.lan_exit_srcs.is_empty());
    }

    #[test]
    fn exit_failover() {
        let mut p = phone();
        p.exit_via = "vps".into();
        let mut v = vps();
        v.exit = true;
        let mut i = Input {
            network: network(),
            self_: p.clone(),
            nodes: vec![p, home(), v.clone(), vps2()],
            exit_capable: true,
            paths: pathsel::Result {
                up: up(&[("home", true), ("vps", false), ("vps2", true)]),
                ..paths(&[("home", via("vps")), ("vps", direct("1.1.1.1:51820")), ("vps2", direct("2.2.2.2:51820"))])
            },
            ..Default::default()
        };
        let c = build(&i).unwrap();
        assert!(c.exit_via == "vps2" && ips(peer(&c, "vps2")).contains("0.0.0.0/0") && !ips(peer(&c, "vps")).contains("0.0.0.0/0"));
        i.paths.up.as_mut().unwrap().insert("vps2".into(), false);
        let c = build(&i).unwrap();
        assert!(c.exit_via.is_empty() && !c.exit_blocked);
        assert!(c.routes.iter().all(|r| r.bits != 0));
        i.self_.exit_only = true;
        let c = build(&i).unwrap();
        assert!(c.exit_blocked && !(ips(peer(&c, "vps")) + &ips(peer(&c, "vps2"))).contains("0.0.0.0/0"));
        assert_eq!(c.routes[0].bits, 0);

        let mut h = home();
        h.lan_exits = vec![LanExit { src: "192.168.1.205".into(), via: "vps".into() }];
        let i = Input {
            network: network(),
            self_: h.clone(),
            nodes: vec![phone(), h, v, vps2()],
            lan_exit_capable: true,
            paths: pathsel::Result {
                up: up(&[("vps", false), ("vps2", true)]),
                ..paths(&[("vps", direct("1.1.1.1:51820")), ("vps2", direct("2.2.2.2:51820")), ("phone", via("vps2"))])
            },
            ..Default::default()
        };
        assert_eq!(build(&i).unwrap().lan_exit_via, "vps2");
    }

    #[test]
    fn exit_permissions() {
        let mut p = phone();
        p.exit_via = "vps".into();
        p.exits_allowed = vec!["vps2".into()];
        let mut v = vps();
        v.exit = true;
        let mut i = Input {
            network: network(),
            self_: p.clone(),
            nodes: vec![p, home(), v, vps2()],
            exit_capable: true,
            exit_choice: "vps".into(),
            paths: paths(&[("home", via("vps")), ("vps", direct("1.1.1.1:51820")), ("vps2", direct("2.2.2.2:51820"))]),
            ..Default::default()
        };
        assert_eq!(build(&i).unwrap().exit_via, "vps2");
        i.paths.up = up(&[("vps", true), ("vps2", false)]);
        assert_eq!(build(&i).unwrap().exit_via, "");
        i.exit_choice = "off".into();
        i.self_.exits_allowed = vec!["*".into()];
        i.paths.up = None;
        assert_eq!(build(&i).unwrap().exit_via, "");
        i.exit_choice = "vps2".into();
        assert_eq!(build(&i).unwrap().exit_via, "vps2");
    }

    #[test]
    fn exit_routes() {
        let mut v = vps();
        v.exit = true;
        let er = |id: &str, src: &str, router: &str, exit_only: bool, enabled: bool| ExitRoute {
            id: id.into(),
            name: id.into(),
            src: src.into(),
            router: router.into(),
            via: "vps".into(),
            exit_only,
            enabled,
        };
        let routes = vec![
            er("a", "192.168.200.11", "home", true, true),
            er("b", "192.168.200.12", "home", false, true),
            er("c", "192.168.200.13", "home", false, false),
            er("d", "10.0.0.5", "other", false, true),
        ];
        let mut i = Input {
            network: network(),
            self_: home(),
            nodes: vec![phone(), home(), v],
            lan_exit_capable: true,
            exit_routes: Box::leak(routes.into_boxed_slice()),
            paths: paths(&[("vps", direct("1.1.1.1:51820")), ("phone", via("vps"))]),
            ..Default::default()
        };
        let c = build(&i).unwrap();
        assert_eq!(c.lan_exit_via, "vps");
        assert_eq!(strs(&c.lan_exit_srcs), "[192.168.200.11/32 192.168.200.12/32]");
        i.paths.up = up(&[("vps", false)]);
        let c = build(&i).unwrap();
        assert!(c.lan_exit_srcs.is_empty());
        assert_eq!(strs(&c.lan_exit_block), "[192.168.200.11/32]");
    }
}
