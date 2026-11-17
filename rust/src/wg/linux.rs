//! Kernel WireGuard on Linux over netlink (Go: internal/wg/wg_linux.go).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::Mutex;

use super::{MTU, PeerStat, key_string, parse_key};
use crate::fw::{self, MARK_BYPASS, MARK_PRESERVE, TABLE_LAN_BLOCK, TABLE_LAN_EXIT, TABLE_REPLY, TABLE_ROUTES, TABLE_UNDERLAY};
use crate::meshcfg;
use crate::netlink::{self as nl, Route, Rule};
use crate::netx::Prefix;

// Before other VPNs' rules (NetBird uses 105/110, wg-quick and Tailscale
// come later), so they cannot pull the mesh into their tunnel.
const PRIO_UNDERLAY: u32 = 90;
const PRIO_REPLY: u32 = 5200;
const PRIO_ROUTES: u32 = 5210;
const PRIO_LAN_LOCAL: u32 = 5220;
const PRIO_LAN_EXIT: u32 = 5221;
const PRIO_LAN_BLOCK: u32 = 5222;

#[derive(Default)]
struct State {
    up: bool,
    underlay: bool,
    nft_tried: Option<std::time::Instant>,
    route_err: HashMap<String, String>,
}

/// Owns one interface.
pub struct Manager {
    pub iface: String,
    key: [u8; 32],
    /// true if using a userspace implementation.
    pub userspace: Mutex<bool>,
    /// Up made a new interface (false: it took over a running one).
    pub created: Mutex<bool>,
    st: Mutex<State>,
}

fn io_err(e: std::io::Error) -> String {
    e.to_string()
}

impl Manager {
    pub fn new(iface: &str, key: [u8; 32]) -> Manager {
        Manager { iface: iface.into(), key, userspace: Mutex::new(false), created: Mutex::new(false), st: Mutex::new(State::default()) }
    }

    pub fn is_created(&self) -> bool {
        *self.created.lock().unwrap()
    }

    pub fn is_userspace(&self) -> bool {
        *self.userspace.lock().unwrap()
    }

    /// Creates the interface if needed.
    pub fn up(&self, force_userspace: bool) -> Result<(), String> {
        let mut st = self.st.lock().unwrap();
        self.up0(&mut st, force_userspace)
    }

    fn up0(&self, st: &mut State, force_userspace: bool) -> Result<(), String> {
        let link = match nl::link_by_name(&self.iface) {
            Ok(l) => {
                *self.created.lock().unwrap() = false;
                l
            }
            Err(_) => {
                *self.created.lock().unwrap() = true;
                let mut err = None;
                if !force_userspace {
                    err = nl::link_add(&self.iface, "wireguard").err();
                }
                if force_userspace || err.is_some() {
                    if let Some(e) = &err {
                        logf!("wg: kernel WireGuard unavailable ({e}); using built-in userspace WireGuard");
                    }
                    crate::wgu::start(&self.iface, MTU)?;
                    *self.userspace.lock().unwrap() = true;
                }
                nl::link_by_name(&self.iface).map_err(io_err)?
            }
        };
        nl::link_set_mtu(link.index, MTU).map_err(io_err)?;
        nl::link_set_up(link.index).map_err(io_err)?;
        sysctl("net/ipv4/conf/all/src_valid_mark", "1");
        sysctl(&format!("net/ipv4/conf/{}/rp_filter", self.iface), "2");
        st.up = true;
        Ok(())
    }

    /// Recreates the interface when something else removed it. true tells
    /// the caller to apply the whole config again.
    pub fn ensure(&self, force_userspace: bool) -> Result<bool, String> {
        let mut st = self.st.lock().unwrap();
        if !st.up || nl::link_by_name(&self.iface).is_ok() {
            return Ok(false);
        }
        crate::wgu::stop(&self.iface);
        *self.userspace.lock().unwrap() = false;
        self.up0(&mut st, force_userspace)?;
        *self.created.lock().unwrap() = true;
        Ok(true)
    }

    /// Makes the interface match cfg. Peers not in cfg are removed;
    /// endpoints learned by roaming are kept when cfg has none.
    pub fn apply(&self, cfg: &meshcfg::Config) -> Result<(), String> {
        let st = self.st.lock().unwrap();
        if !st.up {
            return Err("wg: not up".into());
        }
        let cur = self.device()?;
        let mut want: HashSet<[u8; 32]> = HashSet::new();
        let mut peers = vec![];
        for p in &cfg.peers {
            let Some(k) = parse_key(&p.public_key) else { continue };
            want.insert(k);
            let endpoint = if p.endpoint.is_empty() { None } else { resolve4(&p.endpoint) };
            peers.push(nl::WgPeerConfig {
                public_key: k,
                remove: false,
                replace_allowed_ips: true,
                endpoint,
                keepalive: Some(p.keepalive as u16),
                allowed_ips: p.allowed_ips.iter().map(|a| (a.addr, a.bits)).collect(),
            });
        }
        for p in &cur.peers {
            if !want.contains(&p.public_key) {
                peers.push(nl::WgPeerConfig { public_key: p.public_key, remove: true, ..Default::default() });
            }
        }
        let wc = nl::WgConfig {
            private_key: Some(self.key),
            listen_port: (cfg.listen_port > 0).then_some(cfg.listen_port as u16),
            fwmark: Some(MARK_BYPASS),
            peers,
        };
        self.configure(&wc).map_err(|e| format!("configure {}: {e}", self.iface))?;
        self.apply_network(cfg)
    }

    fn device(&self) -> Result<nl::WgDevice, String> {
        if self.is_userspace() { crate::wgu::get(&self.iface) } else { nl::wg_get(&self.iface).map_err(io_err) }
    }

    fn configure(&self, c: &nl::WgConfig) -> Result<(), String> {
        if self.is_userspace() { crate::wgu::set(&self.iface, c) } else { nl::wg_set(&self.iface, c).map_err(io_err) }
    }

    fn apply_network(&self, cfg: &meshcfg::Config) -> Result<(), String> {
        let link = nl::link_by_name(&self.iface).map_err(io_err)?;
        let addr = cfg.address.ok_or("no address")?;
        let want = nl::Addr { ip: addr.addr, bits: addr.bits, index: link.index };
        for a in nl::addr_list4(link.index).unwrap_or_default() {
            if a.ip != want.ip || a.bits != want.bits {
                let _ = nl::addr_del(&a);
            }
        }
        nl::addr_replace(&want).map_err(|e| format!("address: {e}"))?;

        // Subnet routes live in their own table, consulted by every packet
        // except WireGuard's own and probe sockets (MarkBypass).
        sync_routes(link.index, TABLE_ROUTES, &cfg.routes)?;
        ensure_rule(PRIO_ROUTES, TABLE_ROUTES, MARK_BYPASS, true, !cfg.routes.is_empty());

        // Preserve-client-IP replies: marked packets use a table whose
        // default route is the tunnel.
        let reply: Vec<Prefix> = if cfg.default_via_peer.is_empty() { vec![] } else { vec![all4()] };
        sync_routes(link.index, TABLE_REPLY, &reply)?;
        ensure_rule(PRIO_REPLY, TABLE_REPLY, MARK_PRESERVE, false, !reply.is_empty());

        // LAN devices sent to an exit node.
        sync_lan_exit_table(link.index, cfg)?;
        let routed: Vec<Prefix> = if cfg.lan_exit_via.is_empty() { vec![] } else { cfg.lan_exit_srcs.clone() };
        let local: Vec<Prefix> = routed.iter().chain(&cfg.lan_exit_block).copied().collect();
        sync_src_rules(PRIO_LAN_LOCAL, nl::RT_TABLE_MAIN, true, &local);
        sync_src_rules(PRIO_LAN_EXIT, TABLE_LAN_EXIT, false, &routed);
        sync_src_rules(PRIO_LAN_BLOCK, TABLE_LAN_BLOCK, false, &cfg.lan_exit_block);
        Ok(())
    }

    /// Drops the sessions of the given peers; the next apply adds them back,
    /// which makes WireGuard handshake right away.
    pub fn reset_peers(&self, keys: &[String]) -> Result<(), String> {
        let st = self.st.lock().unwrap();
        if !st.up || keys.is_empty() {
            return Ok(());
        }
        let peers = keys
            .iter()
            .filter_map(|k| parse_key(k))
            .map(|k| nl::WgPeerConfig { public_key: k, remove: true, ..Default::default() })
            .collect();
        self.configure(&nl::WgConfig { peers, ..Default::default() })
    }

    /// Peer runtime data keyed by public key.
    pub fn stats(&self) -> HashMap<String, PeerStat> {
        let st = self.st.lock().unwrap();
        let mut out = HashMap::new();
        if !st.up {
            return out;
        }
        let Ok(d) = self.device() else { return out };
        for p in d.peers {
            let s = PeerStat {
                public_key: key_string(&p.public_key),
                endpoint: p.endpoint.map(|e| e.to_string()).unwrap_or_default(),
                last_handshake: p.last_handshake,
                rx_bytes: p.rx_bytes as i64,
                tx_bytes: p.tx_bytes as i64,
            };
            out.insert(s.public_key.clone(), s);
        }
        out
    }

    /// Lets go of the interface when meshgate exits but leaves a kernel
    /// interface running with its peers, routes and rules: traffic is not
    /// interrupted by a restart or update. (Userspace ends with the process.)
    pub fn release(&self) {
        let mut st = self.st.lock().unwrap();
        if self.is_userspace() {
            self.down0(&mut st);
            return;
        }
        st.up = false;
    }

    /// Removes the interface, rules and tables.
    pub fn down(&self) {
        let mut st = self.st.lock().unwrap();
        self.down0(&mut st);
    }

    fn down0(&self, st: &mut State) {
        ensure_rule(PRIO_ROUTES, TABLE_ROUTES, 0, true, false);
        ensure_rule(PRIO_REPLY, TABLE_REPLY, 0, false, false);
        sync_src_rules(PRIO_LAN_LOCAL, nl::RT_TABLE_MAIN, true, &[]);
        sync_src_rules(PRIO_LAN_EXIT, TABLE_LAN_EXIT, false, &[]);
        sync_src_rules(PRIO_LAN_BLOCK, TABLE_LAN_BLOCK, false, &[]);
        ensure_rule(PRIO_UNDERLAY, TABLE_UNDERLAY, 0, false, false);
        sync_table(TABLE_UNDERLAY, &[], None);
        if st.underlay {
            let _ = nft("table inet meshgate_underlay\ndelete table inet meshgate_underlay\n", true);
            st.underlay = false;
        }
        crate::wgu::stop(&self.iface);
        if let Ok(l) = nl::link_by_name(&self.iface) {
            let _ = nl::link_del(l.index);
        }
        st.up = false;
    }

    /// Keeps WireGuard's own packets and the path probes on this machine's
    /// real connection when another VPN takes over the default route (see
    /// the Go function for the full story).
    pub fn sync_underlay(&self) {
        let mut st = self.st.lock().unwrap();
        let links = nl::link_list().unwrap_or_default();
        let real: HashMap<i32, bool> =
            links.iter().map(|l| (l.index, l.name != self.iface && !fw::is_tunnel(&l.name, l.point_to_point()))).collect();
        let is_real = |i: i32| real.get(&i).copied().unwrap_or(false);
        let names: HashMap<i32, &str> = links.iter().map(|l| (l.index, l.name.as_str())).collect();
        let all = nl::route_list4().unwrap_or_default();
        let mut want: Vec<Route> = vec![];
        let mut have: HashSet<String> = HashSet::new();
        for r in &all {
            let via_real = if r.multipath.is_empty() { is_real(r.index) } else { r.multipath.iter().all(|h| is_real(h.index)) };
            if r.table != nl::RT_TABLE_MAIN || r.typ != nl::RTN_UNICAST || !via_real || r.flags & nl::RTNH_F_LINKDOWN != 0 {
                continue; // a down link (e.g. an idle Docker bridge) cannot take routes
            }
            // Only ONLINK may be set by us; LINKDOWN, DEAD etc. are the kernel's.
            let hops = r.multipath.iter().map(|h| nl::Nexthop { flags: h.flags & nl::RTNH_F_ONLINK, ..h.clone() }).collect();
            want.push(Route {
                index: r.index,
                dst: r.dst,
                gw: r.gw,
                src: r.src,
                scope: r.scope,
                priority: r.priority,
                multipath: hops,
                flags: r.flags & nl::RTNH_F_ONLINK,
                typ: nl::RTN_UNICAST,
                table: TABLE_UNDERLAY,
                protocol: 0,
            });
            have.insert(r.dst_key());
        }
        for r in &all {
            // Another VPN's own subnets (not its 0/0 or 0/1 takeover routes).
            if r.table == TABLE_UNDERLAY || r.dst.is_none() || r.index == 0 || is_real(r.index) || have.contains(&r.dst_key()) {
                continue;
            }
            if r.dst.is_some_and(|d| d.1 < 8) || r.typ != nl::RTN_UNICAST {
                continue;
            }
            match names.get(&r.index) {
                Some(n) if *n != self.iface => {}
                _ => continue,
            }
            have.insert(r.dst_key());
            want.push(Route { dst: r.dst, typ: nl::RTN_THROW, table: TABLE_UNDERLAY, ..Default::default() });
        }
        sync_table(TABLE_UNDERLAY, &want, Some(&mut st.route_err));
        ensure_rule(PRIO_UNDERLAY, TABLE_UNDERLAY, MARK_BYPASS, false, !want.is_empty());
        if !st.underlay && st.nft_tried.is_none_or(|t| t.elapsed().as_secs() > 600) {
            let logged = st.nft_tried.is_some();
            st.nft_tried = Some(std::time::Instant::now());
            // Replies carry no mark; restore it from the connection so strict
            // rp_filter (with src_valid_mark) checks them the same way.
            let m = MARK_BYPASS;
            st.underlay = nft(
                &format!(
                    "table inet meshgate_underlay
delete table inet meshgate_underlay
table inet meshgate_underlay {{
\tchain out {{
\t\ttype route hook output priority mangle;
\t\tmeta l4proto udp meta mark 0x{m:x} ct mark set meta mark
\t}}
\tchain pre {{
\t\ttype filter hook prerouting priority mangle;
\t\tmeta l4proto udp ct mark 0x{m:x} meta mark set ct mark
\t}}
}}
"
                ),
                logged,
            )
            .is_ok();
        }
    }
}

fn all4() -> Prefix {
    Prefix::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

fn resolve4(ep: &str) -> Option<SocketAddr> {
    ep.to_socket_addrs().ok()?.find(|a| a.is_ipv4())
}

/// Removes the interface, its rules and tables (`meshgate stop`).
pub fn teardown(iface: &str) {
    let m = Manager::new(iface, [0; 32]);
    let mut st = m.st.lock().unwrap();
    st.underlay = true;
    m.down0(&mut st);
}

/// Turns on IPv4 routing (server nodes).
pub fn enable_forwarding() {
    sysctl("net/ipv4/ip_forward", "1");
}

/// Removes the interface (`meshgate leave`).
pub fn destroy_interface(name: &str) {
    if let Ok(l) = nl::link_by_name(name) {
        let _ = nl::link_del(l.index);
    }
}

/// Tags a socket with MarkBypass so it ignores mesh routes.
pub fn mark_socket(s: &socket2::Socket) -> std::io::Result<()> {
    s.set_mark(MARK_BYPASS)
}

fn sync_lan_exit_table(index: i32, cfg: &meshcfg::Config) -> Result<(), String> {
    let tunnel = (!cfg.lan_exit_via.is_empty()).then(|| Route {
        index,
        dst: None,
        table: TABLE_LAN_EXIT,
        scope: nl::RT_SCOPE_LINK,
        typ: nl::RTN_UNICAST,
        ..Default::default()
    });
    let block =
        (!cfg.lan_exit_block.is_empty()).then(|| Route { dst: None, table: TABLE_LAN_BLOCK, typ: nl::RTN_BLACKHOLE, ..Default::default() });
    sync_default(TABLE_LAN_EXIT, tunnel)?;
    sync_default(TABLE_LAN_BLOCK, block)
}

/// Makes want the only route in table (none when want is None).
fn sync_default(table: u32, want: Option<Route>) -> Result<(), String> {
    for r in nl::route_list4().unwrap_or_default().into_iter().filter(|r| r.table == table) {
        if want.as_ref().is_none_or(|w| r.typ != w.typ || r.index != w.index) {
            let _ = nl::route_del(&r);
        }
    }
    if let Some(w) = want {
        nl::route_replace(&w).map_err(|e| format!("lan exit route: {e}"))?;
    }
    Ok(())
}

/// Keeps exactly one "from <src> lookup table" rule per source at prio.
fn sync_src_rules(prio: u32, table: u32, suppress_default: bool, srcs: &[Prefix]) {
    let mut want: HashSet<String> = srcs.iter().map(|s| s.to_string()).collect();
    for r in nl::rule_list4().unwrap_or_default() {
        if r.priority != prio {
            continue;
        }
        if let Some((ip, bits)) = r.src {
            let s = Prefix::new(ip, bits).to_string();
            if want.contains(&s) && r.table == table {
                want.remove(&s);
                continue;
            }
        }
        let _ = nl::rule_del(&r);
    }
    for s in want {
        let p = crate::netx::parse_prefix(&s).unwrap();
        let r = Rule {
            priority: prio,
            table,
            src: Some((p.addr, p.bits)),
            suppress_prefixlen: if suppress_default { 0 } else { -1 },
            ..Default::default()
        };
        if let Err(e) = nl::rule_add(&r) {
            logf!("wg: ip rule from {s}: {e}");
        }
    }
}

fn sync_routes(index: i32, table: u32, want: &[Prefix]) -> Result<(), String> {
    let have = nl::route_list4().map_err(io_err)?;
    let keep: HashSet<String> = want.iter().map(|p| p.to_string()).collect();
    for r in have.iter().filter(|r| r.table == table && r.index == index) {
        if !keep.contains(&r.dst_key()) {
            let _ = nl::route_del(r);
        }
    }
    for p in want {
        let dst = if p.bits == 0 { None } else { Some((p.addr, p.bits)) };
        let r = Route { index, dst, table, scope: nl::RT_SCOPE_LINK, typ: nl::RTN_UNICAST, ..Default::default() };
        nl::route_replace(&r).map_err(|e| format!("route {p}: {e}"))?;
    }
    Ok(())
}

/// Adds or removes "[not] fwmark M lookup T".
fn ensure_rule(prio: u32, table: u32, mark: u32, invert: bool, present: bool) {
    let found: Vec<Rule> = nl::rule_list4().unwrap_or_default().into_iter().filter(|r| r.priority == prio && r.table == table).collect();
    if present && !found.is_empty() {
        return;
    }
    for r in &found {
        let _ = nl::rule_del(r);
    }
    if !present {
        return;
    }
    let r = Rule { priority: prio, table, mark, mask: Some(0xffff_ffff), invert, suppress_prefixlen: -1, ..Default::default() };
    if let Err(e) = nl::rule_add(&r) {
        logf!("wg: ip rule {prio}: {e}");
    }
}

fn route_key(r: &Route) -> String {
    let ip = |a: Option<IpAddr>| a.map(|a| a.to_string()).unwrap_or_else(|| "<nil>".into());
    let mut k = format!("{} {} {} {} {} {}", r.typ, r.dst_key(), ip(r.gw), r.index, r.priority, ip(r.src));
    for h in &r.multipath {
        k.push_str(&format!(" {}@{}", ip(h.gw), h.index));
    }
    k
}

/// Makes table hold exactly want. A route that keeps failing is logged
/// once (errs remembers it).
fn sync_table(table: u32, want: &[Route], mut errs: Option<&mut HashMap<String, String>>) {
    let mut keep: HashSet<String> = want.iter().map(route_key).collect();
    for r in nl::route_list4().unwrap_or_default().into_iter().filter(|r| r.table == table) {
        let k = route_key(&r);
        if keep.remove(&k) {
            continue;
        }
        let _ = nl::route_del(&r);
    }
    for r in want {
        let k = route_key(r);
        if !keep.contains(&k) {
            continue;
        }
        match nl::route_replace(r) {
            Err(e) => {
                if let Some(errs) = errs.as_deref_mut() {
                    if errs.get(&k).map(String::as_str) != Some(&e.to_string()) {
                        logf!("wg: underlay route {}: {e}", r.dst_key());
                    }
                    errs.insert(k, e.to_string());
                }
            }
            Ok(()) => {
                if let Some(errs) = errs.as_deref_mut() {
                    errs.remove(&k);
                }
            }
        }
    }
}

/// Loads nft rules; quiet skips logging a failure already reported.
fn nft(rules: &str, quiet: bool) -> Result<(), String> {
    let o = crate::util::run("nft", &["-f", "-"], Some(rules));
    if o.ok {
        return Ok(());
    }
    if !quiet {
        logf!("wg: nft: {}: {} (replies may hit strict rp_filter while another VPN holds the default route)", o.err, o.out.trim());
    }
    Err(o.err)
}

fn sysctl(key: &str, val: &str) {
    if let Err(e) = std::fs::write(format!("/proc/sys/{key}"), val) {
        logf!("sysctl {key}={val}: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meshcfg::{Config, Peer};

    /// Runs the body as root of a fresh network namespace (unshare -r -n),
    /// the way the end-to-end lab does. Skips where namespaces are not
    /// allowed.
    fn in_namespace(name: &str, body: fn()) {
        if std::env::var_os("MG_IN_NS").is_some() {
            body();
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let o = std::process::Command::new("unshare")
            .args(["-r", "-n", "-m"])
            .arg(&exe)
            .args([name, "--exact", "--nocapture", "--test-threads=1"])
            .env("MG_IN_NS", "1")
            .output();
        let Ok(o) = o else { return };
        let text = String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr);
        if text.contains("Operation not permitted") || text.contains("unshare failed") {
            return;
        }
        assert!(o.status.success() && text.contains("1 passed"), "{text}");
    }

    #[test]
    fn kernel_wireguard_in_namespace() {
        in_namespace("wg::linux::tests::kernel_wireguard_in_namespace", || {
            let lo = nl::link_by_name("lo").unwrap();
            nl::link_set_up(lo.index).unwrap();
            let key = super::super::generate_private_key();
            let m = Manager::new("mgt0", key);
            m.up(false).unwrap();
            assert!(m.is_created() && !m.is_userspace());
            let pk = |n: u8| key_string(&super::super::public_key(&[n; 32]));
            let pfx = |s: &str| crate::netx::parse_prefix(s).unwrap();
            let cfg = Config {
                address: Some(pfx("100.88.0.2/16")),
                listen_port: 51999,
                peers: vec![
                    Peer {
                        node_id: "a".into(),
                        public_key: pk(1),
                        endpoint: "127.0.0.1:51820".into(),
                        allowed_ips: vec![pfx("100.88.0.1/32"), pfx("192.168.50.0/24")],
                        keepalive: 20,
                    },
                    Peer {
                        node_id: "b".into(),
                        public_key: pk(2),
                        allowed_ips: vec![pfx("100.88.0.3/32"), pfx("0.0.0.0/0")],
                        ..Default::default()
                    },
                ],
                routes: vec![pfx("192.168.50.0/24")],
                default_via_peer: "b".into(),
                ..Default::default()
            };
            m.apply(&cfg).unwrap();
            let st = m.stats();
            assert_eq!(st.len(), 2);
            assert_eq!(st[&pk(1)].endpoint, "127.0.0.1:51820");
            let dev = nl::wg_get("mgt0").unwrap();
            assert_eq!(dev.listen_port, 51999);
            assert_eq!(dev.fwmark, MARK_BYPASS);
            let a = dev.peers.iter().find(|p| key_string(&p.public_key) == pk(1)).unwrap();
            assert_eq!(a.keepalive, 20);
            assert_eq!(a.allowed_ips.len(), 2);
            let idx = nl::link_by_name("mgt0").unwrap().index;
            assert_eq!(nl::addr_list4(idx).unwrap()[0].ip.to_string(), "100.88.0.2");
            let routes = nl::route_list4().unwrap();
            assert!(routes.iter().any(|r| r.table == TABLE_ROUTES && r.dst_key() == "192.168.50.0/24"));
            assert!(routes.iter().any(|r| r.table == TABLE_REPLY && r.dst.is_none()));
            let rules = nl::rule_list4().unwrap();
            let r = rules.iter().find(|r| r.priority == PRIO_ROUTES).expect("routes rule");
            assert!(r.invert && r.mark == MARK_BYPASS && r.table == TABLE_ROUTES);
            assert!(rules.iter().any(|r| r.priority == PRIO_REPLY && r.mark == MARK_PRESERVE));

            // Peer b dropped, routes gone: removed from the kernel too.
            let mut c2 = cfg.clone();
            c2.peers.truncate(1);
            c2.routes.clear();
            c2.default_via_peer.clear();
            m.apply(&c2).unwrap();
            assert_eq!(m.stats().len(), 1);
            let rules = nl::rule_list4().unwrap();
            assert!(!rules.iter().any(|r| r.priority == PRIO_ROUTES || r.priority == PRIO_REPLY));

            // Release keeps the interface (restart without dropping traffic).
            m.release();
            assert!(nl::link_by_name("mgt0").is_ok());
            let m2 = Manager::new("mgt0", key);
            m2.up(false).unwrap();
            assert!(!m2.is_created(), "took over the running interface");
            assert_eq!(m2.stats().len(), 1);
            // Something deletes the interface: ensure brings it back.
            nl::link_del(idx).unwrap();
            assert!(m2.ensure(false).unwrap());
            teardown("mgt0");
            assert!(nl::link_by_name("mgt0").is_err());
        });
    }

    #[test]
    fn userspace_wireguard_in_namespace() {
        in_namespace("wg::linux::tests::userspace_wireguard_in_namespace", || {
            // /var/run must be writable for the UAPI socket.
            let ok = std::process::Command::new("mount").args(["-t", "tmpfs", "none", "/run"]).status().is_ok_and(|s| s.success());
            if !ok || !std::path::Path::new("/dev/net/tun").exists() {
                return;
            }
            let key = super::super::generate_private_key();
            let m = Manager::new("mgu0", key);
            m.up(true).unwrap();
            assert!(m.is_userspace() && m.is_created());
            let pk = key_string(&super::super::public_key(&[7; 32]));
            let pfx = |s: &str| crate::netx::parse_prefix(s).unwrap();
            let cfg = Config {
                address: Some(pfx("100.88.0.9/16")),
                listen_port: 51998,
                peers: vec![Peer {
                    node_id: "a".into(),
                    public_key: pk.clone(),
                    endpoint: "127.0.0.1:51820".into(),
                    allowed_ips: vec![pfx("100.88.0.1/32")],
                    keepalive: 20,
                }],
                ..Default::default()
            };
            m.apply(&cfg).unwrap();
            let st = m.stats();
            assert_eq!(st[&pk].endpoint, "127.0.0.1:51820");
            let dev = crate::wgu::get("mgu0").unwrap();
            assert_eq!(dev.listen_port, 51998);
            assert_eq!(dev.fwmark, MARK_BYPASS);
            assert_eq!(dev.peers[0].allowed_ips, vec![("100.88.0.1".parse().unwrap(), 32)]);
            let idx = nl::link_by_name("mgu0").unwrap().index;
            assert_eq!(nl::addr_list4(idx).unwrap()[0].ip.to_string(), "100.88.0.9");
            // Userspace ends with the process: release takes it down.
            m.release();
            assert!(nl::link_by_name("mgu0").is_err());
        });
    }
}
