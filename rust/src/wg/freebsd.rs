//! WireGuard on FreeBSD/pfSense (Go: internal/wg/wg_freebsd.go): the if_wg
//! kernel module (FreeBSD 13.2+/pfSense 2.7+), configured with the `wg`
//! tool. Preserve-client-IP replies use pf's reply-to, so no policy routing.

use std::collections::{HashMap, HashSet};
use std::net::ToSocketAddrs;
use std::sync::Mutex;

use super::{MTU, PeerStat, key_string, parse_key};
use crate::meshcfg;
use crate::netx::Prefix;
use crate::util::run as exec;

#[derive(Default)]
struct State {
    up: bool,
    routes: HashSet<Prefix>,
}

pub struct Manager {
    pub iface: String,
    key: [u8; 32],
    userspace: Mutex<bool>,
    created: Mutex<bool>,
    st: Mutex<State>,
}

fn run(name: &str, args: &[&str]) -> Result<String, String> {
    let o = exec(name, args, None);
    if o.ok { Ok(o.out.trim().to_string()) } else { Err(format!("{name} {}: {}: {}", args.join(" "), o.err, o.out.trim())) }
}

fn iface_exists(name: &str) -> bool {
    crate::ifaces::list().iter().any(|i| i.name == name)
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
        if !crate::util::look_path("wg") {
            return Err("the `wg` tool is missing: pkg install wireguard-tools".into());
        }
        let exists = iface_exists(&self.iface);
        *self.created.lock().unwrap() = !exists;
        if !exists {
            let kernel = if force_userspace { Err("userspace forced".to_string()) } else { self.create_kernel() };
            if let Err(e) = kernel {
                logf!("wg: kernel WireGuard unavailable ({e}); using built-in userspace WireGuard");
                crate::wgu::start(&self.iface, MTU)?;
                *self.userspace.lock().unwrap() = true;
            }
        }
        run("ifconfig", &[&self.iface, "mtu", &MTU.to_string(), "up"])?;
        // FreeBSD puts every if_wg interface in the "wg" group, which
        // pfSense's WireGuard package treats as its own tunnels: leave it.
        let _ = run("ifconfig", &[&self.iface, "-group", "wg"]);
        st.up = true;
        Ok(())
    }

    fn create_kernel(&self) -> Result<(), String> {
        let _ = run("kldload", &["-n", "if_wg"]);
        let name = run("ifconfig", &["wg", "create"])?;
        if let Err(e) = run("ifconfig", &[&name, "name", &self.iface]) {
            let _ = run("ifconfig", &[&name, "destroy"]);
            return Err(e);
        }
        Ok(())
    }

    /// Recreates the interface when something else removed it.
    pub fn ensure(&self, force_userspace: bool) -> Result<bool, String> {
        let mut st = self.st.lock().unwrap();
        if !st.up || iface_exists(&self.iface) {
            return Ok(false);
        }
        crate::wgu::stop(&self.iface);
        st.up = false;
        st.routes.clear();
        *self.userspace.lock().unwrap() = false;
        self.up0(&mut st, force_userspace)?;
        *self.created.lock().unwrap() = true;
        Ok(true)
    }

    /// Makes the interface match cfg; peers are updated in place with
    /// `wg set` so sessions and roaming endpoints survive.
    pub fn apply(&self, cfg: &meshcfg::Config) -> Result<(), String> {
        let mut st = self.st.lock().unwrap();
        if !st.up {
            return Err("wg: not up".into());
        }
        let cur = self.dump()?;
        let mut args: Vec<String> = vec!["set".into(), self.iface.clone(), "private-key".into(), "/dev/stdin".into()];
        if cfg.listen_port > 0 {
            args.extend(["listen-port".into(), cfg.listen_port.to_string()]);
        }
        let mut want = HashSet::new();
        for p in &cfg.peers {
            if parse_key(&p.public_key).is_none() {
                continue;
            }
            want.insert(p.public_key.clone());
            let ips: Vec<String> = p.allowed_ips.iter().map(|a| a.to_string()).collect();
            let ka = if p.keepalive <= 0 { "off".to_string() } else { p.keepalive.to_string() };
            args.extend(["peer".into(), p.public_key.clone(), "allowed-ips".into(), ips.join(","), "persistent-keepalive".into(), ka]);
            if !p.endpoint.is_empty() {
                if let Some(a) = p.endpoint.to_socket_addrs().ok().and_then(|mut a| a.find(|x| x.is_ipv4())) {
                    args.extend(["endpoint".into(), a.to_string()]);
                }
            }
        }
        for k in cur.keys() {
            if !want.contains(k) {
                args.extend(["peer".into(), k.clone(), "remove".into()]);
            }
        }
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        let o = exec("wg", &a, Some(&format!("{}\n", key_string(&self.key))));
        if !o.ok {
            return Err(format!("wg set: {}: {}", o.err, o.out.trim()));
        }
        self.apply_network(&mut st, cfg)
    }

    /// `wg show <iface> dump` as per-peer stats.
    fn dump(&self) -> Result<HashMap<String, PeerStat>, String> {
        Ok(parse_dump(&run("wg", &["show", &self.iface, "dump"])?))
    }

    fn apply_network(&self, st: &mut State, cfg: &meshcfg::Config) -> Result<(), String> {
        let addr = cfg.address.ok_or("no address")?;
        let mut have = false;
        if let Some(i) = crate::ifaces::list().into_iter().find(|i| i.name == self.iface) {
            for (a, bits) in i.addrs.iter().filter(|(a, _)| a.is_ipv4()) {
                if *a == addr.addr && *bits == addr.bits {
                    have = true;
                    continue;
                }
                let _ = run("ifconfig", &[&self.iface, "inet", &a.to_string(), "-alias"]);
            }
        }
        if !have {
            run("ifconfig", &[&self.iface, "inet", &addr.to_string(), "alias"])?;
        }
        let keep: HashSet<Prefix> = cfg.routes.iter().copied().collect();
        for p in &cfg.routes {
            if st.routes.contains(p) {
                continue;
            }
            // "change" fails if the route does not exist; then add it.
            let ps = p.to_string();
            if run("route", &["-q", "-n", "change", "-net", &ps, "-interface", &self.iface]).is_err() {
                run("route", &["-q", "-n", "add", "-net", &ps, "-interface", &self.iface])?;
            }
            st.routes.insert(*p);
        }
        let gone: Vec<Prefix> = st.routes.iter().filter(|p| !keep.contains(p)).copied().collect();
        for p in gone {
            let _ = run("route", &["-q", "-n", "delete", "-net", &p.to_string(), "-interface", &self.iface]);
            st.routes.remove(&p);
        }
        Ok(())
    }

    /// Drops the sessions of the given peers.
    pub fn reset_peers(&self, keys: &[String]) -> Result<(), String> {
        let st = self.st.lock().unwrap();
        if !st.up || keys.is_empty() {
            return Ok(());
        }
        let mut args = vec!["set".to_string(), self.iface.clone()];
        for k in keys {
            args.extend(["peer".into(), k.clone(), "remove".into()]);
        }
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        run("wg", &a).map(|_| ())
    }

    pub fn stats(&self) -> HashMap<String, PeerStat> {
        let st = self.st.lock().unwrap();
        if !st.up {
            return HashMap::new();
        }
        self.dump().unwrap_or_default()
    }

    /// Linux only for now.
    pub fn sync_underlay(&self) {}

    /// A kernel interface keeps running when meshgate exits.
    pub fn release(&self) {
        if self.is_userspace() {
            self.down();
        }
    }

    pub fn down(&self) {
        let mut st = self.st.lock().unwrap();
        if self.is_userspace() {
            crate::wgu::stop(&self.iface);
        } else {
            let _ = run("ifconfig", &[&self.iface, "destroy"]);
        }
        st.up = false;
        st.routes.clear();
    }
}

/// Parses `wg show <iface> dump`.
pub fn parse_dump(out: &str) -> HashMap<String, PeerStat> {
    let mut res = HashMap::new();
    for (i, l) in out.trim().split('\n').enumerate() {
        let f: Vec<&str> = l.split('\t').collect();
        if i == 0 || f.len() < 8 {
            continue;
        }
        let mut s = PeerStat { public_key: f[0].into(), ..Default::default() };
        if f[2] != "(none)" {
            s.endpoint = f[2].into();
        }
        let ts: i64 = f[4].parse().unwrap_or(0);
        if ts > 0 {
            s.last_handshake = (ts, 0);
        }
        s.rx_bytes = f[5].parse().unwrap_or(0);
        s.tx_bytes = f[6].parse().unwrap_or(0);
        res.insert(s.public_key.clone(), s);
    }
    res
}

/// Destroys the interface (meshgate stop).
pub fn teardown(iface: &str) {
    destroy_interface(iface);
}

pub fn enable_forwarding() {
    let _ = run("sysctl", &["net.inet.ip.forwarding=1"]);
}

/// Removes the interface (`meshgate leave`).
pub fn destroy_interface(name: &str) {
    let _ = run("ifconfig", &[name, "destroy"]);
}
