//! Nodes on Windows and macOS: userspace WireGuard (wgdev, the role
//! wireguard-go plays in the Go build) on the system's TUN device (Wintun,
//! utun). The tunnel belongs to the process and ends with it.

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};

use super::types::{WgConfig, WgPeerConfig};
use super::{PeerStat, key_string, parse_key};
use crate::meshcfg;
use crate::netx::Prefix;
use crate::wgdev;

#[cfg(windows)]
use super::windows as platform;

#[cfg(target_os = "macos")]
use super::macos as platform;

/// The system side of the tunnel: packets plus the interface's address and
/// routes.
pub(super) trait NetIf: Send + Sync {
    fn tun(&self) -> Arc<dyn wgdev::Tun>;
    fn set_address(&self, a: Prefix) -> Result<(), String>;
    /// Replaces the routes added before (`old`) with `new`.
    fn set_routes(&self, old: &[Prefix], new: &[Prefix]) -> Result<(), String>;
    /// Removes the interface.
    fn close(&self);
}

#[derive(Default)]
struct State {
    net: Option<Box<dyn NetIf>>,
    dev: Option<wgdev::Device>,
    addr: Option<Prefix>,
    routes: Vec<Prefix>,
}

pub struct Manager {
    pub iface: String,
    key: [u8; 32],
    st: Mutex<State>,
}

impl Manager {
    pub fn new(iface: &str, key: [u8; 32]) -> Manager {
        Manager { iface: iface.into(), key, st: Mutex::new(State::default()) }
    }

    /// Always: the adapter ends with the process.
    pub fn is_created(&self) -> bool {
        true
    }

    pub fn is_userspace(&self) -> bool {
        true
    }

    /// Creates the TUN device and starts WireGuard.
    pub fn up(&self, _force_userspace: bool) -> Result<(), String> {
        let mut st = self.st.lock().unwrap();
        if st.dev.is_some() {
            return Ok(());
        }
        let net = platform::open(&self.iface)?;
        let dev = wgdev::Device::new(net.tun(), None).map_err(|e| format!("wireguard: {e}"))?;
        if let Err(e) = dev.set(&WgConfig { private_key: Some(self.key), ..Default::default() }) {
            drop(dev);
            net.close();
            return Err(e);
        }
        *st = State { net: Some(net), dev: Some(dev), addr: None, routes: vec![] };
        Ok(())
    }

    /// Nothing to recover: the device belongs to this process.
    pub fn ensure(&self, _force_userspace: bool) -> Result<bool, String> {
        Ok(false)
    }

    /// Makes the device match cfg.
    pub fn apply(&self, cfg: &meshcfg::Config) -> Result<(), String> {
        let mut st = self.st.lock().unwrap();
        let (Some(dev), Some(net)) = (&st.dev, &st.net) else { return Err("wg: not up".into()) };
        let cur = dev.get();
        let mut want: HashSet<[u8; 32]> = HashSet::new();
        let mut peers = vec![];
        for p in &cfg.peers {
            let Some(k) = parse_key(&p.public_key) else { continue };
            want.insert(k);
            let endpoint = if p.endpoint.is_empty() { None } else { resolve4(&p.endpoint) };
            peers.push(WgPeerConfig {
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
                peers.push(WgPeerConfig { public_key: p.public_key, remove: true, ..Default::default() });
            }
        }
        let wc = WgConfig { listen_port: (cfg.listen_port > 0).then_some(cfg.listen_port as u16), peers, ..Default::default() };
        dev.set(&wc).map_err(|e| format!("configure: {e}"))?;

        let addr = cfg.address.ok_or("no address")?;
        if st.addr != Some(addr) {
            net.set_address(addr).map_err(|e| format!("address: {e}"))?;
        }
        if st.routes != cfg.routes {
            net.set_routes(&st.routes, &cfg.routes).map_err(|e| format!("routes: {e}"))?;
        }
        st.addr = Some(addr);
        st.routes = cfg.routes.clone();
        Ok(())
    }

    /// Drops the sessions of the given peers; the next apply adds them back.
    pub fn reset_peers(&self, keys: &[String]) -> Result<(), String> {
        let st = self.st.lock().unwrap();
        let Some(dev) = &st.dev else { return Ok(()) };
        if keys.is_empty() {
            return Ok(());
        }
        let peers =
            keys.iter().filter_map(|k| parse_key(k)).map(|k| WgPeerConfig { public_key: k, remove: true, ..Default::default() }).collect();
        dev.set(&WgConfig { peers, ..Default::default() })
    }

    /// Peer runtime data keyed by base64 public key.
    pub fn stats(&self) -> HashMap<String, PeerStat> {
        let st = self.st.lock().unwrap();
        let mut out = HashMap::new();
        let Some(dev) = &st.dev else { return out };
        for p in dev.get().peers {
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

    pub fn sync_underlay(&self) {}

    /// The tunnel cannot outlive the process.
    pub fn release(&self) {
        self.down()
    }

    pub fn down(&self) {
        let mut st = self.st.lock().unwrap();
        st.dev = None; // stops WireGuard's threads
        if let Some(net) = st.net.take() {
            net.close();
        }
        *st = State::default();
    }
}

fn resolve4(ep: &str) -> Option<SocketAddr> {
    ep.to_socket_addrs().ok()?.find(|a| a.is_ipv4())
}

/// Nothing outlives meshgate here.
pub fn teardown(_iface: &str) {}

/// Not supported: these nodes do not route into their LAN.
pub fn enable_forwarding() {}

pub fn destroy_interface(_name: &str) {}
