//! Measures which WireGuard endpoints are reachable and how fast (Go:
//! internal/probe). Every node answers probes on UDP (WireGuard port + 2)
//! and probes every candidate endpoint of every peer. The packet format is
//! shared with Go nodes and the phone app:
//!
//!   "MGP1" | type (1 req, 2 resp) | nonce u64 BE | len | sender | len | target
//!
//! In a response the second string is the responder's boot ID.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Notify;

use crate::netx::Prefix;
use crate::pathsel;
use crate::util::mono_ns;

/// Added to a WireGuard port to get the probe port.
pub const OFFSET: i64 = 2;
/// Between probe rounds.
pub const INTERVAL: Duration = Duration::from_secs(3);

const MAGIC: &[u8; 4] = b"MGP1";
const TYPE_REQ: u8 = 1;
const TYPE_RESP: u8 = 2;

/// Tags sockets (Linux SO_MARK) so probes never travel inside the tunnel
/// they are testing.
pub type Control = crate::util::SockHook;

struct Pending {
    endpoint: String,
    sent: i64,
}

#[derive(Default)]
struct State {
    results: HashMap<String, pathsel::Probe>,
    inbound: HashMap<String, i64>,
    pending: HashMap<u64, Pending>,
    boot_id: String,
    boots: HashMap<String, String>,
    restarted: HashMap<String, bool>,
}

pub struct Prober {
    pub self_id: String,
    pub mesh: Prefix,
    pub control: Option<Control>,
    st: Mutex<State>,
    kick: Notify,
}

/// One endpoint to probe.
#[derive(Clone, Debug)]
pub struct Target {
    pub node_id: String,
    pub endpoint: String,
}

pub fn new_boot_id() -> String {
    hex::encode(crate::util::random_bytes::<6>())
}

impl Prober {
    pub fn new(self_id: &str, mesh: Prefix, control: Option<Control>) -> Arc<Prober> {
        Arc::new(Prober {
            self_id: self_id.into(),
            mesh,
            control,
            st: Mutex::new(State { boot_id: new_boot_id(), ..Default::default() }),
            kick: Notify::new(),
        })
    }

    /// Replaces the boot ID (a restart that keeps the tunnel keeps its ID).
    pub fn set_boot_id(&self, id: &str) {
        self.st.lock().unwrap().boot_id = id.into();
    }

    /// Peers that restarted since the last call.
    pub fn take_restarted(&self) -> Vec<String> {
        std::mem::take(&mut self.st.lock().unwrap().restarted).into_keys().collect()
    }

    /// Runs a probe round now.
    pub fn kick(&self) {
        self.kick.notify_one();
    }

    fn bind(&self, port: u16) -> std::io::Result<UdpSocket> {
        let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        if let Some(c) = &self.control {
            c(&s)?;
        }
        s.set_nonblocking(true)?;
        s.bind(&SocketAddr::from(([0, 0, 0, 0], port)).into())?;
        UdpSocket::from_std(s.into())
    }

    /// Answers probes on port forever. Returns early only if binding fails.
    pub async fn serve(self: Arc<Self>, port: u16) -> std::io::Result<()> {
        let c = self.bind(port)?;
        let mut buf = [0u8; 512];
        loop {
            let Ok((n, from)) = c.recv_from(&mut buf).await else { continue };
            let Some((typ, nonce, sender, target)) = parse(&buf[..n]) else { continue };
            if typ != TYPE_REQ || (!target.is_empty() && target != self.self_id) {
                continue;
            }
            // A probe that came through the tunnel says nothing about direct
            // reachability: drop it without answering.
            let IpAddr::V4(a) = from.ip() else { continue };
            if self.mesh.contains(IpAddr::V4(a)) {
                continue;
            }
            let boot = {
                let mut st = self.st.lock().unwrap();
                if !sender.is_empty() {
                    st.inbound.insert(sender, mono_ns());
                }
                st.boot_id.clone()
            };
            let _ = c.send_to(&encode(TYPE_RESP, nonce, &self.self_id, &boot), from).await;
        }
    }

    /// Probes targets() every INTERVAL (or on kick) forever.
    pub async fn run(self: Arc<Self>, targets: impl Fn() -> Vec<Target> + Send + 'static) -> std::io::Result<()> {
        let c = Arc::new(self.bind(0)?);
        let rd = c.clone();
        let me = self.clone();
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                if let Ok((n, _)) = rd.recv_from(&mut buf).await {
                    me.handle_response(&buf[..n], mono_ns());
                }
            }
        });
        struct Abort(tokio::task::JoinHandle<()>);
        impl Drop for Abort {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let _reader = Abort(reader);
        let mut t = tokio::time::interval(INTERVAL);
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        t.tick().await;
        loop {
            self.round(&c, targets()).await;
            tokio::select! {
                _ = t.tick() => {}
                _ = self.kick.notified() => {}
            }
        }
    }

    /// Sends one probe to each target.
    pub async fn round(&self, c: &UdpSocket, targets: Vec<Target>) {
        let now = mono_ns();
        self.st.lock().unwrap().pending.retain(|_, p| now - p.sent <= 5 * pathsel::SEC);
        for t in targets {
            let Some(addr) = probe_addr(&t.endpoint).await else { continue };
            let nonce = u64::from_be_bytes(crate::util::random_bytes::<8>());
            self.st.lock().unwrap().pending.insert(nonce, Pending { endpoint: t.endpoint.clone(), sent: mono_ns() });
            if let Err(e) = c.send_to(&encode(TYPE_REQ, nonce, &self.self_id, &t.node_id), addr).await {
                crate::logf!("probe {}: {e}", t.endpoint);
            }
        }
    }

    /// Records the RTT of a matching probe and notices restarts.
    fn handle_response(&self, b: &[u8], now: i64) {
        let Some((typ, nonce, responder, boot)) = parse(b) else { return };
        if typ != TYPE_RESP {
            return;
        }
        let mut st = self.st.lock().unwrap();
        let Some(pd) = st.pending.remove(&nonce) else { return }; // unsolicited or late
        st.results.insert(pd.endpoint, pathsel::Probe { last_ok: now, rtt: now - pd.sent });
        if !responder.is_empty() && !boot.is_empty() {
            if st.boots.get(&responder).is_some_and(|old| *old != boot) {
                st.restarted.insert(responder.clone(), true);
            }
            st.boots.insert(responder, boot);
        }
    }

    /// Copies of the current results and inbound times.
    pub fn snapshot(&self) -> (HashMap<String, pathsel::Probe>, HashMap<String, i64>) {
        let st = self.st.lock().unwrap();
        (st.results.clone(), st.inbound.clone())
    }

    /// Drops all results.
    pub fn forget(&self) {
        self.st.lock().unwrap().results.clear();
    }
}

/// Maps a WireGuard endpoint to its probe address (IPv4).
pub async fn probe_addr(endpoint: &str) -> Option<SocketAddr> {
    let (host, port) = crate::netx::split_host_port(endpoint).ok()?;
    let p = crate::gojson::atoi(&port)? + OFFSET;
    if !(0..65536).contains(&p) {
        return None;
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return Some(SocketAddr::from((ip, p as u16)));
    }
    tokio::net::lookup_host((host.as_str(), p as u16)).await.ok()?.find(|a| a.is_ipv4())
}

fn encode(typ: u8, nonce: u64, sender: &str, target: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(15 + sender.len() + target.len());
    b.extend_from_slice(MAGIC);
    b.push(typ);
    b.extend_from_slice(&nonce.to_be_bytes());
    b.push(sender.len() as u8);
    b.extend_from_slice(sender.as_bytes());
    b.push(target.len() as u8);
    b.extend_from_slice(target.as_bytes());
    b
}

fn parse(b: &[u8]) -> Option<(u8, u64, String, String)> {
    if b.len() < 15 || &b[..4] != MAGIC {
        return None;
    }
    let typ = b[4];
    let nonce = u64::from_be_bytes(b[5..13].try_into().ok()?);
    let rest = &b[13..];
    let ls = rest[0] as usize;
    if rest.len() < 1 + ls + 1 {
        return None;
    }
    let sender = String::from_utf8_lossy(&rest[1..1 + ls]).into_owned();
    let rest = &rest[1 + ls..];
    let lt = rest[0] as usize;
    if rest.len() < 1 + lt {
        return None;
    }
    let target = String::from_utf8_lossy(&rest[1..1 + lt]).into_owned();
    Some((typ, nonce, sender, target))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn free_udp() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    #[tokio::test]
    async fn probe_round_trip() {
        let mesh = crate::netx::parse_prefix("100.88.0.0/16").unwrap();
        let probe_port = free_udp();
        let server = Prober::new("home", mesh, None);
        tokio::spawn(server.clone().serve(probe_port));
        tokio::time::sleep(Duration::from_millis(50)).await;
        let client = Prober::new("phone", mesh, None);
        let ep = format!("127.0.0.1:{}", probe_port as i64 - OFFSET);
        let ep2 = ep.clone();
        tokio::spawn(client.clone().run(move || vec![Target { node_id: "home".into(), endpoint: ep2.clone() }]));
        for _ in 0..100 {
            let (res, _) = client.snapshot();
            let (_, inb) = server.snapshot();
            if res.get(&ep).is_some_and(|r| r.last_ok != 0) && inb.contains_key("phone") {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("probe did not complete");
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse(b"MGP1\x01short").is_none());
        let b = encode(TYPE_REQ, 42, "a", "bb");
        assert_eq!(parse(&b), Some((TYPE_REQ, 42, "a".into(), "bb".into())));
    }

    #[tokio::test]
    async fn mesh_sourced_probe_ignored() {
        let mesh = crate::netx::parse_prefix("127.0.0.0/8").unwrap();
        let probe_port = free_udp();
        let server = Prober::new("home", mesh, None);
        tokio::spawn(server.clone().serve(probe_port));
        tokio::time::sleep(Duration::from_millis(50)).await;
        let client = Prober::new("phone", mesh, None);
        let ep = format!("127.0.0.1:{}", probe_port as i64 - OFFSET);
        let ep2 = ep.clone();
        tokio::spawn(client.clone().run(move || vec![Target { node_id: "home".into(), endpoint: ep2.clone() }]));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!client.snapshot().0.contains_key(&ep), "server answered a probe from inside the mesh");
        assert!(!server.snapshot().1.contains_key("phone"), "mesh-sourced probe counted as inbound direct");
    }

    #[test]
    fn boot_id_change_detected() {
        let p = Prober::new("me", crate::netx::parse_prefix("100.88.0.0/16").unwrap(), None);
        let feed = |nonce: u64, boot: &str| {
            p.st.lock().unwrap().pending.insert(nonce, Pending { endpoint: "x:1".into(), sent: mono_ns() });
            p.handle_response(&encode(TYPE_RESP, nonce, "peer", boot), mono_ns());
        };
        feed(1, "a");
        feed(2, "a");
        assert!(p.take_restarted().is_empty(), "false restart");
        feed(3, "b");
        assert_eq!(p.take_restarted(), vec!["peer".to_string()]);
        p.handle_response(&encode(TYPE_RESP, 99, "peer", "c"), mono_ns());
        assert!(p.take_restarted().is_empty(), "unsolicited response counted");
    }
}
