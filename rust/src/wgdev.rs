//! A portable userspace WireGuard device (the role wireguard-go plays for the
//! Go build): boringtun's protocol state per peer, one UDP socket, routing by
//! allowed IPs, endpoints learned from handshakes (roaming), timers. Used by
//! the phone apps, Windows, macOS and the phone simulator; packets come from
//! any [`Tun`] (an Android/iOS file descriptor, Wintun, utun, Linux TUN).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use boringtun::noise::{Packet, Tunn, TunnResult, handshake::parse_handshake_anon};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::netx::Prefix;
use crate::wg::types::{WgConfig, WgDevice, WgPeer};

/// Where packets go in and out of the tunnel.
pub trait Tun: Send + Sync + 'static {
    /// Reads one packet; Ok(0) when nothing arrived for a while (so the
    /// device can notice it is stopping).
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
    fn write(&self, packet: &[u8]) -> io::Result<()>;
}

/// Keeps a socket outside the VPN (see util::SockHook).
pub type Protect = crate::util::SockHook;

const MAX_PACKET: usize = 65536;

struct Peer {
    key: [u8; 32],
    idx: u32,
    tunn: Mutex<Tunn>,
    endpoint: Mutex<Option<SocketAddr>>,
    allowed: Mutex<Vec<(IpAddr, u8)>>,
    keepalive: u16,
}

#[derive(Default)]
struct Peers {
    by_key: HashMap<[u8; 32], Arc<Peer>>,
    by_idx: HashMap<u32, Arc<Peer>>,
    /// Allowed IPs, longest prefix first.
    routes: Vec<(Prefix, Arc<Peer>)>,
    next_idx: u32,
}

impl Peers {
    fn rebuild_routes(&mut self) {
        let mut r = vec![];
        for p in self.by_key.values() {
            for (ip, bits) in p.allowed.lock().unwrap().iter() {
                r.push((Prefix::new(*ip, *bits), p.clone()));
            }
        }
        r.sort_by_key(|(pf, _)| std::cmp::Reverse(pf.bits));
        self.routes = r;
    }

    fn route(&self, dst: IpAddr) -> Option<Arc<Peer>> {
        self.routes.iter().find(|(pf, _)| pf.contains(dst)).map(|(_, p)| p.clone())
    }
}

struct Inner {
    secret: RwLock<StaticSecret>,
    public: RwLock<PublicKey>,
    peers: RwLock<Peers>,
    sock: RwLock<Option<Arc<UdpSocket>>>,
    listen_port: Mutex<u16>,
    fwmark: Mutex<u32>,
    tun: Arc<dyn Tun>,
    protect: Option<Protect>,
    stop: AtomicBool,
}

/// A running device; dropping it stops its threads.
pub struct Device {
    inner: Arc<Inner>,
    threads: Vec<JoinHandle<()>>,
}

fn now_unix() -> (i64, i64) {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (d.as_secs() as i64, d.subsec_nanos() as i64)
}

impl Device {
    pub fn new(tun: Arc<dyn Tun>, protect: Option<Protect>) -> io::Result<Device> {
        let secret = StaticSecret::from(crate::wg::generate_private_key());
        let inner = Arc::new(Inner {
            public: RwLock::new(PublicKey::from(&secret)),
            secret: RwLock::new(secret),
            peers: RwLock::new(Peers::default()),
            sock: RwLock::new(None),
            listen_port: Mutex::new(0),
            fwmark: Mutex::new(0),
            tun,
            protect,
            stop: AtomicBool::new(false),
        });
        inner.bind(0)?;
        let mut threads = vec![];
        for f in [Inner::tun_loop as fn(&Arc<Inner>), Inner::udp_loop, Inner::timer_loop] {
            let i = inner.clone();
            threads.push(std::thread::Builder::new().name("wgdev".into()).spawn(move || f(&i))?);
        }
        Ok(Device { inner, threads })
    }

    /// Applies a configuration (same meaning as the kernel's netlink set).
    pub fn set(&self, cfg: &WgConfig) -> Result<(), String> {
        let i = &self.inner;
        if let Some(k) = cfg.private_key {
            let s = StaticSecret::from(k);
            let p = PublicKey::from(&s);
            let changed = *i.public.read().unwrap() != p;
            *i.secret.write().unwrap() = s.clone();
            *i.public.write().unwrap() = p;
            if changed {
                for peer in i.peers.read().unwrap().by_key.values() {
                    peer.tunn.lock().unwrap().set_static_private(s.clone(), p, None);
                }
            }
        }
        if let Some(f) = cfg.fwmark {
            *i.fwmark.lock().unwrap() = f;
        }
        if let Some(port) = cfg.listen_port
            && *i.listen_port.lock().unwrap() != port
        {
            i.bind(port).map_err(|e| format!("listen udp :{port}: {e}"))?;
        }
        let mut peers = i.peers.write().unwrap();
        for pc in &cfg.peers {
            if pc.remove {
                if let Some(p) = peers.by_key.remove(&pc.public_key) {
                    peers.by_idx.remove(&p.idx);
                }
                continue;
            }
            let keepalive = pc.keepalive.unwrap_or_else(|| peers.by_key.get(&pc.public_key).map(|p| p.keepalive).unwrap_or(0));
            let existing = peers.by_key.get(&pc.public_key).cloned();
            let peer = match existing {
                Some(p) if p.keepalive == keepalive => p,
                old => {
                    // New peer, or a new keepalive (boringtun cannot change it
                    // in place): a fresh session.
                    peers.next_idx = (peers.next_idx + 1) & 0x00ff_ffff;
                    let idx = peers.next_idx;
                    let tunn = Tunn::new(
                        i.secret.read().unwrap().clone(),
                        PublicKey::from(pc.public_key),
                        None,
                        (keepalive > 0).then_some(keepalive),
                        idx,
                        None,
                    );
                    let p = Arc::new(Peer {
                        key: pc.public_key,
                        idx,
                        tunn: Mutex::new(tunn),
                        endpoint: Mutex::new(old.as_ref().and_then(|o| *o.endpoint.lock().unwrap())),
                        allowed: Mutex::new(old.as_ref().map(|o| o.allowed.lock().unwrap().clone()).unwrap_or_default()),
                        keepalive,
                    });
                    if let Some(o) = old {
                        peers.by_idx.remove(&o.idx);
                    }
                    peers.by_idx.insert(idx, p.clone());
                    peers.by_key.insert(pc.public_key, p.clone());
                    p
                }
            };
            if let Some(ep) = pc.endpoint {
                *peer.endpoint.lock().unwrap() = Some(ep);
            }
            let mut a = peer.allowed.lock().unwrap();
            if pc.replace_allowed_ips {
                a.clear();
            }
            for x in &pc.allowed_ips {
                if !a.contains(x) {
                    a.push(*x);
                }
            }
        }
        peers.rebuild_routes();
        Ok(())
    }

    /// The device and its peers (like the kernel's netlink get).
    pub fn get(&self) -> WgDevice {
        let i = &self.inner;
        let now = now_unix();
        let mut d = WgDevice {
            public_key: *i.public.read().unwrap().as_bytes(),
            listen_port: *i.listen_port.lock().unwrap(),
            fwmark: *i.fwmark.lock().unwrap(),
            peers: vec![],
        };
        let peers = i.peers.read().unwrap();
        let mut list: Vec<&Arc<Peer>> = peers.by_key.values().collect();
        list.sort_by_key(|p| p.idx);
        for p in list {
            let t = p.tunn.lock().unwrap();
            let (since, tx, rx, ..) = t.stats();
            let last_handshake = match since {
                Some(s) => {
                    let ns = now.0 as i128 * 1_000_000_000 + now.1 as i128 - s.as_nanos() as i128;
                    ((ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as i64)
                }
                None => (0, 0),
            };
            d.peers.push(WgPeer {
                public_key: p.key,
                endpoint: *p.endpoint.lock().unwrap(),
                last_handshake,
                rx_bytes: rx as u64,
                tx_bytes: tx as u64,
                keepalive: p.keepalive,
                allowed_ips: p.allowed.lock().unwrap().clone(),
            });
        }
        d
    }

    /// The UDP port actually in use.
    pub fn port(&self) -> u16 {
        self.inner.sock.read().unwrap().as_ref().and_then(|s| s.local_addr().ok()).map(|a| a.port()).unwrap_or(0)
    }

    /// Drops every session and makes peers handshake again (after the
    /// network changed).
    pub fn rehandshake(&self) {
        let i = &self.inner;
        let peers = i.peers.read().unwrap();
        let mut buf = vec![0u8; MAX_PACKET];
        for p in peers.by_key.values() {
            let ep = *p.endpoint.lock().unwrap();
            let mut t = p.tunn.lock().unwrap();
            if let TunnResult::WriteToNetwork(pkt) = t.format_handshake_initiation(&mut buf, true)
                && let Some(ep) = ep
            {
                i.send(pkt, ep);
            }
        }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

impl Inner {
    fn bind(&self, port: u16) -> io::Result<()> {
        let s = UdpSocket::bind(("0.0.0.0", port))?;
        s.set_read_timeout(Some(Duration::from_millis(250)))?;
        if let Some(p) = &self.protect {
            p(&socket2::SockRef::from(&s))?;
        }
        #[cfg(target_os = "linux")]
        {
            let mark = *self.fwmark.lock().unwrap();
            if mark != 0 {
                let _ = socket2::SockRef::from(&s).set_mark(mark);
            }
        }
        *self.listen_port.lock().unwrap() = s.local_addr()?.port();
        *self.sock.write().unwrap() = Some(Arc::new(s));
        Ok(())
    }

    fn send(&self, pkt: &[u8], to: SocketAddr) {
        if let Some(s) = self.sock.read().unwrap().clone() {
            let _ = s.send_to(pkt, to);
        }
    }

    /// Packets from the tunnel interface to peers.
    fn tun_loop(self: &Arc<Self>) {
        let mut buf = vec![0u8; MAX_PACKET];
        let mut out = vec![0u8; MAX_PACKET + 32];
        while !self.stop.load(Ordering::Relaxed) {
            let n = match self.tun.read(&mut buf) {
                Ok(0) => continue,
                Ok(n) => n,
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
            };
            let Some(dst) = Tunn::dst_address(&buf[..n]) else { continue };
            let Some(peer) = self.peers.read().unwrap().route(dst) else { continue };
            let ep = *peer.endpoint.lock().unwrap();
            let r = peer.tunn.lock().unwrap().encapsulate(&buf[..n], &mut out);
            if let (TunnResult::WriteToNetwork(pkt), Some(ep)) = (r, ep) {
                self.send(pkt, ep);
            }
        }
    }

    /// Packets from the network to the tunnel interface.
    fn udp_loop(self: &Arc<Self>) {
        let mut buf = vec![0u8; MAX_PACKET];
        let mut out = vec![0u8; MAX_PACKET];
        while !self.stop.load(Ordering::Relaxed) {
            let Some(sock) = self.sock.read().unwrap().clone() else {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            };
            let (n, from) = match sock.recv_from(&mut buf) {
                Ok(x) => x,
                Err(_) => continue,
            };
            let Some(peer) = self.peer_for(&buf[..n]) else { continue };
            let mut t = peer.tunn.lock().unwrap();
            let mut first = true;
            loop {
                let input: &[u8] = if first { &buf[..n] } else { &[] };
                first = false;
                match t.decapsulate(Some(from.ip()), input, &mut out) {
                    TunnResult::WriteToNetwork(pkt) => {
                        let _ = sock.send_to(pkt, from);
                        continue; // flush queued packets
                    }
                    TunnResult::WriteToTunnelV4(pkt, src) => self.deliver(&peer, pkt, IpAddr::V4(src), from),
                    TunnResult::WriteToTunnelV6(pkt, src) => self.deliver(&peer, pkt, IpAddr::V6(src), from),
                    TunnResult::Done => {
                        if input.is_empty() {
                            // A handshake or keepalive from this address: it is
                            // where the peer is now.
                        }
                        *peer.endpoint.lock().unwrap() = Some(from);
                    }
                    TunnResult::Err(_) => {}
                }
                break;
            }
        }
    }

    fn deliver(&self, peer: &Arc<Peer>, pkt: &[u8], src: IpAddr, from: SocketAddr) {
        *peer.endpoint.lock().unwrap() = Some(from); // roaming
        if pkt.is_empty() {
            return; // keepalive
        }
        let allowed = peer.allowed.lock().unwrap().iter().any(|(ip, bits)| Prefix::new(*ip, *bits).contains(src));
        if allowed {
            let _ = self.tun.write(pkt);
        }
    }

    /// The peer a datagram belongs to.
    fn peer_for(&self, d: &[u8]) -> Option<Arc<Peer>> {
        let peers = self.peers.read().unwrap();
        match Tunn::parse_incoming_packet(d).ok()? {
            Packet::HandshakeInit(h) => {
                let hs = parse_handshake_anon(&self.secret.read().unwrap(), &self.public.read().unwrap(), &h).ok()?;
                peers.by_key.get(&hs.peer_static_public).cloned()
            }
            Packet::HandshakeResponse(p) => peers.by_idx.get(&(p.receiver_idx >> 8)).cloned(),
            Packet::PacketCookieReply(p) => peers.by_idx.get(&(p.receiver_idx >> 8)).cloned(),
            Packet::PacketData(p) => peers.by_idx.get(&(p.receiver_idx >> 8)).cloned(),
        }
    }

    /// Handshake retries, rekeys and keepalives.
    fn timer_loop(self: &Arc<Self>) {
        let mut out = vec![0u8; MAX_PACKET];
        while !self.stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(250));
            let list: Vec<Arc<Peer>> = self.peers.read().unwrap().by_key.values().cloned().collect();
            for p in list {
                let ep = *p.endpoint.lock().unwrap();
                let r = p.tunn.lock().unwrap().update_timers(&mut out);
                if let (TunnResult::WriteToNetwork(pkt), Some(ep)) = (r, ep) {
                    self.send(pkt, ep);
                }
            }
        }
    }
}

/// A TUN file descriptor (Android VpnService, iOS utun, Linux /dev/net/tun).
/// `af_header`: utun packets start with a 4-byte address family.
#[cfg(unix)]
pub struct FdTun {
    fd: std::os::fd::RawFd,
    af_header: bool,
    owned: bool,
}

#[cfg(unix)]
impl FdTun {
    /// Uses fd without closing it when dropped (the app owns it).
    pub fn borrowed(fd: i32, af_header: bool) -> FdTun {
        FdTun { fd, af_header, owned: false }
    }

    /// Takes over fd: it is closed when the FdTun is dropped.
    pub fn owned(fd: i32, af_header: bool) -> FdTun {
        FdTun { fd, af_header, owned: true }
    }

    /// Opens a Linux TUN interface named `name` (raw IP packets).
    #[cfg(target_os = "linux")]
    pub fn open_linux(name: &str) -> io::Result<FdTun> {
        // SAFETY: open + TUNSETIFF ioctl with a zeroed ifreq holding the name.
        unsafe {
            let fd = libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut ifr: libc::ifreq = std::mem::zeroed();
            for (i, b) in name.bytes().take(15).enumerate() {
                ifr.ifr_name[i] = b as libc::c_char;
            }
            ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
            if libc::ioctl(fd, libc::TUNSETIFF as _, &ifr) < 0 {
                let e = io::Error::last_os_error();
                libc::close(fd);
                return Err(e);
            }
            Ok(FdTun { fd, af_header: false, owned: true })
        }
    }
}

#[cfg(unix)]
impl std::os::fd::IntoRawFd for FdTun {
    fn into_raw_fd(mut self) -> std::os::fd::RawFd {
        self.owned = false;
        self.fd
    }
}

#[cfg(unix)]
impl Drop for FdTun {
    fn drop(&mut self) {
        if self.owned {
            // SAFETY: we opened this descriptor.
            unsafe { libc::close(self.fd) };
        }
    }
}

#[cfg(unix)]
impl Tun for FdTun {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut pfd = libc::pollfd { fd: self.fd, events: libc::POLLIN, revents: 0 };
        // SAFETY: polling and reading our descriptor into our buffer.
        unsafe {
            let r = libc::poll(&mut pfd, 1, 250);
            if r < 0 {
                return Err(io::Error::last_os_error());
            }
            if r == 0 {
                return Ok(0);
            }
            if self.af_header {
                let mut tmp = vec![0u8; buf.len() + 4];
                let n = libc::read(self.fd, tmp.as_mut_ptr() as *mut libc::c_void, tmp.len());
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                let n = (n as usize).saturating_sub(4);
                buf[..n].copy_from_slice(&tmp[4..4 + n]);
                return Ok(n);
            }
            let n = libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
            if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
        }
    }

    fn write(&self, packet: &[u8]) -> io::Result<()> {
        let mut data = packet.to_vec();
        if self.af_header {
            let af: u32 = if packet.first().map(|b| b >> 4) == Some(6) { libc::AF_INET6 as u32 } else { libc::AF_INET as u32 };
            let mut v = af.to_be_bytes().to_vec();
            v.extend_from_slice(packet);
            data = v;
        }
        // SAFETY: writing our buffer to our descriptor.
        let n = unsafe { libc::write(self.fd, data.as_ptr() as *const libc::c_void, data.len()) };
        if n < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }
}

/// In-memory packets, for tests.
#[cfg(test)]
pub struct ChanTun {
    pub rx: Mutex<std::sync::mpsc::Receiver<Vec<u8>>>,
    pub tx: std::sync::mpsc::Sender<Vec<u8>>,
}

#[cfg(test)]
impl Tun for ChanTun {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self.rx.lock().unwrap().recv_timeout(Duration::from_millis(100)) {
            Ok(p) => {
                buf[..p.len()].copy_from_slice(&p);
                Ok(p.len())
            }
            Err(_) => Ok(0),
        }
    }
    fn write(&self, packet: &[u8]) -> io::Result<()> {
        let _ = self.tx.send(packet.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wg::types::WgPeerConfig;
    use std::sync::mpsc::channel;

    /// An IPv4/UDP packet from src to dst carrying payload.
    fn ipv4(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let len = 20 + 8 + payload.len();
        let mut p = vec![0x45, 0, (len >> 8) as u8, len as u8, 0, 0, 0x40, 0, 64, 17, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        let mut sum = 0u32;
        for c in p.chunks(2) {
            sum += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let ck = !(sum as u16);
        p[10..12].copy_from_slice(&ck.to_be_bytes());
        p.extend_from_slice(&[0x30, 0x39, 0x30, 0x39, 0, (8 + payload.len()) as u8, 0, 0]);
        p.extend_from_slice(payload);
        p
    }

    struct Side {
        dev: Device,
        to_tun: std::sync::mpsc::Sender<Vec<u8>>,
        from_tun: std::sync::mpsc::Receiver<Vec<u8>>,
        key: [u8; 32],
    }

    fn side() -> Side {
        let (a_tx, a_rx) = channel();
        let (b_tx, b_rx) = channel();
        let tun = Arc::new(ChanTun { rx: Mutex::new(a_rx), tx: b_tx });
        let dev = Device::new(tun, None).unwrap();
        let key = crate::wg::generate_private_key();
        dev.set(&WgConfig { private_key: Some(key), listen_port: Some(0), ..Default::default() }).unwrap();
        Side { dev, to_tun: a_tx, from_tun: b_rx, key }
    }

    fn peer(of: &Side, ep: Option<SocketAddr>, allowed: &str, keepalive: u16) -> WgPeerConfig {
        let p = crate::netx::parse_prefix(allowed).unwrap();
        WgPeerConfig {
            public_key: crate::wg::public_key(&of.key),
            replace_allowed_ips: true,
            endpoint: ep,
            keepalive: Some(keepalive),
            allowed_ips: vec![(p.addr, p.bits)],
            ..Default::default()
        }
    }

    #[test]
    fn two_devices_exchange_packets_and_roam() {
        let a = side();
        let b = side();
        let b_ep: SocketAddr = format!("127.0.0.1:{}", b.dev.port()).parse().unwrap();
        // a knows where b is; b learns a's address from the handshake.
        a.dev.set(&WgConfig { peers: vec![peer(&b, Some(b_ep), "100.88.0.2/32", 0)], ..Default::default() }).unwrap();
        b.dev.set(&WgConfig { peers: vec![peer(&a, None, "100.88.0.1/32", 0)], ..Default::default() }).unwrap();

        let ping = ipv4([100, 88, 0, 1], [100, 88, 0, 2], b"hello");
        a.to_tun.send(ping.clone()).unwrap();
        let got = b.from_tun.recv_timeout(Duration::from_secs(5)).expect("b received the packet");
        assert_eq!(got, ping);

        // The reply goes back to the endpoint b learned.
        let pong = ipv4([100, 88, 0, 2], [100, 88, 0, 1], b"world");
        b.to_tun.send(pong.clone()).unwrap();
        assert_eq!(a.from_tun.recv_timeout(Duration::from_secs(5)).expect("a received the reply"), pong);

        let st = b.dev.get();
        assert_eq!(st.peers.len(), 1);
        assert!(st.peers[0].last_handshake.0 > 0 && st.peers[0].rx_bytes > 0);
        assert_eq!(st.peers[0].endpoint.unwrap().ip().to_string(), "127.0.0.1");

        // Spoofed source outside the allowed IPs is dropped.
        a.to_tun.send(ipv4([10, 9, 9, 9], [100, 88, 0, 2], b"spoof")).unwrap();
        assert!(b.from_tun.recv_timeout(Duration::from_millis(500)).is_err());

        // Removing the peer stops traffic.
        b.dev
            .set(&WgConfig {
                peers: vec![WgPeerConfig { public_key: crate::wg::public_key(&a.key), remove: true, ..Default::default() }],
                ..Default::default()
            })
            .unwrap();
        assert!(b.dev.get().peers.is_empty());
    }
}
