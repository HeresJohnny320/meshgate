//! A small synchronous netlink client (Linux): links, addresses, routes,
//! policy rules and the kernel WireGuard family. Replaces Go's
//! vishvananda/netlink and wgctrl.

#![cfg(target_os = "linux")]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, Ordering};

const NETLINK_ROUTE: i32 = 0;
const NETLINK_GENERIC: i32 = 16;

pub const NLM_F_REQUEST: u16 = 1;
pub const NLM_F_ACK: u16 = 4;
pub const NLM_F_DUMP: u16 = 0x300;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
const NLA_F_NESTED: u16 = 0x8000;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;
const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;
const RTM_GETRULE: u16 = 34;

const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_PREFSRC: u16 = 7;
const RTA_MULTIPATH: u16 = 9;
const RTA_TABLE: u16 = 15;
const FRA_SRC: u16 = 2;
const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
const FRA_TABLE: u16 = 15;
const FRA_FWMASK: u16 = 16;

pub const RT_TABLE_UNSPEC: u32 = 0;
pub const RT_TABLE_MAIN: u32 = 254;
pub const RTN_UNICAST: u8 = 1;
pub const RTN_BLACKHOLE: u8 = 6;
pub const RTN_THROW: u8 = 9;
pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_LINK: u8 = 253;
pub const RTNH_F_ONLINK: u32 = 4;
pub const RTNH_F_LINKDOWN: u32 = 16;
const RTPROT_BOOT: u8 = 3;
const FR_ACT_TO_TBL: u8 = 1;
const FIB_RULE_INVERT: u32 = 2;

const IFF_UP: u32 = 1;
const IFF_LOOPBACK: u32 = 8;
const IFF_POINTOPOINT: u32 = 0x10;

static SEQ: AtomicU32 = AtomicU32::new(1);

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// A netlink message under construction.
pub struct Msg {
    buf: Vec<u8>,
    nests: Vec<usize>,
}

impl Msg {
    pub fn new(typ: u16, flags: u16) -> Msg {
        let mut buf = vec![0u8; 16];
        buf[4..6].copy_from_slice(&typ.to_ne_bytes());
        buf[6..8].copy_from_slice(&flags.to_ne_bytes());
        Msg { buf, nests: vec![] }
    }

    pub fn bytes(&mut self, b: &[u8]) -> &mut Msg {
        self.buf.extend_from_slice(b);
        self.buf.resize(align4(self.buf.len()), 0);
        self
    }

    pub fn attr(&mut self, typ: u16, data: &[u8]) -> &mut Msg {
        let len = 4 + data.len();
        self.buf.extend_from_slice(&(len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&typ.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.buf.resize(align4(self.buf.len()), 0);
        self
    }

    pub fn u8(&mut self, typ: u16, v: u8) -> &mut Msg {
        self.attr(typ, &[v])
    }
    pub fn u16(&mut self, typ: u16, v: u16) -> &mut Msg {
        self.attr(typ, &v.to_ne_bytes())
    }
    pub fn u32(&mut self, typ: u16, v: u32) -> &mut Msg {
        self.attr(typ, &v.to_ne_bytes())
    }
    pub fn str(&mut self, typ: u16, s: &str) -> &mut Msg {
        let mut b = s.as_bytes().to_vec();
        b.push(0);
        self.attr(typ, &b)
    }

    pub fn nest(&mut self, typ: u16) -> &mut Msg {
        self.nests.push(self.buf.len());
        self.attr(typ | NLA_F_NESTED, &[])
    }

    pub fn end(&mut self) -> &mut Msg {
        let start = self.nests.pop().expect("nest");
        let len = (self.buf.len() - start) as u16;
        self.buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
        self
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn finish(&mut self, seq: u32) -> &[u8] {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        &self.buf
    }
}

/// Iterates the attributes in `b`.
pub fn attrs(b: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    let mut b = b;
    std::iter::from_fn(move || {
        if b.len() < 4 {
            return None;
        }
        let len = u16::from_ne_bytes([b[0], b[1]]) as usize;
        let typ = u16::from_ne_bytes([b[2], b[3]]) & 0x3fff;
        if len < 4 || len > b.len() {
            return None;
        }
        let data = &b[4..len];
        b = &b[align4(len).min(b.len())..];
        Some((typ, data))
    })
}

fn ne_u16(b: &[u8]) -> u16 {
    b.get(..2).map(|x| u16::from_ne_bytes([x[0], x[1]])).unwrap_or(0)
}
fn ne_u32(b: &[u8]) -> u32 {
    b.get(..4).map(|x| u32::from_ne_bytes([x[0], x[1], x[2], x[3]])).unwrap_or(0)
}
fn ne_u64(b: &[u8]) -> u64 {
    b.get(..8).map(|x| u64::from_ne_bytes(x.try_into().unwrap())).unwrap_or(0)
}
fn ne_i64(b: &[u8]) -> i64 {
    ne_u64(b) as i64
}

fn ip_from(b: &[u8]) -> Option<IpAddr> {
    match b.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))),
        16 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(b).ok()?))),
        _ => None,
    }
}

fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

/// One netlink socket.
pub struct Socket {
    fd: OwnedFd,
}

impl Socket {
    pub fn new(proto: i32) -> io::Result<Socket> {
        // SAFETY: plain socket syscall.
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, proto) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a fresh descriptor we own.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: sa is a valid sockaddr_nl.
        if unsafe { libc::bind(fd.as_raw_fd(), &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_nl>() as u32) }
            < 0
        {
            return Err(io::Error::last_os_error());
        }
        let size: libc::c_int = 1 << 20;
        // SAFETY: setting a socket option on our descriptor.
        unsafe {
            libc::setsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF, &size as *const _ as *const libc::c_void, 4);
            let one: libc::c_int = 1;
            libc::setsockopt(fd.as_raw_fd(), libc::SOL_NETLINK, libc::NETLINK_EXT_ACK, &one as *const _ as *const libc::c_void, 4);
        }
        Ok(Socket { fd })
    }

    pub fn route() -> io::Result<Socket> {
        Socket::new(NETLINK_ROUTE)
    }

    /// Sends a request and collects reply payloads (each starting after the
    /// 16-byte header) until DONE or the ACK.
    pub fn request(&self, m: &mut Msg) -> io::Result<Vec<(u16, Vec<u8>)>> {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let flags = ne_u16(&m.buf[6..8]);
        let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
        if !dump {
            // Single requests end with an ACK, so we know when the reply is
            // complete (a GET otherwise sends just its answer).
            m.buf[6..8].copy_from_slice(&(flags | NLM_F_ACK).to_ne_bytes());
        }
        let b = m.finish(seq);
        // SAFETY: sending our buffer on our socket.
        let n = unsafe { libc::send(self.fd.as_raw_fd(), b.as_ptr() as *const libc::c_void, b.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut out = vec![];
        let mut buf = vec![0u8; 1 << 16];
        loop {
            // SAFETY: receiving into our buffer.
            let n = unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            let mut b = &buf[..n as usize];
            while b.len() >= 16 {
                let len = ne_u32(b) as usize;
                if len < 16 || len > b.len() {
                    break;
                }
                let typ = ne_u16(&b[4..]);
                let mseq = ne_u32(&b[8..]);
                let payload = &b[16..len];
                b = &b[align4(len).min(b.len())..];
                if mseq != seq {
                    continue;
                }
                match typ {
                    NLMSG_DONE => return Ok(out),
                    NLMSG_ERROR => {
                        let code = ne_u32(payload) as i32;
                        if code == 0 {
                            if !dump {
                                return Ok(out);
                            }
                            continue;
                        }
                        return Err(io::Error::from_raw_os_error(-code));
                    }
                    _ => out.push((typ, payload.to_vec())),
                }
            }
        }
    }
}

// ---------------------------------------------------------------- links

#[derive(Clone, Debug)]
pub struct Link {
    pub index: i32,
    pub name: String,
    pub flags: u32,
}

impl Link {
    pub fn up(&self) -> bool {
        self.flags & IFF_UP != 0
    }
    pub fn loopback(&self) -> bool {
        self.flags & IFF_LOOPBACK != 0
    }
    pub fn point_to_point(&self) -> bool {
        self.flags & IFF_POINTOPOINT != 0
    }
}

fn ifinfo(family: u8, index: i32, flags: u32, change: u32) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0] = family;
    b[4..8].copy_from_slice(&index.to_ne_bytes());
    b[8..12].copy_from_slice(&flags.to_ne_bytes());
    b[12..16].copy_from_slice(&change.to_ne_bytes());
    b
}

fn parse_link(p: &[u8]) -> Option<Link> {
    if p.len() < 16 {
        return None;
    }
    let index = ne_u32(&p[4..]) as i32;
    let flags = ne_u32(&p[8..]);
    let name = attrs(&p[16..]).find(|(t, _)| *t == IFLA_IFNAME).map(|(_, d)| cstr(d)).unwrap_or_default();
    Some(Link { index, name, flags })
}

fn cstr(d: &[u8]) -> String {
    String::from_utf8_lossy(d.split(|c| *c == 0).next().unwrap_or(d)).into_owned()
}

pub fn link_by_name(name: &str) -> io::Result<Link> {
    let s = Socket::route()?;
    let mut m = Msg::new(RTM_GETLINK, NLM_F_REQUEST);
    m.bytes(&ifinfo(0, 0, 0, 0)).str(IFLA_IFNAME, name);
    let r = s.request(&mut m)?;
    r.iter().find_map(|(_, p)| parse_link(p)).ok_or_else(|| io::Error::from_raw_os_error(libc::ENODEV))
}

pub fn link_by_index(index: i32) -> io::Result<Link> {
    let s = Socket::route()?;
    let mut m = Msg::new(RTM_GETLINK, NLM_F_REQUEST);
    m.bytes(&ifinfo(0, index, 0, 0));
    let r = s.request(&mut m)?;
    r.iter().find_map(|(_, p)| parse_link(p)).ok_or_else(|| io::Error::from_raw_os_error(libc::ENODEV))
}

pub fn link_list() -> io::Result<Vec<Link>> {
    let s = Socket::route()?;
    let mut m = Msg::new(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP);
    m.bytes(&ifinfo(0, 0, 0, 0));
    Ok(s.request(&mut m)?.iter().filter_map(|(_, p)| parse_link(p)).collect())
}

/// `ip link add <name> type <kind>`.
pub fn link_add(name: &str, kind: &str) -> io::Result<()> {
    let s = Socket::route()?;
    let mut m = Msg::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
    m.bytes(&ifinfo(0, 0, 0, 0)).str(IFLA_IFNAME, name).nest(IFLA_LINKINFO).str(IFLA_INFO_KIND, kind).end();
    s.request(&mut m).map(|_| ())
}

pub fn link_set_mtu(index: i32, mtu: u32) -> io::Result<()> {
    let s = Socket::route()?;
    let mut m = Msg::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
    m.bytes(&ifinfo(0, index, 0, 0)).u32(IFLA_MTU, mtu);
    s.request(&mut m).map(|_| ())
}

pub fn link_set_up(index: i32) -> io::Result<()> {
    let s = Socket::route()?;
    let mut m = Msg::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
    m.bytes(&ifinfo(0, index, IFF_UP, IFF_UP));
    s.request(&mut m).map(|_| ())
}

pub fn link_del(index: i32) -> io::Result<()> {
    let s = Socket::route()?;
    let mut m = Msg::new(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK);
    m.bytes(&ifinfo(0, index, 0, 0));
    s.request(&mut m).map(|_| ())
}

// ---------------------------------------------------------------- addresses

#[derive(Clone, Debug, PartialEq)]
pub struct Addr {
    pub ip: IpAddr,
    pub bits: u8,
    pub index: i32,
}

fn ifaddr(family: u8, bits: u8, index: i32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0] = family;
    b[1] = bits;
    b[4..8].copy_from_slice(&index.to_ne_bytes());
    b
}

/// IPv4 addresses of a link.
pub fn addr_list4(index: i32) -> io::Result<Vec<Addr>> {
    let s = Socket::route()?;
    let mut m = Msg::new(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP);
    m.bytes(&ifaddr(libc::AF_INET as u8, 0, 0));
    let mut out = vec![];
    for (_, p) in s.request(&mut m)? {
        if p.len() < 8 || ne_u32(&p[4..]) as i32 != index {
            continue;
        }
        let local = attrs(&p[8..]).find(|(t, _)| *t == IFA_LOCAL).or_else(|| attrs(&p[8..]).find(|(t, _)| *t == IFA_ADDRESS));
        if let Some(ip) = local.and_then(|(_, d)| ip_from(d)) {
            out.push(Addr { ip, bits: p[1], index });
        }
    }
    Ok(out)
}

fn addr_msg(typ: u16, flags: u16, a: &Addr) -> Msg {
    let fam = if a.ip.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 } as u8;
    let mut m = Msg::new(typ, flags);
    m.bytes(&ifaddr(fam, a.bits, a.index)).attr(IFA_LOCAL, &ip_bytes(a.ip)).attr(IFA_ADDRESS, &ip_bytes(a.ip));
    m
}

pub fn addr_del(a: &Addr) -> io::Result<()> {
    Socket::route()?.request(&mut addr_msg(RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK, a)).map(|_| ())
}

pub fn addr_replace(a: &Addr) -> io::Result<()> {
    Socket::route()?.request(&mut addr_msg(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE, a)).map(|_| ())
}

// ---------------------------------------------------------------- routes

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Nexthop {
    pub index: i32,
    pub gw: Option<IpAddr>,
    pub flags: u32,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Route {
    /// None = default route.
    pub dst: Option<(IpAddr, u8)>,
    pub gw: Option<IpAddr>,
    pub src: Option<IpAddr>,
    pub index: i32,
    pub table: u32,
    pub typ: u8,
    pub scope: u8,
    pub protocol: u8,
    pub priority: u32,
    pub flags: u32,
    pub multipath: Vec<Nexthop>,
}

impl Route {
    pub fn dst_key(&self) -> String {
        match self.dst {
            None => "0.0.0.0/0".into(),
            Some((ip, bits)) => crate::netx::Prefix::new(ip, bits).masked().to_string(),
        }
    }
}

fn parse_route(p: &[u8]) -> Option<Route> {
    if p.len() < 12 {
        return None;
    }
    let mut r = Route { table: p[4] as u32, protocol: p[5], scope: p[6], typ: p[7], flags: ne_u32(&p[8..]), ..Default::default() };
    let dst_len = p[1];
    for (t, d) in attrs(&p[12..]) {
        match t {
            RTA_DST => r.dst = ip_from(d).map(|ip| (ip, dst_len)),
            RTA_GATEWAY => r.gw = ip_from(d),
            RTA_OIF => r.index = ne_u32(d) as i32,
            RTA_PRIORITY => r.priority = ne_u32(d),
            RTA_PREFSRC => r.src = ip_from(d),
            RTA_TABLE => r.table = ne_u32(d),
            RTA_MULTIPATH => {
                let mut b = d;
                while b.len() >= 8 {
                    let len = ne_u16(b) as usize;
                    if len < 8 || len > b.len() {
                        break;
                    }
                    let mut h = Nexthop { flags: b[2] as u32, index: ne_u32(&b[4..]) as i32, gw: None };
                    for (t, d) in attrs(&b[8..len]) {
                        if t == RTA_GATEWAY {
                            h.gw = ip_from(d);
                        }
                    }
                    r.multipath.push(h);
                    b = &b[align4(len).min(b.len())..];
                }
            }
            _ => {}
        }
    }
    if dst_len == 0 {
        r.dst = None;
    }
    Some(r)
}

/// All IPv4 routes of every table.
pub fn route_list4() -> io::Result<Vec<Route>> {
    let s = Socket::route()?;
    let mut m = Msg::new(RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP);
    m.bytes(&[libc::AF_INET as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    Ok(s.request(&mut m)?.iter().filter_map(|(_, p)| parse_route(p)).collect())
}

fn route_msg(typ: u16, flags: u16, r: &Route) -> Msg {
    let mut m = Msg::new(typ, flags);
    let (dst_len, fam) = match r.dst {
        Some((ip, bits)) => (bits, if ip.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 }),
        None => (0, libc::AF_INET),
    };
    let table_u8 = if r.table < 256 { r.table as u8 } else { RT_TABLE_UNSPEC as u8 };
    let proto = if r.protocol == 0 { RTPROT_BOOT } else { r.protocol };
    let typ = if r.typ == 0 { RTN_UNICAST } else { r.typ };
    let mut hdr = [fam as u8, dst_len, 0, 0, table_u8, proto, r.scope, typ, 0, 0, 0, 0];
    hdr[8..12].copy_from_slice(&r.flags.to_ne_bytes());
    m.bytes(&hdr);
    m.u32(RTA_TABLE, r.table);
    if let Some((ip, _)) = r.dst {
        m.attr(RTA_DST, &ip_bytes(ip));
    }
    if let Some(gw) = r.gw {
        m.attr(RTA_GATEWAY, &ip_bytes(gw));
    }
    if let Some(src) = r.src {
        m.attr(RTA_PREFSRC, &ip_bytes(src));
    }
    if r.index != 0 {
        m.u32(RTA_OIF, r.index as u32);
    }
    if r.priority != 0 {
        m.u32(RTA_PRIORITY, r.priority);
    }
    if !r.multipath.is_empty() {
        let mut b = vec![];
        for h in &r.multipath {
            let mut nh = vec![0u8; 8];
            nh[2] = h.flags as u8;
            nh[4..8].copy_from_slice(&(h.index as u32).to_ne_bytes());
            if let Some(gw) = h.gw {
                let g = ip_bytes(gw);
                nh.extend_from_slice(&((4 + g.len()) as u16).to_ne_bytes());
                nh.extend_from_slice(&RTA_GATEWAY.to_ne_bytes());
                nh.extend_from_slice(&g);
            }
            let len = nh.len() as u16;
            nh[0..2].copy_from_slice(&len.to_ne_bytes());
            b.extend_from_slice(&nh);
            b.resize(align4(b.len()), 0);
        }
        m.attr(RTA_MULTIPATH, &b);
    }
    m
}

pub fn route_replace(r: &Route) -> io::Result<()> {
    Socket::route()?.request(&mut route_msg(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE, r)).map(|_| ())
}

pub fn route_del(r: &Route) -> io::Result<()> {
    Socket::route()?.request(&mut route_msg(RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, r)).map(|_| ())
}

// ---------------------------------------------------------------- rules

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Rule {
    pub priority: u32,
    pub table: u32,
    pub mark: u32,
    pub mask: Option<u32>,
    pub invert: bool,
    pub src: Option<(IpAddr, u8)>,
    /// -1 = not set.
    pub suppress_prefixlen: i32,
}

pub fn rule_list4() -> io::Result<Vec<Rule>> {
    let s = Socket::route()?;
    let mut m = Msg::new(RTM_GETRULE, NLM_F_REQUEST | NLM_F_DUMP);
    m.bytes(&[libc::AF_INET as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let mut out = vec![];
    for (_, p) in s.request(&mut m)? {
        if p.len() < 12 {
            continue;
        }
        let mut r =
            Rule { table: p[4] as u32, invert: ne_u32(&p[8..]) & FIB_RULE_INVERT != 0, suppress_prefixlen: -1, ..Default::default() };
        let src_len = p[2];
        for (t, d) in attrs(&p[12..]) {
            match t {
                FRA_PRIORITY => r.priority = ne_u32(d),
                FRA_TABLE => r.table = ne_u32(d),
                FRA_FWMARK => r.mark = ne_u32(d),
                FRA_FWMASK => r.mask = Some(ne_u32(d)),
                FRA_SRC => r.src = ip_from(d).map(|ip| (ip, src_len)),
                FRA_SUPPRESS_PREFIXLEN => r.suppress_prefixlen = ne_u32(d) as i32,
                _ => {}
            }
        }
        out.push(r);
    }
    Ok(out)
}

fn rule_msg(typ: u16, flags: u16, r: &Rule) -> Msg {
    let mut m = Msg::new(typ, flags);
    let src_len = r.src.map(|s| s.1).unwrap_or(0);
    let table_u8 = if r.table < 256 { r.table as u8 } else { RT_TABLE_UNSPEC as u8 };
    let mut hdr = [libc::AF_INET as u8, 0, src_len, 0, table_u8, 0, 0, FR_ACT_TO_TBL, 0, 0, 0, 0];
    if r.invert {
        hdr[8..12].copy_from_slice(&FIB_RULE_INVERT.to_ne_bytes());
    }
    m.bytes(&hdr);
    m.u32(FRA_PRIORITY, r.priority);
    m.u32(FRA_TABLE, r.table);
    if r.mark != 0 || r.mask.is_some() {
        m.u32(FRA_FWMARK, r.mark);
    }
    if let Some(mask) = r.mask {
        m.u32(FRA_FWMASK, mask);
    }
    if let Some((ip, _)) = r.src {
        m.attr(FRA_SRC, &ip_bytes(ip));
    }
    if r.suppress_prefixlen >= 0 {
        m.u32(FRA_SUPPRESS_PREFIXLEN, r.suppress_prefixlen as u32);
    }
    m
}

pub fn rule_add(r: &Rule) -> io::Result<()> {
    Socket::route()?.request(&mut rule_msg(RTM_NEWRULE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, r)).map(|_| ())
}

pub fn rule_del(r: &Rule) -> io::Result<()> {
    Socket::route()?.request(&mut rule_msg(RTM_DELRULE, NLM_F_REQUEST | NLM_F_ACK, r)).map(|_| ())
}

// ---------------------------------------------------------------- wireguard

const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const WG_CMD_GET_DEVICE: u8 = 0;
const WG_CMD_SET_DEVICE: u8 = 1;
const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
const WGDEVICE_A_PUBLIC_KEY: u16 = 4;
const WGDEVICE_A_LISTEN_PORT: u16 = 6;
const WGDEVICE_A_FWMARK: u16 = 7;
const WGDEVICE_A_PEERS: u16 = 8;
const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_FLAGS: u16 = 3;
const WGPEER_A_ENDPOINT: u16 = 4;
const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
const WGPEER_A_LAST_HANDSHAKE_TIME: u16 = 6;
const WGPEER_A_RX_BYTES: u16 = 7;
const WGPEER_A_TX_BYTES: u16 = 8;
const WGPEER_A_ALLOWEDIPS: u16 = 9;
const WGPEER_F_REMOVE_ME: u32 = 1;
const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 2;
const WGALLOWEDIP_A_FAMILY: u16 = 1;
const WGALLOWEDIP_A_IPADDR: u16 = 2;
const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;

pub use crate::wg::types::*;

fn genl_family(name: &str) -> io::Result<u16> {
    let s = Socket::new(NETLINK_GENERIC)?;
    let mut m = Msg::new(GENL_ID_CTRL, NLM_F_REQUEST);
    m.bytes(&[CTRL_CMD_GETFAMILY, 1, 0, 0]).str(CTRL_ATTR_FAMILY_NAME, name);
    for (_, p) in s.request(&mut m)? {
        if let Some((_, d)) = attrs(&p[4..]).find(|(t, _)| *t == CTRL_ATTR_FAMILY_ID) {
            return Ok(ne_u16(d));
        }
    }
    Err(io::Error::from_raw_os_error(libc::ENOENT))
}

fn sockaddr(b: &[u8]) -> Option<SocketAddr> {
    let fam = ne_u16(b) as i32;
    if fam == libc::AF_INET && b.len() >= 8 {
        let port = u16::from_be_bytes([b[2], b[3]]);
        return Some(SocketAddr::from((Ipv4Addr::new(b[4], b[5], b[6], b[7]), port)));
    }
    if fam == libc::AF_INET6 && b.len() >= 24 {
        let port = u16::from_be_bytes([b[2], b[3]]);
        let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).ok()?);
        return Some(SocketAddr::from((ip, port)));
    }
    None
}

fn sockaddr_bytes(a: &SocketAddr) -> Vec<u8> {
    match a {
        SocketAddr::V4(v) => {
            let mut b = vec![0u8; 16];
            b[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            b[2..4].copy_from_slice(&v.port().to_be_bytes());
            b[4..8].copy_from_slice(&v.ip().octets());
            b
        }
        SocketAddr::V6(v) => {
            let mut b = vec![0u8; 28];
            b[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            b[2..4].copy_from_slice(&v.port().to_be_bytes());
            b[8..24].copy_from_slice(&v.ip().octets());
            b
        }
    }
}

fn key32(d: &[u8]) -> [u8; 32] {
    <[u8; 32]>::try_from(d).unwrap_or([0; 32])
}

/// Reads a kernel WireGuard device.
pub fn wg_get(ifname: &str) -> io::Result<WgDevice> {
    let fam = genl_family("wireguard")?;
    let s = Socket::new(NETLINK_GENERIC)?;
    let mut m = Msg::new(fam, NLM_F_REQUEST | NLM_F_DUMP);
    m.bytes(&[WG_CMD_GET_DEVICE, 1, 0, 0]).str(WGDEVICE_A_IFNAME, ifname);
    let mut dev = WgDevice::default();
    for (_, p) in s.request(&mut m)? {
        for (t, d) in attrs(&p[4..]) {
            match t {
                WGDEVICE_A_PUBLIC_KEY => dev.public_key = key32(d),
                WGDEVICE_A_LISTEN_PORT => dev.listen_port = ne_u16(d),
                WGDEVICE_A_FWMARK => dev.fwmark = ne_u32(d),
                WGDEVICE_A_PEERS => {
                    for (_, pd) in attrs(d) {
                        let mut peer = WgPeer::default();
                        for (t, d) in attrs(pd) {
                            match t {
                                WGPEER_A_PUBLIC_KEY => peer.public_key = key32(d),
                                WGPEER_A_ENDPOINT => peer.endpoint = sockaddr(d),
                                WGPEER_A_LAST_HANDSHAKE_TIME if d.len() >= 16 => peer.last_handshake = (ne_i64(d), ne_i64(&d[8..])),
                                WGPEER_A_RX_BYTES => peer.rx_bytes = ne_u64(d),
                                WGPEER_A_TX_BYTES => peer.tx_bytes = ne_u64(d),
                                WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL => peer.keepalive = ne_u16(d),
                                WGPEER_A_ALLOWEDIPS => {
                                    for (_, ad) in attrs(d) {
                                        let (mut ip, mut bits) = (None, 0u8);
                                        for (t, d) in attrs(ad) {
                                            match t {
                                                WGALLOWEDIP_A_IPADDR => ip = ip_from(d),
                                                WGALLOWEDIP_A_CIDR_MASK => bits = d.first().copied().unwrap_or(0),
                                                _ => {}
                                            }
                                        }
                                        if let Some(ip) = ip {
                                            peer.allowed_ips.push((ip, bits));
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        // A peer with many allowed IPs spans several messages.
                        match dev.peers.last_mut() {
                            Some(last) if last.public_key == peer.public_key => last.allowed_ips.extend(peer.allowed_ips),
                            _ => dev.peers.push(peer),
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(dev)
}

/// Configures a kernel WireGuard device, splitting large peer lists across
/// several messages.
pub fn wg_set(ifname: &str, cfg: &WgConfig) -> io::Result<()> {
    let fam = genl_family("wireguard")?;
    let s = Socket::new(NETLINK_GENERIC)?;
    let new_msg = |first: bool| {
        let mut m = Msg::new(fam, NLM_F_REQUEST | NLM_F_ACK);
        m.bytes(&[WG_CMD_SET_DEVICE, 1, 0, 0]).str(WGDEVICE_A_IFNAME, ifname);
        if first {
            if let Some(k) = cfg.private_key {
                m.attr(WGDEVICE_A_PRIVATE_KEY, &k);
            }
            if let Some(p) = cfg.listen_port {
                m.u16(WGDEVICE_A_LISTEN_PORT, p);
            }
            if let Some(f) = cfg.fwmark {
                m.u32(WGDEVICE_A_FWMARK, f);
            }
        }
        m
    };
    const BUDGET: usize = 16 << 10;
    let mut m = new_msg(true);
    let mut open = false;
    let mut idx = 0u16;
    for p in &cfg.peers {
        if open && m.len() > BUDGET {
            m.end();
            s.request(&mut m)?;
            m = new_msg(false);
            open = false;
        }
        if !open {
            m.nest(WGDEVICE_A_PEERS);
            open = true;
        }
        m.nest(idx);
        idx = idx.wrapping_add(1);
        m.attr(WGPEER_A_PUBLIC_KEY, &p.public_key);
        let mut flags = 0;
        if p.remove {
            flags |= WGPEER_F_REMOVE_ME;
        }
        if p.replace_allowed_ips {
            flags |= WGPEER_F_REPLACE_ALLOWEDIPS;
        }
        m.u32(WGPEER_A_FLAGS, flags);
        if !p.remove {
            if let Some(ep) = &p.endpoint {
                m.attr(WGPEER_A_ENDPOINT, &sockaddr_bytes(ep));
            }
            if let Some(k) = p.keepalive {
                m.u16(WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, k);
            }
            m.nest(WGPEER_A_ALLOWEDIPS);
            for (i, (ip, bits)) in p.allowed_ips.iter().enumerate() {
                m.nest(i as u16);
                m.u16(WGALLOWEDIP_A_FAMILY, if ip.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 } as u16);
                m.attr(WGALLOWEDIP_A_IPADDR, &ip_bytes(*ip));
                m.u8(WGALLOWEDIP_A_CIDR_MASK, *bits);
                m.end();
            }
            m.end();
        }
        m.end();
    }
    if open {
        m.end();
    }
    s.request(&mut m).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attrs_roundtrip() {
        let mut m = Msg::new(1, 0);
        m.u32(1, 7).str(2, "mg0").nest(3).u16(1, 9).end();
        let b = &m.buf[16..];
        let got: Vec<(u16, Vec<u8>)> = attrs(b).map(|(t, d)| (t, d.to_vec())).collect();
        assert_eq!(got[0], (1, 7u32.to_ne_bytes().to_vec()));
        assert_eq!(got[1], (2, b"mg0\0".to_vec()));
        assert_eq!(attrs(&got[2].1).next().unwrap(), (1, &9u16.to_ne_bytes()[..]));
    }

    /// Reads real routes and links (works unprivileged).
    #[test]
    fn dumps_work() {
        let links = link_list().unwrap();
        assert!(links.iter().any(|l| l.loopback()));
        let lo = link_by_name("lo").unwrap();
        assert!(lo.index > 0);
        assert!(link_by_name("no-such-link0").is_err());
        let _ = route_list4().unwrap();
        let rules = rule_list4().unwrap();
        assert!(rules.iter().any(|r| r.table == RT_TABLE_MAIN));
    }
}
