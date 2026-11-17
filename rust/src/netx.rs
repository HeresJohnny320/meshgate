//! Go `net/netip` and `net.SplitHostPort` equivalents with the same parsing
//! rules, so a value one implementation accepts the other accepts too.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

/// An IP prefix as Go's netip.Prefix: address (host bits kept) and length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Prefix {
    pub addr: IpAddr,
    pub bits: u8,
}

impl Prefix {
    pub fn new(addr: IpAddr, bits: u8) -> Prefix {
        Prefix { addr, bits }
    }

    /// The prefix with host bits cleared.
    pub fn masked(&self) -> Prefix {
        match self.addr {
            IpAddr::V4(a) => {
                let m = mask4(self.bits);
                Prefix::new(IpAddr::V4(Ipv4Addr::from(u32::from(a) & m)), self.bits)
            }
            IpAddr::V6(a) => {
                let m: u128 = if self.bits == 0 { 0 } else { u128::MAX << (128 - self.bits as u32) };
                Prefix::new(IpAddr::V6((u128::from(a) & m).into()), self.bits)
            }
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(p), IpAddr::V4(a)) => {
                let m = mask4(self.bits);
                u32::from(p) & m == u32::from(a) & m
            }
            (IpAddr::V6(p), IpAddr::V6(a)) => {
                let m: u128 = if self.bits == 0 { 0 } else { u128::MAX << (128 - self.bits as u32) };
                u128::from(p) & m == u128::from(a) & m
            }
            _ => false,
        }
    }

    pub fn overlaps(&self, o: &Prefix) -> bool {
        if self.addr.is_ipv4() != o.addr.is_ipv4() {
            return false;
        }
        let bits = self.bits.min(o.bits);
        Prefix::new(self.addr, bits).contains(o.addr)
    }

    pub fn is4(&self) -> bool {
        self.addr.is_ipv4()
    }

    pub fn is_single_ip(&self) -> bool {
        self.bits == if self.is4() { 32 } else { 128 }
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.bits)
    }
}

pub fn mask4(bits: u8) -> u32 {
    if bits == 0 { 0 } else { u32::MAX << (32 - bits as u32) }
}

/// netip.ParseAddr (IPv4 without leading zeros, or IPv6).
pub fn parse_addr(s: &str) -> Option<IpAddr> {
    s.parse().ok()
}

/// netip.ParseAddr that must be IPv4 (`Is4()`).
pub fn parse_addr4(s: &str) -> Option<Ipv4Addr> {
    match parse_addr(s)? {
        IpAddr::V4(a) => Some(a),
        _ => None,
    }
}

/// netip.ParsePrefix: "addr/bits", host bits allowed, bits without sign or
/// leading zeros.
pub fn parse_prefix(s: &str) -> Option<Prefix> {
    let (a, b) = s.rsplit_once('/')?;
    let addr = parse_addr(a)?;
    if b.is_empty() || b.len() > 3 || !b.bytes().all(|c| c.is_ascii_digit()) || (b.len() > 1 && b.starts_with('0')) {
        return None;
    }
    let bits: u8 = b.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if bits > max {
        return None;
    }
    Some(Prefix::new(addr, bits))
}

/// net.SplitHostPort.
pub fn split_host_port(hp: &str) -> Result<(String, String), String> {
    let missing = || format!("address {hp}: missing port in address");
    let too_many = || format!("address {hp}: too many colons in address");
    let (host, port);
    if let Some(rest) = hp.strip_prefix('[') {
        let end = rest.find(']').ok_or_else(|| format!("address {hp}: missing ']' in address"))?;
        host = &rest[..end];
        let after = &rest[end + 1..];
        port = after
            .strip_prefix(':')
            .ok_or_else(|| if after.is_empty() { missing() } else { format!("address {hp}: unexpected character after ']'") })?;
        if port.contains(':') {
            return Err(too_many());
        }
    } else {
        let i = hp.rfind(':').ok_or_else(missing)?;
        host = &hp[..i];
        port = &hp[i + 1..];
        if host.contains(':') {
            return Err(too_many());
        }
        if host.contains('[') || host.contains(']') {
            return Err(format!("address {hp}: unexpected '[' in address"));
        }
    }
    if port.contains('[') || port.contains(']') {
        return Err(format!("address {hp}: unexpected ']' in address"));
    }
    Ok((host.to_string(), port.to_string()))
}

/// net.JoinHostPort.
pub fn join_host_port(host: &str, port: impl fmt::Display) -> String {
    if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes() {
        let p = parse_prefix("192.168.1.7/24").unwrap();
        assert_eq!(p.masked().to_string(), "192.168.1.0/24");
        assert!(p.contains("192.168.1.200".parse().unwrap()));
        assert!(parse_prefix("1.2.3.4/33").is_none());
        assert!(parse_prefix("1.2.3.4/024").is_none());
        assert!(parse_prefix("1.2.3.04/24").is_none());
        assert!(parse_prefix("0.0.0.0/0").unwrap().contains("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn host_port() {
        assert_eq!(split_host_port("a:1").unwrap(), ("a".into(), "1".into()));
        assert_eq!(split_host_port("[::1]:5").unwrap(), ("::1".into(), "5".into()));
        assert!(split_host_port("a").is_err());
        assert!(split_host_port("a:b:c").is_err());
        assert_eq!(split_host_port("a:").unwrap(), ("a".into(), "".into()));
    }
}
