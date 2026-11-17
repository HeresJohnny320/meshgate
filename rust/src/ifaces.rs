//! Network interfaces and their addresses (Go: net.Interfaces + Addrs).

use std::net::IpAddr;

#[derive(Clone, Debug, Default)]
pub struct Iface {
    pub name: String,
    pub index: u32,
    pub up: bool,
    pub loopback: bool,
    pub point_to_point: bool,
    pub broadcast: bool,
    /// Addresses with their prefix length.
    pub addrs: Vec<(IpAddr, u8)>,
}

/// All interfaces in index order, like Go's net.Interfaces.
#[cfg(unix)]
pub fn list() -> Vec<Iface> {
    use std::collections::BTreeMap;
    use std::ffi::CStr;

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates a list we free below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return vec![];
    }
    let mut by_name: BTreeMap<String, Iface> = BTreeMap::new();
    let mut order: Vec<String> = vec![];
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: cur points into the list returned by getifaddrs.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().into_owned();
        let flags = ifa.ifa_flags as libc::c_int;
        let e = by_name.entry(name.clone()).or_insert_with(|| {
            order.push(name.clone());
            let cname = std::ffi::CString::new(name.clone()).unwrap_or_default();
            Iface {
                name: name.clone(),
                index: unsafe { libc::if_nametoindex(cname.as_ptr()) },
                up: flags & libc::IFF_UP != 0,
                loopback: flags & libc::IFF_LOOPBACK != 0,
                point_to_point: flags & libc::IFF_POINTOPOINT != 0,
                broadcast: flags & libc::IFF_BROADCAST != 0,
                addrs: vec![],
            }
        });
        if let (Some(a), Some(m)) = (sockaddr_ip(ifa.ifa_addr), sockaddr_ip(ifa.ifa_netmask)) {
            let bits = match m {
                IpAddr::V4(m) => u32::from(m).count_ones() as u8,
                IpAddr::V6(m) => u128::from(m).count_ones() as u8,
            };
            e.addrs.push((a, bits));
        } else if let Some(a) = sockaddr_ip(ifa.ifa_addr) {
            e.addrs.push((a, if a.is_ipv4() { 32 } else { 128 }));
        }
    }
    // SAFETY: head came from getifaddrs.
    unsafe { libc::freeifaddrs(head) };
    let mut out: Vec<Iface> = order.into_iter().filter_map(|n| by_name.remove(&n)).collect();
    out.sort_by_key(|i| i.index);
    out
}

#[cfg(unix)]
fn sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: the family field says which sockaddr type this is.
    unsafe {
        match (*sa).sa_family as libc::c_int {
            libc::AF_INET => {
                let s = &*(sa as *const libc::sockaddr_in);
                Some(IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(s.sin_addr.s_addr))))
            }
            libc::AF_INET6 => {
                let s = &*(sa as *const libc::sockaddr_in6);
                Some(IpAddr::V6(std::net::Ipv6Addr::from(s.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }
}

/// Interfaces on Windows (from `netsh`-free IP Helper API; filled in with the
/// Windows port).
#[cfg(windows)]
pub fn list() -> Vec<Iface> {
    crate::winnet::interfaces()
}

/// IPv4 addresses of all up interfaces.
pub fn local_v4() -> Vec<std::net::Ipv4Addr> {
    list()
        .into_iter()
        .filter(|i| i.up)
        .flat_map(|i| i.addrs)
        .filter_map(|(a, _)| match a {
            IpAddr::V4(a) => Some(a),
            _ => None,
        })
        .collect()
}
