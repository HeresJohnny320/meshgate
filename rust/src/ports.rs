//! Finds free ports during setup (Go: internal/ports).

use std::collections::HashSet;
use std::net::{TcpListener, UdpSocket};

/// Whether UDP port p can be bound on all IPv4 addresses.
pub fn udp_free(p: i64) -> bool {
    (0..65536).contains(&p) && UdpSocket::bind(("0.0.0.0", p as u16)).is_ok()
}

/// Whether TCP port p can be bound on all IPv4 addresses.
pub fn tcp_free(p: i64) -> bool {
    (0..65536).contains(&p) && TcpListener::bind(("0.0.0.0", p as u16)).is_ok()
}

/// Peers probe a node on its WireGuard port + 2 (see probe).
const PROBE_OFFSET: i64 = 2;

/// `want` if UDP want and want+2 are free, otherwise the next free pair in
/// steps of 10 (51830, 51840, ...).
pub fn wireguard(want: i64) -> Option<i64> {
    let mut c = want;
    while c < want + 1000 && c + PROBE_OFFSET < 65536 {
        if udp_free(c) && udp_free(c + PROBE_OFFSET) {
            return Some(c);
        }
        c += 10;
    }
    None
}

/// `want` if free, otherwise the next free port not in `taken`.
pub fn tcp(want: i64, taken: &HashSet<i64>) -> Option<i64> {
    (want..(want + 1000).min(65536)).find(|c| !taken.contains(c) && tcp_free(*c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wireguard_skips_busy_port() {
        let Some(base) = wireguard(41820) else { return };
        let c = UdpSocket::bind(("0.0.0.0", base as u16)).unwrap();
        let got = wireguard(base).unwrap();
        assert!(got != base && (got - base) % 10 == 0, "got {got} (base {base} busy)");
        drop(c);
        let _p = UdpSocket::bind(("0.0.0.0", (base + 2) as u16)).unwrap();
        assert_ne!(wireguard(base), Some(base), "ignored busy probe port");
    }

    #[test]
    fn tcp_skips_busy_and_taken() {
        let l = TcpListener::bind("0.0.0.0:0").unwrap();
        let busy = l.local_addr().unwrap().port() as i64;
        let got = tcp(busy, &HashSet::from([busy + 1])).unwrap();
        assert!(got != busy && got != busy + 1);
    }
}
