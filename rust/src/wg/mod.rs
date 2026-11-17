//! The WireGuard interface (Go: internal/wg). Linux uses the kernel module
//! over netlink; FreeBSD/pfSense the if_wg kernel module through `wg`/
//! `ifconfig`; Windows the WireGuardNT driver.

use std::net::IpAddr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;

pub mod types;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "freebsd")]
pub use freebsd::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

/// Leaves room for IPv6 outer headers and PPPoE/LTE links.
pub const MTU: u32 = 1280;

/// Runtime information about a peer.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PeerStat {
    pub public_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub endpoint: String,
    /// Unix seconds and nanoseconds; (0, 0) = never. Serialized like Go's
    /// time.Time.
    #[serde(serialize_with = "crate::util::ser_go_time")]
    pub last_handshake: (i64, i64),
    pub rx_bytes: i64,
    pub tx_bytes: i64,
}

impl PeerStat {
    /// Seconds since the last handshake, None when there was none.
    pub fn handshake_age(&self) -> Option<i64> {
        (self.last_handshake.0 != 0).then(|| crate::util::now_unix() - self.last_handshake.0)
    }
}

/// IPv4 addresses on interfaces other than the mesh.
pub fn local_addrs(skip: &str) -> Vec<IpAddr> {
    crate::ifaces::list()
        .into_iter()
        .filter(|i| i.name != skip && i.up && !i.loopback)
        .flat_map(|i| i.addrs)
        .filter(|(a, _)| a.is_ipv4())
        .map(|(a, _)| a)
        .collect()
}

/// A WireGuard key (base64 of 32 bytes).
pub fn parse_key(s: &str) -> Option<[u8; 32]> {
    crate::join::parse_key(s)
}

pub fn key_string(k: &[u8; 32]) -> String {
    STANDARD.encode(k)
}

/// A new private key (clamped like wgtypes.GeneratePrivateKey).
pub fn generate_private_key() -> [u8; 32] {
    let mut k = crate::util::random_bytes::<32>();
    k[0] &= 248;
    k[31] = (k[31] & 127) | 64;
    k
}

pub fn public_key(private: &[u8; 32]) -> [u8; 32] {
    let s = x25519_dalek::StaticSecret::from(*private);
    *x25519_dalek::PublicKey::from(&s).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same public key as wgtypes for a known private key.
    #[test]
    fn public_key_matches_wireguard() {
        let private = parse_key("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=").unwrap();
        assert_eq!(key_string(&public_key(&private)), "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=");
        let k = generate_private_key();
        assert_eq!(k[0] & 7, 0);
    }
}
