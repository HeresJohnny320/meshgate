//! WireGuard device and peer settings shared by the kernel (netlink) and
//! userspace back ends.

use std::net::{IpAddr, SocketAddr};

/// A peer as the kernel reports it.
#[derive(Clone, Debug, Default)]
pub struct WgPeer {
    pub public_key: [u8; 32],
    pub endpoint: Option<SocketAddr>,
    /// Unix seconds and nanoseconds; (0, 0) = never.
    pub last_handshake: (i64, i64),
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub keepalive: u16,
    pub allowed_ips: Vec<(IpAddr, u8)>,
}

#[derive(Clone, Debug, Default)]
pub struct WgDevice {
    pub public_key: [u8; 32],
    pub listen_port: u16,
    pub fwmark: u32,
    pub peers: Vec<WgPeer>,
}

/// A peer change for set_device.
#[derive(Clone, Debug, Default)]
pub struct WgPeerConfig {
    pub public_key: [u8; 32],
    pub remove: bool,
    pub replace_allowed_ips: bool,
    pub endpoint: Option<SocketAddr>,
    pub keepalive: Option<u16>,
    pub allowed_ips: Vec<(IpAddr, u8)>,
}

#[derive(Clone, Debug, Default)]
pub struct WgConfig {
    pub private_key: Option<[u8; 32]>,
    pub listen_port: Option<u16>,
    pub fwmark: Option<u32>,
    pub peers: Vec<WgPeerConfig>,
}
