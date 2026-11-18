//! Userspace WireGuard, used when the kernel has no WireGuard module (Go:
//! the embedded wireguard-go). On Linux it runs boringtun; it is configured
//! through the standard UAPI socket (/var/run/wireguard/<iface>.sock), so
//! `wg show` works with it too.

#[cfg(target_os = "linux")]
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::sync::Mutex;

use crate::wg::types as nl;

#[cfg(target_os = "linux")]
static DEVICES: Mutex<Option<HashMap<String, boringtun::device::DeviceHandle>>> = Mutex::new(None);

/// Starts a userspace interface.
#[cfg(target_os = "linux")]
pub fn start(iface: &str, _mtu: u32) -> Result<(), String> {
    let cfg = boringtun::device::DeviceConfig { n_threads: 2, use_connected_socket: true, use_multi_queue: false, uapi_fd: -1 };
    let h = boringtun::device::DeviceHandle::new(iface, cfg).map_err(|e| format!("userspace WireGuard: {e:?}"))?;
    DEVICES.lock().unwrap().get_or_insert_default().insert(iface.to_string(), h);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn start(_iface: &str, _mtu: u32) -> Result<(), String> {
    Err("userspace WireGuard is not available on this system; load the if_wg kernel module (FreeBSD 13.2+, pfSense 2.7+)".into())
}

/// Stops it (the interface goes away with it).
pub fn stop(iface: &str) {
    #[cfg(target_os = "linux")]
    {
        let h = DEVICES.lock().unwrap().as_mut().and_then(|m| m.remove(iface));
        drop(h);
    }
    let _ = std::fs::remove_file(sock(iface));
}

fn sock(iface: &str) -> String {
    format!("/var/run/wireguard/{iface}.sock")
}

#[cfg(unix)]
fn uapi(iface: &str, req: &str) -> Result<Vec<(String, String)>, String> {
    let mut c = std::os::unix::net::UnixStream::connect(sock(iface)).map_err(|e| format!("uapi {iface}: {e}"))?;
    c.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
    c.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut out = vec![];
    for l in BufReader::new(c).lines() {
        let l = l.map_err(|e| e.to_string())?;
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once('=') {
            out.push((k.to_string(), v.to_string()));
        }
    }
    if let Some((_, e)) = out.iter().find(|(k, _)| k == "errno")
        && e != "0"
    {
        return Err(format!("uapi {iface}: errno {e}"));
    }
    Ok(out)
}

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).ok().and_then(|b| b.try_into().ok()).unwrap_or([0; 32])
}

/// Reads the device (UAPI "get").
pub fn get(iface: &str) -> Result<nl::WgDevice, String> {
    let mut dev = nl::WgDevice::default();
    let mut peer: Option<nl::WgPeer> = None;
    for (k, v) in uapi(iface, "get=1\n\n")? {
        match k.as_str() {
            "listen_port" => dev.listen_port = v.parse().unwrap_or(0),
            "fwmark" => dev.fwmark = v.parse().unwrap_or(0),
            "public_key" => {
                if let Some(p) = peer.take() {
                    dev.peers.push(p);
                }
                peer = Some(nl::WgPeer { public_key: hex32(&v), ..Default::default() });
            }
            _ => {
                let Some(p) = peer.as_mut() else { continue };
                match k.as_str() {
                    "endpoint" => p.endpoint = v.parse().ok(),
                    "last_handshake_time_sec" => p.last_handshake.0 = v.parse().unwrap_or(0),
                    "last_handshake_time_nsec" => p.last_handshake.1 = v.parse().unwrap_or(0),
                    "rx_bytes" => p.rx_bytes = v.parse().unwrap_or(0),
                    "tx_bytes" => p.tx_bytes = v.parse().unwrap_or(0),
                    "persistent_keepalive_interval" => p.keepalive = v.parse().unwrap_or(0),
                    "allowed_ip" => {
                        if let Some(pf) = crate::netx::parse_prefix(&v) {
                            p.allowed_ips.push((pf.addr, pf.bits));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    if let Some(p) = peer {
        dev.peers.push(p);
    }
    Ok(dev)
}

/// Configures the device (UAPI "set").
pub fn set(iface: &str, cfg: &nl::WgConfig) -> Result<(), String> {
    let mut r = String::from("set=1\n");
    if let Some(k) = cfg.private_key {
        r += &format!("private_key={}\n", hex::encode(k));
    }
    if let Some(p) = cfg.listen_port {
        r += &format!("listen_port={p}\n");
    }
    if let Some(f) = cfg.fwmark {
        r += &format!("fwmark={f}\n");
    }
    for p in &cfg.peers {
        r += &format!("public_key={}\n", hex::encode(p.public_key));
        if p.remove {
            r += "remove=true\n";
            continue;
        }
        if p.replace_allowed_ips {
            r += "replace_allowed_ips=true\n";
        }
        if let Some(ep) = &p.endpoint {
            r += &format!("endpoint={ep}\n");
        }
        if let Some(k) = p.keepalive {
            r += &format!("persistent_keepalive_interval={k}\n");
        }
        for (ip, bits) in &p.allowed_ips {
            let ip = match ip {
                IpAddr::V4(a) => a.to_string(),
                IpAddr::V6(a) => a.to_string(),
            };
            r += &format!("allowed_ip={ip}/{bits}\n");
        }
    }
    r += "\n";
    uapi(iface, &r).map(|_| ())
}
