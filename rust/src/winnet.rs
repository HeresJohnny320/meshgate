//! Windows helpers: network interfaces (IP Helper API), the password prompt,
//! and the local API transport (a named pipe only SYSTEM and Administrators
//! can open; the Go build used an AF_UNIX socket file).

#![cfg(windows)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, ServerOptions};
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_PIPE_BUSY, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, IF_TYPE_PPP, IF_TYPE_SOFTWARE_LOOPBACK,
    IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6};
use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::System::Console::{ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode};

use crate::http::{self, Peer};
use crate::ifaces::Iface;

/// Interfaces like Go's net.Interfaces on Windows (friendly names).
pub fn interfaces() -> Vec<Iface> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u64> = vec![];
    for _ in 0..3 {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: buf is size bytes, 8-byte aligned.
        let r = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, flags, std::ptr::null(), buf.as_mut_ptr() as *mut _, &mut size) };
        if r == NO_ERROR {
            break;
        }
        if r != ERROR_BUFFER_OVERFLOW {
            return vec![];
        }
    }
    let mut out = vec![];
    let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    // SAFETY: walking the list the API wrote into buf.
    unsafe {
        while !p.is_null() {
            let a = &*p;
            let name = wide(a.FriendlyName);
            let mut index = a.Anonymous1.Anonymous.IfIndex;
            if index == 0 {
                index = a.Ipv6IfIndex;
            }
            let loopback = a.IfType == IF_TYPE_SOFTWARE_LOOPBACK;
            let p2p = a.IfType == IF_TYPE_PPP || a.IfType == IF_TYPE_TUNNEL;
            let mut addrs = vec![];
            let mut u = a.FirstUnicastAddress;
            while !u.is_null() {
                let ua = &*u;
                if let Some(ip) = sockaddr_ip(ua.Address.lpSockaddr as *const u8) {
                    addrs.push((ip, ua.OnLinkPrefixLength));
                }
                u = ua.Next;
            }
            out.push(Iface {
                name,
                index,
                up: a.OperStatus == IfOperStatusUp,
                loopback,
                point_to_point: p2p,
                broadcast: !loopback && !p2p,
                addrs,
            });
            p = a.Next;
        }
    }
    out.sort_by_key(|i| i.index);
    out
}

unsafe fn wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    // SAFETY: a NUL-terminated UTF-16 string from the API.
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }
}

unsafe fn sockaddr_ip(sa: *const u8) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: the family field selects the struct the API stored.
    unsafe {
        let family = *(sa as *const u16);
        if family == AF_INET {
            let s = &*(sa as *const SOCKADDR_IN);
            Some(IpAddr::V4(Ipv4Addr::from(s.sin_addr.S_un.S_addr.to_ne_bytes())))
        } else if family == AF_INET6 {
            let s = &*(sa as *const SOCKADDR_IN6);
            Some(IpAddr::V6(Ipv6Addr::from(s.sin6_addr.u.Byte)))
        } else {
            None
        }
    }
}

/// Reads a line without echo.
pub fn read_password() -> String {
    // SAFETY: console mode calls on our own stdin handle.
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode = 0;
        let ok = GetConsoleMode(h, &mut mode) != 0;
        if ok {
            SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT);
        }
        let s = crate::cli::term::read_line();
        if ok {
            SetConsoleMode(h, mode);
        }
        s.trim_end_matches(['\r', '\n']).to_string()
    }
}

/// The pipe standing in for the socket file at `socket`.
pub fn pipe_name(socket: &str) -> String {
    format!(r"\\.\pipe\meshgate-{:08x}", crc32fast::hash(socket.to_lowercase().as_bytes()))
}

/// Pipe access: SYSTEM and Administrators only. Returns the descriptor's
/// address (kept as an integer so the serving future stays Send).
fn security() -> Result<usize, String> {
    let sddl: Vec<u16> = "D:P(A;;GA;;;SY)(A;;GA;;;BA)\0".encode_utf16().collect();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: converts a constant SDDL string; the descriptor is kept for the
    // life of the process (one per agent).
    let ok = unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) };
    if ok == 0 {
        return Err(format!("pipe security: {}", std::io::Error::last_os_error()));
    }
    Ok(sd as usize)
}

/// Serves h on the pipe for `socket`.
pub async fn serve_local(socket: &str, h: Arc<dyn http::Handler>) -> Result<(), String> {
    let name = pipe_name(socket);
    let sd = security()?;
    let create = |first: bool| {
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd as PSECURITY_DESCRIPTOR,
            bInheritHandle: 0,
        };
        let mut o = ServerOptions::new();
        o.first_pipe_instance(first).reject_remote_clients(true);
        // SAFETY: sa holds a valid descriptor for the call.
        unsafe { o.create_with_security_attributes_raw(&name, &mut sa as *mut _ as *mut std::ffi::c_void) }
            .map_err(|e| format!("listen pipe {name}: {e}"))
    };
    let mut server = create(true)?;
    loop {
        if server.connect().await.is_err() {
            tokio::time::sleep(Duration::from_millis(100)).await;
            server = create(false)?;
            continue;
        }
        let conn = server;
        server = create(false)?;
        let h = h.clone();
        tokio::spawn(http::serve_conn(conn, h, Peer { addr: None, tls: false }));
    }
}

/// Connects to the agent's pipe.
pub async fn connect_local(socket: &str) -> Result<NamedPipeClient, String> {
    let name = pipe_name(socket);
    loop {
        match ClientOptions::new().open(&name) {
            Ok(c) => return Ok(c),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => tokio::time::sleep(Duration::from_millis(50)).await,
            Err(e) => return Err(format!("dial pipe {name}: {e}")),
        }
    }
}
