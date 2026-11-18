//! Windows: a Wintun adapter carries the tunnel's packets; its address,
//! routes and MTU are set through the IP Helper API (what winipcfg does for
//! the Go build). wintun.dll must sit next to meshgate.exe (the release zip
//! ships it).

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use windows_sys::Win32::Foundation::{ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR, WAIT_OBJECT_0};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2, DeleteUnicastIpAddressEntry, FreeMibTable,
    GetIpInterfaceEntry, GetUnicastIpAddressTable, InitializeIpForwardEntry, InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry,
    MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE, SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, IN_ADDR, IN_ADDR_0, IpDadStatePreferred, MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_INET,
};
use windows_sys::Win32::System::Threading::WaitForSingleObject;

use super::user::NetIf;
use crate::netx::Prefix;
use crate::wgdev;

pub(super) fn open(iface: &str) -> Result<Box<dyn NetIf>, String> {
    let dll = std::env::current_exe().ok().and_then(|e| e.parent().map(|d| d.join("wintun.dll")));
    let dll = match dll {
        Some(p) if p.exists() => p,
        _ => return Err("wintun.dll is missing next to meshgate.exe (download it from https://www.wintun.net)".into()),
    };
    // SAFETY: loads the Wintun DLL shipped next to the executable.
    let wintun = unsafe { wintun::load_from_path(&dll) }.map_err(|e| format!("load wintun.dll: {e}"))?;
    // An adapter left by a crash would keep the name taken.
    if let Ok(old) = wintun::Adapter::open(&wintun, iface)
        && let Ok(a) = Arc::try_unwrap(old)
    {
        let _ = a.delete();
    }
    let adapter = wintun::Adapter::create(&wintun, iface, "meshgate", None)
        .map_err(|e| format!("create Wintun adapter (run as Administrator): {e}"))?;
    // SAFETY: every bit pattern of the LUID union is a valid u64.
    let luid = unsafe { adapter.get_luid().Value };
    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY).map_err(|e| format!("Wintun session: {e}"))?);
    let event = session.get_read_wait_event().map_err(|e| format!("Wintun session: {e}"))? as isize;
    if let Err(e) = set_mtu(luid, super::MTU) {
        crate::logx::output(&format!("wg: mtu: {e}"));
    }
    Ok(Box::new(Wintun { tun: Arc::new(WintunTun { session, event }), luid }))
}

struct Wintun {
    tun: Arc<WintunTun>,
    luid: u64,
}

struct WintunTun {
    session: Arc<wintun::Session>,
    event: isize,
}

impl wgdev::Tun for WintunTun {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        for _ in 0..2 {
            match self.session.try_receive() {
                Ok(Some(p)) => {
                    let b = p.bytes();
                    let n = b.len().min(buf.len());
                    buf[..n].copy_from_slice(&b[..n]);
                    return Ok(n);
                }
                Ok(None) => {
                    // SAFETY: the event handle lives as long as the session.
                    if unsafe { WaitForSingleObject(self.event as _, 250) } != WAIT_OBJECT_0 {
                        return Ok(0);
                    }
                }
                Err(e) => return Err(io::Error::other(e.to_string())),
            }
        }
        Ok(0)
    }

    fn write(&self, packet: &[u8]) -> io::Result<()> {
        let mut p = self.session.allocate_send_packet(packet.len() as u16).map_err(|e| io::Error::other(e.to_string()))?;
        p.bytes_mut().copy_from_slice(packet);
        self.session.send_packet(p);
        Ok(())
    }
}

impl NetIf for Wintun {
    fn tun(&self) -> Arc<dyn wgdev::Tun> {
        self.tun.clone()
    }

    fn set_address(&self, a: Prefix) -> Result<(), String> {
        let IpAddr::V4(ip) = a.addr else { return Err("IPv6 mesh addresses are not supported".into()) };
        // Drop other IPv4 addresses of the adapter.
        let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
        // SAFETY: the table is allocated by the API and freed below.
        unsafe {
            if GetUnicastIpAddressTable(AF_INET, &mut table) == NO_ERROR {
                let t = &*table;
                let rows = std::slice::from_raw_parts(t.Table.as_ptr(), t.NumEntries as usize);
                for r in rows {
                    if r.InterfaceLuid.Value == self.luid && (from_sockaddr(&r.Address) != ip || r.OnLinkPrefixLength != a.bits) {
                        DeleteUnicastIpAddressEntry(r);
                    }
                }
                FreeMibTable(table as _);
            }
            let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
            InitializeUnicastIpAddressEntry(&mut row);
            row.InterfaceLuid = luid(self.luid);
            row.Address = sockaddr(ip);
            row.OnLinkPrefixLength = a.bits;
            row.DadState = IpDadStatePreferred;
            check(CreateUnicastIpAddressEntry(&row))
        }
    }

    fn set_routes(&self, old: &[Prefix], new: &[Prefix]) -> Result<(), String> {
        for r in old.iter().filter(|r| !new.contains(r)) {
            if let Some(row) = self.route(r) {
                // SAFETY: a fully initialized row.
                unsafe { DeleteIpForwardEntry2(&row) };
            }
        }
        for r in new {
            let Some(row) = self.route(r) else { continue };
            // SAFETY: as above.
            check(unsafe { CreateIpForwardEntry2(&row) }).map_err(|e| format!("{}/{}: {e}", r.addr, r.bits))?;
        }
        Ok(())
    }

    fn close(&self) {
        let _ = self.tun.session.shutdown();
        // The adapter is removed when the last handle (the session's) goes.
    }
}

impl Wintun {
    /// An on-link IPv4 route through the adapter.
    fn route(&self, p: &Prefix) -> Option<MIB_IPFORWARD_ROW2> {
        let IpAddr::V4(dst) = p.addr else { return None };
        let bits = p.bits.min(32);
        let masked = if bits == 0 { 0 } else { u32::from(dst) & (u32::MAX << (32 - bits)) };
        // SAFETY: zeroed then initialized by the API.
        unsafe {
            let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
            InitializeIpForwardEntry(&mut row);
            row.InterfaceLuid = luid(self.luid);
            row.DestinationPrefix.Prefix = sockaddr(Ipv4Addr::from(masked));
            row.DestinationPrefix.PrefixLength = bits;
            row.NextHop = sockaddr(Ipv4Addr::UNSPECIFIED);
            row.Metric = 0;
            row.Protocol = MIB_IPPROTO_NETMGMT;
            Some(row)
        }
    }
}

fn set_mtu(l: u64, mtu: u32) -> Result<(), String> {
    // SAFETY: zeroed then initialized and filled by the API.
    unsafe {
        let mut row: MIB_IPINTERFACE_ROW = std::mem::zeroed();
        InitializeIpInterfaceEntry(&mut row);
        row.Family = AF_INET;
        row.InterfaceLuid = luid(l);
        check(GetIpInterfaceEntry(&mut row))?;
        row.NlMtu = mtu;
        row.SitePrefixLength = 0; // required for IPv4
        check(SetIpInterfaceEntry(&mut row))
    }
}

fn luid(v: u64) -> NET_LUID_LH {
    NET_LUID_LH { Value: v }
}

fn sockaddr(ip: Ipv4Addr) -> SOCKADDR_INET {
    SOCKADDR_INET {
        Ipv4: SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR { S_un: IN_ADDR_0 { S_addr: u32::from_ne_bytes(ip.octets()) } },
            sin_zero: [0; 8],
        },
    }
}

fn from_sockaddr(a: &SOCKADDR_INET) -> Ipv4Addr {
    // SAFETY: rows from an AF_INET table hold IPv4 addresses.
    Ipv4Addr::from(unsafe { a.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes())
}

fn check(code: u32) -> Result<(), String> {
    if code == NO_ERROR || code == ERROR_OBJECT_ALREADY_EXISTS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32).to_string())
    }
}
