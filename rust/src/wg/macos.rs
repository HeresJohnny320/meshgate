//! macOS: a utun interface carries the tunnel's packets (macOS picks its
//! name, utunN); address and routes are set with ifconfig and route.

use std::sync::Arc;

use super::user::NetIf;
use crate::netx::Prefix;
use crate::util::run;
use crate::wgdev;

pub(super) fn open(_iface: &str) -> Result<Box<dyn NetIf>, String> {
    let (fd, name) = open_utun().map_err(|e| format!("create utun interface (run as root): {e}"))?;
    let tun = Arc::new(wgdev::FdTun::owned(fd, true));
    let o = run("ifconfig", &[&name, "mtu", &super::MTU.to_string(), "up"], None);
    if !o.ok {
        return Err(format!("ifconfig {name}: {} {}", o.err, o.out.trim()));
    }
    Ok(Box::new(Utun { tun, name }))
}

/// Opens a utun control socket; returns it and the interface's name.
fn open_utun() -> std::io::Result<(i32, String)> {
    use std::io::Error;
    // SAFETY: the kernel-control socket sequence from <sys/kern_control.h>
    // with zeroed structs; the descriptor is closed on every error path.
    unsafe {
        let fd = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
        if fd < 0 {
            return Err(Error::last_os_error());
        }
        let fail = |fd: i32| {
            let e = Error::last_os_error();
            libc::close(fd);
            Err(e)
        };
        let mut info: libc::ctl_info = std::mem::zeroed();
        for (i, b) in b"com.apple.net.utun_control".iter().enumerate() {
            info.ctl_name[i] = *b as libc::c_char;
        }
        if libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) < 0 {
            return fail(fd);
        }
        let addr = libc::sockaddr_ctl {
            sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: libc::AF_SYS_CONTROL as u16,
            sc_id: info.ctl_id,
            sc_unit: 0, // the next free utunN
            sc_reserved: [0; 5],
        };
        if libc::connect(fd, &addr as *const _ as *const libc::sockaddr, std::mem::size_of_val(&addr) as libc::socklen_t) < 0 {
            return fail(fd);
        }
        let mut name = [0u8; libc::IFNAMSIZ];
        let mut len = name.len() as libc::socklen_t;
        if libc::getsockopt(fd, libc::SYSPROTO_CONTROL, libc::UTUN_OPT_IFNAME, name.as_mut_ptr() as *mut libc::c_void, &mut len) < 0 {
            return fail(fd);
        }
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        Ok((fd, String::from_utf8_lossy(&name[..end]).into_owned()))
    }
}

struct Utun {
    tun: Arc<wgdev::FdTun>,
    name: String,
}

fn mask(bits: u8) -> String {
    std::net::Ipv4Addr::from(crate::netx::mask4(bits)).to_string()
}

impl NetIf for Utun {
    fn tun(&self) -> Arc<dyn wgdev::Tun> {
        self.tun.clone()
    }

    fn set_address(&self, a: Prefix) -> Result<(), String> {
        let ip = a.addr.to_string();
        // utun is point to point: the address is both ends, and the mesh's
        // subnet is routed to the interface.
        let o = run("ifconfig", &[&self.name, "inet", &ip, &ip, "netmask", &mask(a.bits), "alias"], None);
        if !o.ok {
            return Err(format!("ifconfig {}: {} {}", self.name, o.err, o.out.trim()));
        }
        let net = a.masked();
        run("route", &["-q", "-n", "add", "-inet", &format!("{}/{}", net.addr, net.bits), "-interface", &self.name], None);
        Ok(())
    }

    fn set_routes(&self, old: &[Prefix], new: &[Prefix]) -> Result<(), String> {
        for r in old.iter().filter(|r| !new.contains(r)) {
            run("route", &["-q", "-n", "delete", "-inet", &format!("{}/{}", r.addr, r.bits), "-interface", &self.name], None);
        }
        for r in new.iter().filter(|r| !old.contains(r)) {
            let dst = format!("{}/{}", r.addr, r.bits);
            let o = run("route", &["-q", "-n", "add", "-inet", &dst, "-interface", &self.name], None);
            if !o.ok && !o.out.contains("File exists") {
                return Err(format!("route add {dst}: {} {}", o.err, o.out.trim()));
            }
        }
        Ok(())
    }

    /// The interface disappears with its descriptor, closed when the last
    /// user of the FdTun (the WireGuard device) is gone.
    fn close(&self) {}
}
