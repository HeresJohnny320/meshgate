//! Starting and stopping the meshgate service (systemd on Linux, the rc
//! script on FreeBSD/pfSense, the Windows service).

use crate::util::run;

#[cfg(target_os = "linux")]
mod imp {
    use super::run;

    pub const START_HINT: &str = "sudo systemctl enable --now meshgate";

    /// Restarts meshgate if it runs; a stopped one stays stopped.
    pub fn restart() -> Result<(), String> {
        let o = run("systemctl", &["try-restart", "meshgate"], None);
        if o.ok { Ok(()) } else { Err(o.err) }
    }

    pub fn stop_for_leave() {
        run("systemctl", &["disable", "--now", "meshgate"], None);
    }

    /// Starts or stops meshgate and makes that survive reboots.
    pub fn set(on: bool) -> Result<(), String> {
        let verb = if on { "enable" } else { "disable" };
        let o = run("systemctl", &[verb, "--now", "meshgate"], None);
        if o.ok { Ok(()) } else { Err(format!("systemctl {verb}: {}: {}", o.err, o.out.trim())) }
    }
}

#[cfg(target_os = "freebsd")]
mod imp {
    use super::run;

    const RC: &str = "/usr/local/etc/rc.d/meshgate.sh";
    pub const START_HINT: &str = "/usr/local/etc/rc.d/meshgate.sh start";

    pub fn restart() -> Result<(), String> {
        if !run(RC, &["onestatus"], None).ok {
            return Ok(());
        }
        let o = run(RC, &["onerestart"], None);
        if o.ok { Ok(()) } else { Err(o.err) }
    }

    pub fn stop_for_leave() {
        run(RC, &["stop"], None);
        let _ = std::fs::remove_file(RC);
    }

    fn quiet(name: &str, args: &[&str]) -> Result<(), String> {
        let o = run(name, args, None);
        if o.ok { Ok(()) } else { Err(format!("{name} {args:?}: {}: {}", o.err, o.out.trim())) }
    }

    /// meshgate_enable in /etc/rc.conf.local; the rc script defaults to YES.
    pub fn set(on: bool) -> Result<(), String> {
        if on {
            run("sysrc", &["-f", "/etc/rc.conf.local", "-x", "meshgate_enable"], None);
            return quiet(RC, &["onestart"]);
        }
        let _ = quiet(RC, &["onestop"]);
        quiet("sysrc", &["-f", "/etc/rc.conf.local", "meshgate_enable=NO"])
    }
}

#[cfg(windows)]
mod imp {
    pub const START_HINT: &str = "meshgate service install";
    pub use crate::winsvc::{restart, set, stop_for_leave};
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd", windows)))]
mod imp {
    pub const START_HINT: &str = "meshgate agent";
    pub fn restart() -> Result<(), String> {
        Ok(())
    }
    pub fn stop_for_leave() {}
    pub fn set(_on: bool) -> Result<(), String> {
        Err("no service manager on this system".into())
    }
}

pub use imp::*;
