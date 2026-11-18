//! Starting and stopping the meshgate service (systemd on Linux, the rc
//! script on FreeBSD/pfSense, the Windows service, launchd on macOS).

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
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

#[cfg(target_os = "macos")]
mod imp {
    use super::run;

    const LABEL: &str = "dev.meshgate";
    const TARGET: &str = "system/dev.meshgate";
    const PLIST: &str = "/Library/LaunchDaemons/dev.meshgate.plist";
    pub const START_HINT: &str = "sudo meshgate service install";

    fn loaded() -> bool {
        run("launchctl", &["print", TARGET], None).ok
    }

    fn quiet(args: &[&str]) -> Result<(), String> {
        let o = run("launchctl", args, None);
        if o.ok { Ok(()) } else { Err(format!("launchctl {}: {}: {}", args.join(" "), o.err, o.out.trim())) }
    }

    /// Restarts meshgate if it runs; a stopped one stays stopped.
    pub fn restart() -> Result<(), String> {
        if !loaded() {
            return Ok(());
        }
        quiet(&["kickstart", "-k", TARGET])
    }

    pub fn stop_for_leave() {
        run("launchctl", &["bootout", TARGET], None);
        let _ = std::fs::remove_file(PLIST);
    }

    /// Starts or stops meshgate and makes that survive reboots.
    pub fn set(on: bool) -> Result<(), String> {
        if !std::path::Path::new(PLIST).exists() {
            return Err("meshgate service not installed (sudo meshgate service install)".into());
        }
        if on {
            quiet(&["enable", TARGET])?;
            if loaded() { Ok(()) } else { quiet(&["bootstrap", "system", PLIST]) }
        } else {
            quiet(&["disable", TARGET])?;
            run("launchctl", &["bootout", TARGET], None);
            Ok(())
        }
    }

    fn xml(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
    }

    /// `meshgate service install|uninstall`: a launchd job that runs the
    /// agent at boot and restarts it when it exits.
    pub fn cmd_service(cfg_path: &str, args: &[String]) -> Result<(), String> {
        match args.first().map(String::as_str) {
            Some("install") => {
                let exe = std::env::current_exe().map_err(|e| e.to_string())?;
                let cfg = std::path::absolute(cfg_path).map_err(|e| e.to_string())?;
                let argv = [exe.to_string_lossy().into_owned(), "-config".into(), cfg.to_string_lossy().into_owned(), "agent".into()];
                let argv: String = argv.iter().map(|a| format!("\t\t<string>{}</string>\n", xml(a))).collect();
                let plist = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                     <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
                     <plist version=\"1.0\">\n<dict>\n\
                     \t<key>Label</key>\n\t<string>{LABEL}</string>\n\
                     \t<key>ProgramArguments</key>\n\t<array>\n{argv}\t</array>\n\
                     \t<key>RunAtLoad</key>\n\t<true/>\n\
                     \t<key>KeepAlive</key>\n\t<true/>\n\
                     \t<key>ThrottleInterval</key>\n\t<integer>3</integer>\n\
                     \t<key>StandardOutPath</key>\n\t<string>/var/log/meshgate.log</string>\n\
                     \t<key>StandardErrorPath</key>\n\t<string>/var/log/meshgate.log</string>\n\
                     </dict>\n</plist>\n"
                );
                std::fs::write(PLIST, plist).map_err(|e| format!("write {PLIST} (run with sudo): {e}"))?;
                run("launchctl", &["bootout", TARGET], None);
                quiet(&["enable", TARGET])?;
                quiet(&["bootstrap", "system", PLIST])?;
                println!("meshgate service installed and started.");
                Ok(())
            }
            Some("uninstall") => {
                stop_for_leave();
                println!("meshgate service removed.");
                Ok(())
            }
            _ => Err("usage: meshgate service install|uninstall".into()),
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd", windows, target_os = "macos")))]
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
