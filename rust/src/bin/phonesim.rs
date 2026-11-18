//! Runs the phone engine (meshgate::mobile) on Linux with a fake platform
//! layer, so the phone code path is tested end to end without a phone (Go:
//! mobile/phonesim, same flags). Like the iOS app: one TUN device whose
//! settings are updated in place.
//!
//!   phonesim -dir /tmp/phone -join mg1.... -name phone
//!   kill -USR1 <pid>   # simulate a Wi-Fi/LTE change

#[cfg(target_os = "linux")]
fn main() {
    sim::main()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("phonesim runs on Linux only");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod sim {
    use std::os::fd::IntoRawFd;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use meshgate::mobile::{Engine, Platform, TunnelSettings};

    const IFNAME: &str = "mgphone";
    const TABLE: &str = "51820"; // tunnel routes, like Android's VPN routing
    const BYPASS_MARK: u32 = 0x4d46;

    fn log(msg: &str) {
        let (_, _, _, h, m, s, _) = meshgate::logx::local(meshgate::util::now_unix());
        eprintln!("{h:02}:{m:02}:{s:02} {msg}");
    }

    struct Plat {
        fd: Mutex<i32>,
        routes: Mutex<Option<Vec<String>>>,
    }

    fn ip(args: &[&str]) {
        let o = meshgate::util::run("ip", args, None);
        if !o.ok {
            log(&format!("ip {args:?}: {} {}", o.err, o.out));
        }
    }

    impl Platform for Plat {
        /// Marks the socket like Android's VpnService.protect: marked traffic
        /// skips the tunnel's routing table.
        fn protect(&self, fd: i32) -> bool {
            let mark = BYPASS_MARK;
            // SAFETY: setsockopt on a descriptor the engine owns.
            unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_MARK, &mark as *const u32 as *const libc::c_void, 4) == 0 }
        }

        fn log(&self, msg: String) {
            log(&msg);
        }

        fn local_addresses(&self) -> String {
            meshgate::ifaces::list()
                .into_iter()
                .filter(|i| i.name != IFNAME && i.up && !i.loopback)
                .flat_map(|i| i.addrs)
                .filter(|(a, _)| a.is_ipv4())
                .map(|(a, _)| a.to_string())
                .collect::<Vec<_>>()
                .join(",")
        }

        fn configure_tunnel(&self, settings: String) -> i32 {
            let ts: TunnelSettings = match serde_json::from_str(&settings) {
                Ok(t) => t,
                Err(e) => {
                    log(&e.to_string());
                    return -1;
                }
            };
            let mut fd = self.fd.lock().unwrap();
            if *fd < 0 {
                match meshgate::wgdev::FdTun::open_linux(IFNAME) {
                    Ok(t) => {
                        // The descriptor lives as long as the simulator.
                        let raw = tun_raw(t);
                        *fd = raw;
                    }
                    Err(e) => {
                        log(&format!("tun: {e}"));
                        return -1;
                    }
                }
            }
            ip(&["link", "set", IFNAME, "mtu", &ts.mtu.to_string(), "up"]);
            ip(&["addr", "replace", &format!("{}/{}", ts.address, ts.prefix), "dev", IFNAME]);
            // Tunnel routes live in their own table, used by every unmarked
            // packet unless the main table has a more specific route.
            let mut routes = self.routes.lock().unwrap();
            if routes.is_none() {
                ip(&["rule", "add", "prio", "99", "lookup", "main", "suppress_prefixlength", "0"]);
                ip(&["rule", "add", "prio", "100", "not", "fwmark", &BYPASS_MARK.to_string(), "lookup", TABLE]);
            }
            for r in &ts.routes {
                ip(&["route", "replace", r, "dev", IFNAME, "table", TABLE]);
            }
            for r in routes.iter().flatten() {
                if !ts.routes.contains(r) {
                    ip(&["route", "del", r, "dev", IFNAME, "table", TABLE]);
                }
            }
            if !ts.dns.is_empty() {
                log(&format!("dns: [{}]", ts.dns.join(" ")));
            }
            *routes = Some(ts.routes.clone());
            log(&format!("tunnel settings: {settings}"));
            *fd
        }
    }

    /// Takes the descriptor out of the FdTun without closing it.
    fn tun_raw(t: meshgate::wgdev::FdTun) -> i32 {
        t.into_raw_fd()
    }

    pub fn main() {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let get = |name: &str| -> String {
            let mut v = String::new();
            let mut i = 0;
            while i < args.len() {
                let a = args[i].trim_start_matches('-');
                if let Some((k, val)) = a.split_once('=') {
                    if k == name {
                        v = val.to_string();
                    }
                } else if a == name && i + 1 < args.len() {
                    v = args[i + 1].clone();
                    i += 1;
                }
                i += 1;
            }
            v
        };
        let dir = get("dir");
        let tok = get("join");
        let mut name = get("name");
        if name.is_empty() {
            name = "phone".into();
        }
        let status_file = get("status");
        let myip = get("myip-url");
        let cmd_file = get("cmd");
        if !myip.is_empty() {
            // SAFETY: set before any thread starts.
            unsafe { std::env::set_var("MESHGATE_MYIP_URL", &myip) };
        }
        let plat = Arc::new(Plat { fd: Mutex::new(-1), routes: Mutex::new(None) });
        let e = match Engine::new(&dir, plat) {
            Ok(e) => e,
            Err(err) => {
                log(&err);
                std::process::exit(1);
            }
        };
        if !e.is_joined() {
            if let Err(err) = e.join(&tok, &name) {
                log(&format!("join: {err}"));
                std::process::exit(1);
            }
            log("joined");
        }
        if let Err(err) = e.start() {
            log(&format!("start: {err}"));
            std::process::exit(1);
        }
        let usr1 = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let usr2 = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let quit = Arc::new(std::sync::atomic::AtomicBool::new(false));
        for (sig, flag) in
            [(libc::SIGUSR1, usr1.clone()), (libc::SIGUSR2, usr2.clone()), (libc::SIGINT, quit.clone()), (libc::SIGTERM, quit.clone())]
        {
            let _ = signal_hook_lite(sig, flag);
        }
        loop {
            std::thread::sleep(Duration::from_secs(1));
            if quit.load(std::sync::atomic::Ordering::SeqCst) {
                e.stop();
                return;
            }
            if usr1.swap(false, std::sync::atomic::Ordering::SeqCst) {
                log("network changed");
                e.network_changed();
            }
            if usr2.swap(false, std::sync::atomic::Ordering::SeqCst) {
                let e2 = e.clone();
                std::thread::spawn(move || log(&format!("diag myip: {}", e2.diag("myip", "", 0))));
            }
            if !cmd_file.is_empty()
                && let Ok(b) = std::fs::read_to_string(&cmd_file)
            {
                let _ = std::fs::remove_file(&cmd_file);
                let e2 = e.clone();
                std::thread::spawn(move || run_admin(&e2, &b));
            }
            if !status_file.is_empty() {
                let tmp = format!("{status_file}.tmp");
                if std::fs::write(&tmp, e.status_json()).is_ok() {
                    let _ = std::fs::rename(&tmp, &status_file);
                }
            }
        }
    }

    /// Replays dashboard requests the way the app's Admin screen sends them.
    fn run_admin(e: &Engine, lines: &str) {
        for l in lines.trim().lines() {
            let f: Vec<&str> = l.trim().splitn(3, ' ').collect();
            if f.len() == 2 && f[0] == "killswitch" {
                log(&format!("killswitch {}: {:?}", f[1], e.set_kill_switch(f[1] == "on")));
                continue;
            }
            if f.len() == 2 && f[0] == "exit" {
                let choice = if f[1] == "default" { "" } else { f[1] };
                log(&format!("exit choice {}: {:?}", f[1], e.set_exit_choice(choice)));
                continue;
            }
            if f.len() < 2 {
                continue;
            }
            let body = f.get(2).copied().unwrap_or("");
            #[derive(serde::Deserialize, Default)]
            #[serde(default)]
            struct R {
                status: i64,
                body: String,
                server: String,
            }
            let mut r: R = serde_json::from_str(&e.admin(f[0], f[1], body)).unwrap_or_default();
            if r.body.chars().count() > 200 {
                r.body = r.body.chars().take(200).collect::<String>() + "…";
            }
            log(&format!("admin {} {}: status={} server={} {}", f[0], f[1], r.status, r.server, r.body));
        }
    }

    /// Sets flag when sig arrives.
    fn signal_hook_lite(sig: i32, flag: Arc<std::sync::atomic::AtomicBool>) -> std::io::Result<()> {
        use std::sync::OnceLock;
        type Flags = Mutex<Vec<(i32, Arc<std::sync::atomic::AtomicBool>)>>;
        static FLAGS: OnceLock<Flags> = OnceLock::new();
        extern "C" fn handler(sig: i32) {
            if let Some(f) = FLAGS.get()
                && let Ok(v) = f.try_lock()
            {
                for (s, fl) in v.iter() {
                    if *s == sig {
                        fl.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                }
            }
        }
        FLAGS.get_or_init(|| Mutex::new(vec![])).lock().unwrap().push((sig, flag));
        // SAFETY: installing a handler that only stores atomics.
        unsafe { libc::signal(sig, handler as *const () as libc::sighandler_t) };
        Ok(())
    }
}
