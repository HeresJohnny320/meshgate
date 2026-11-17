//! The command line (Go: cmd/meshgate): same commands, flags, output and
//! exit codes.

mod flags;
pub mod service;
mod setup;
pub mod term;

use std::path::Path;

use flags::Flags;

use crate::config;
use crate::localapi::Client;
use crate::model::{self, Node};
use crate::ops::{Item, View};

fn usage() -> String {
    format!(
        "meshgate - self-hosted WireGuard mesh, port forwarding and HTTPS tunnels

Usage:
  meshgate init                 set up this machine (asks: web UI or node)
  meshgate join <token>         join an existing mesh
  meshgate agent                run the node (started by systemd)
  meshgate tui                  manage the mesh in the terminal
  meshgate status               show nodes and connection paths
  meshgate token [flags]        create a join token (--kind client|server)
  meshgate webui enable|disable host the web UI on this node (or stop)
  meshgate webui ca             the web UI's CA: install it once per device, no more warnings
  meshgate pfsense install|remove  VPN > meshgate page and Firewall > Rules > MESHGATE tab (pfSense)
  meshgate diag ping|trace|tcp|udp|http <target> [port]  test connectivity from this node
  meshgate service install|uninstall  run at boot (Windows service; systemd/rc.d are set up by the installer)
  meshgate start|stop|restart   turn meshgate on or off; it stays that way after reboots
  meshgate leave                stop and remove meshgate config from this machine
  meshgate update [--check]     install the latest release (checksum-verified) and restart
  meshgate version

Global flags:
  -config path                  node config (default {})
",
        config::default_path()
    )
}

/// The process entry point; returns the exit code.
pub fn main() -> i32 {
    crate::logx::set_std_flags(false);
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut cfg_path = config::default_path();
    if args.len() >= 2 && (args[0] == "-config" || args[0] == "--config") {
        cfg_path = args[1].clone();
        args.drain(..2);
    }
    if args.is_empty() {
        print!("{}", usage());
        return 2;
    }
    let cmd = args.remove(0);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(16)
        .thread_keep_alive(std::time::Duration::from_secs(10))
        .build();
    let rt = match rt {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let res: Result<(), String> = rt.block_on(async {
        match cmd.as_str() {
            "init" => setup::cmd_init(&cfg_path, &args).await,
            "join" => setup::cmd_join(&cfg_path, &args).await,
            "agent" | "up" => cmd_agent(&cfg_path).await,
            "tui" => crate::tui::run(&socket_for(&cfg_path)?).await,
            "status" => cmd_status(&socket_for(&cfg_path)?).await,
            "token" => cmd_token(&cfg_path, &args).await,
            "leave" => cmd_leave(&cfg_path, &args),
            "webui" => cmd_webui(&cfg_path, &args).await,
            "pfsense" => cmd_pfsense(&cfg_path, &args).await,
            "diag" => cmd_diag(&cfg_path, &args).await,
            "update" => cmd_update(&args).await,
            "service" => cmd_service(&cfg_path, &args),
            "start" | "stop" | "restart" => cmd_start_stop(&cfg_path, &cmd),
            "ports" => cmd_ports(&cfg_path),
            "version" | "--version" | "-v" => {
                println!("meshgate {}", crate::VERSION);
                Ok(())
            }
            "help" | "-h" | "--help" => {
                print!("{}", usage());
                Ok(())
            }
            _ => {
                eprint!("unknown command {cmd:?}\n\n{}", usage());
                std::process::exit(2);
            }
        }
    });
    match res {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

/// Fails early on Linux/FreeBSD when not run as root.
fn need_root(what: &str) -> Result<(), String> {
    #[cfg(unix)]
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err(format!("{what} needs root: sudo {what}"));
    }
    let _ = what;
    Ok(())
}

fn socket_for(cfg_path: &str) -> Result<String, String> {
    match config::load(cfg_path) {
        Ok(c) => Ok(c.socket),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Err("permission denied; run as root/Administrator".into()),
        Err(_) => Ok(config::default_socket()),
    }
}

/// Runs the node until SIGINT/SIGTERM (or the Windows service stops it).
async fn cmd_agent(cfg_path: &str) -> Result<(), String> {
    crate::logx::set_std_flags(true);
    let cfg = config::load(cfg_path).map_err(|e| format!("load {cfg_path}: {} (run `meshgate init` first)", go_err(&e)))?;
    let a = crate::agent::Agent::new(cfg)?;
    #[cfg(windows)]
    if crate::winsvc::is_service() {
        return crate::winsvc::run(a).await;
    }
    a.run(shutdown_signal()).await
}

/// Go's error text for file errors ("open x: no such file or directory").
fn go_err(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::NotFound => "no such file or directory".into(),
        std::io::ErrorKind::PermissionDenied => "permission denied".into(),
        _ => e.to_string(),
    }
}

pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let (Ok(mut term), Ok(mut int)) = (signal(SignalKind::terminate()), signal(SignalKind::interrupt())) else {
            return std::future::pending().await;
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn cmd_start_stop(cfg_path: &str, cmd: &str) -> Result<(), String> {
    need_root(&format!("meshgate {cmd}"))?;
    match cmd {
        "stop" => {
            service::set(false)?;
            // The tunnel outlives a restart; stopping for good takes it down.
            let iface =
                config::load(cfg_path).ok().map(|c| c.iface).filter(|i| !i.is_empty()).unwrap_or_else(|| config::DEFAULT_IFACE.into());
            crate::wg::teardown(&iface);
            println!("meshgate stopped; it stays off after reboots until `meshgate start`.");
        }
        "start" => {
            service::set(true)?;
            println!("meshgate started; it starts at boot again.");
        }
        _ => {
            service::set(true)?;
            service::restart().map_err(|e| format!("restart: {e}"))?;
            println!("meshgate restarted.");
        }
    }
    Ok(())
}

fn cmd_service(cfg_path: &str, args: &[String]) -> Result<(), String> {
    #[cfg(windows)]
    return crate::winsvc::cmd_service(cfg_path, args);
    #[cfg(target_os = "freebsd")]
    {
        let _ = (cfg_path, args);
        return Err("on FreeBSD/pfSense the installer sets up /usr/local/etc/rc.d/meshgate.sh".into());
    }
    #[allow(unreachable_code)]
    {
        let _ = (cfg_path, args);
        Err("on Linux the installer sets up systemd: systemctl enable --now meshgate".into())
    }
}

/// Go's Duration.Round(time.Second).String().
fn ago(secs: i64) -> String {
    crate::agent::dur(secs)
}

/// A text/tabwriter table: columns padded to their widest cell plus 2.
fn table(rows: &[Vec<String>]) -> String {
    let cols = rows.iter().map(|r| r.len()).max().unwrap_or(0);
    let mut w = vec![0usize; cols];
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            if i + 1 < r.len() {
                w[i] = w[i].max(c.chars().count());
            }
        }
    }
    let mut out = String::new();
    for r in rows {
        let mut line = String::new();
        for (i, c) in r.iter().enumerate() {
            line.push_str(c);
            if i + 1 < r.len() {
                line.push_str(&" ".repeat(w[i] - c.chars().count() + 2));
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

async fn cmd_status(socket: &str) -> Result<(), String> {
    let v: View = Client::new(socket).get("view").await?;
    let names = v.names();
    let name = |id: &str| names.get(id).cloned().unwrap_or_default();
    print!("mesh {}   this node: {}", v.network.cidr, name(&v.self_id));
    if !v.runtime.home_relay.is_empty() {
        print!("   preferred relay: {}", name(&v.runtime.home_relay));
    }
    println!("\n");
    let mut rows = vec![["NAME", "KIND", "MESH IP", "PATH", "HANDSHAKE", "ENDPOINT"].map(String::from).to_vec()];
    for it in &v.nodes {
        let n = &it.value;
        let p = v.runtime.peers.get(&n.id);
        let (mut path, mut hs) = (String::new(), String::new());
        if n.id == v.self_id {
            path = "(this node)".into();
        } else if let Some(p) = p {
            path = p.path.clone();
            if let Some(r) = path.strip_prefix("via ") {
                path = format!("via {}", name(r));
            }
            hs = "never".into();
            if p.last_handshake.0 > 946_684_800 {
                hs = format!("{} ago", ago(crate::util::now_unix() - p.last_handshake.0));
            }
        }
        let mut kind = n.kind.clone();
        if n.relay {
            kind.push_str(",relay");
        }
        rows.push(vec![n.name.clone(), kind, n.mesh_ip.clone(), path, hs, p.map(|p| p.endpoint.clone()).unwrap_or_default()]);
    }
    print!("{}", table(&rows));
    if !v.forwards.is_empty() {
        println!("\nForwards:");
        for it in &v.forwards {
            let f = &it.value;
            let state = if f.enabled { "on" } else { "off" };
            println!(
                "  {:<16} {} {}:{} -> {}:{} [{state}]",
                f.name,
                f.proto,
                name(&f.edge_node),
                f.listen_port,
                name(&f.target_node),
                f.target_port
            );
        }
    }
    print_web_fps(&v.nodes, &v.self_id, &v.runtime.web_cert_fp, &v.runtime.web_ca_fp);
    for w in &v.runtime.warnings {
        println!("warning: {w}");
    }
    Ok(())
}

/// Web UI certificate fingerprints, from the local socket and the node
/// records synced over WireGuard (a man in the middle cannot change these).
fn print_web_fps(nodes: &[Item<Node>], self_id: &str, self_fp: &str, self_ca: &str) {
    let mut lines = vec![];
    for it in nodes {
        let n = &it.value;
        let (mut fp, mut ca) = (n.web_fp.clone(), n.web_ca_fp.clone());
        if n.id == self_id && !self_fp.is_empty() {
            fp = self_fp.into();
            ca = self_ca.into();
        }
        if n.webui && n.web_tls && !fp.is_empty() {
            lines.push(format!("  {:<16} {fp}", n.name));
            if !ca.is_empty() {
                lines.push(format!("  {:<16} {ca}", "  its CA"));
            }
        }
    }
    if lines.is_empty() {
        return;
    }
    println!("\nWeb UI certificates (SHA-256; the browser must show the same; CA: see meshgate webui ca):");
    for l in lines {
        println!("{l}");
    }
}

/// A QR code for the terminal (go-qrcode's ToSmallString(false)).
pub fn qr_small(text: &str, level: qrcode::EcLevel) -> Option<String> {
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), level).ok()?;
    let n = code.width();
    let colors = code.to_colors();
    let size = n + 8;
    let bit = |x: usize, y: usize| -> bool {
        if x < 4 || y < 4 || x >= n + 4 || y >= n + 4 {
            return false;
        }
        colors[(y - 4) * n + (x - 4)] == qrcode::Color::Dark
    };
    let mut out = String::new();
    let mut y = 0;
    while y + 1 < size {
        for x in 0..size {
            let (a, b) = (bit(x, y), bit(x, y + 1));
            out.push(if a == b {
                if a { ' ' } else { '█' }
            } else if a {
                '▄'
            } else {
                '▀'
            });
        }
        out.push('\n');
        y += 2;
    }
    if size % 2 == 1 {
        for x in 0..size {
            out.push(if bit(x, size - 1) { ' ' } else { '▀' });
        }
        out.push('\n');
    }
    Some(out)
}

async fn cmd_token(cfg_path: &str, args: &[String]) -> Result<(), String> {
    let mut f = Flags::new("token");
    f.str("kind", "client", "client (phone/laptop) or server")
        .int("uses", 1, "how many devices may use it (-1 = unlimited)")
        .dur("ttl", "24h", "validity (0 = forever)")
        .str("note", "", "note shown in the UI");
    f.parse(args);
    let socket = socket_for(cfg_path)?;
    let kind = f.get_str("kind");
    let body =
        serde_json::json!({"kind": kind, "uses": f.get_int("uses"), "ttl_hours": f.get_dur("ttl") / 3600, "note": f.get_str("note")});
    #[derive(serde::Deserialize, Default)]
    #[serde(default)]
    struct Out {
        token: String,
    }
    let out: Out = Client::new(&socket).post("token", &body).await?;
    if let Some(q) = qr_small(&out.token, qrcode::EcLevel::L) {
        println!("{q}");
    }
    println!("{}", out.token);
    let (linux, pfsense, windows) = crate::join::install_commands(&out.token);
    if kind == "server" {
        println!(
            "\nLinux server (shell):\n  {linux}\n\npfSense (Diagnostics > Command Prompt > Execute Shell Command):\n  {pfsense}\n\nWindows (PowerShell as Administrator):\n  {windows}"
        );
    } else {
        println!(
            "\nPhone: scan the QR code with the meshgate app.\nLinux laptop:\n  {linux} --kind client\nWindows PC (PowerShell as Administrator):\n  {windows} --kind client"
        );
    }
    Ok(())
}

fn cmd_leave(cfg_path: &str, args: &[String]) -> Result<(), String> {
    let mut f = Flags::new("leave");
    f.bool("y", false, "do not ask for confirmation");
    f.parse(args);
    let cfg = config::load(cfg_path).map_err(|e| format!("open {cfg_path}: {}", go_err(&e)))?;
    if !f.get_bool("y") {
        print!("This stops meshgate and deletes its config and keys from this machine. Continue? (y/N): ");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        if !term::read_line().trim().to_lowercase().starts_with('y') {
            return Ok(());
        }
    }
    service::stop_for_leave();
    crate::wg::teardown(&cfg.iface);
    let _ = crate::fw::remove();
    crate::hostfw::remove_all(&cfg.host_firewall_state_path());
    let _ = std::fs::remove_dir_all(&cfg.data_dir);
    let _ = std::fs::remove_file(cfg_path);
    println!("Removed. Also remove this node from the mesh in the web UI or TUI on another node.");
    Ok(())
}

async fn cmd_webui(cfg_path: &str, args: &[String]) -> Result<(), String> {
    if args.first().map(String::as_str) == Some("ca") {
        return cmd_webui_ca(cfg_path, &args[1..]);
    }
    let action = args.first().cloned().unwrap_or_default();
    if action != "enable" && action != "disable" {
        return Err("usage: meshgate webui enable [--public] [--http] | disable | ca [--pem] [--new]".into());
    }
    let mut f = Flags::new("webui");
    f.bool("public", false, "serve on all interfaces instead of localhost + mesh IP")
        .int("port", 0, "TCP port (default: 8080, or the next free one)")
        .bool("http", false, "serve plain http instead of https (self-signed certificate)")
        .str("admin-user", "admin", "admin username to create if the mesh has none")
        .str("admin-pass", "", "admin password to create if the mesh has none");
    f.parse(&args[1..]);
    let mut cfg = config::load(cfg_path).map_err(|e| format!("open {cfg_path}: {}", go_err(&e)))?;
    if !cfg.kind.is_empty() && cfg.kind != "server" {
        return Err("the web UI runs on server nodes only".into());
    }
    let api = Client::new(&cfg.socket);
    let v: View = api.get("view").await?;
    let (public, plain, port_flag) = (f.get_bool("public"), f.get_bool("http"), f.get_int("port"));
    if action == "disable" {
        cfg.web_listen.clear();
    } else {
        let mesh_ip = v.self_node().map(|n| n.mesh_ip.clone()).unwrap_or_default();
        let want = if port_flag != 0 {
            port_flag
        } else if let Some(l) = cfg.web_listen.first() {
            setup::listen_port(l) // already on: keep its port
        } else {
            model::DEFAULT_WEB_PORT
        };
        let mut got = want;
        if cfg.web_listen.is_empty() || port_flag != 0 {
            let p = crate::ports::tcp(want, &Default::default()).ok_or_else(|| format!("no free TCP port near {want}"))?;
            if p != want && port_flag != 0 {
                return Err(format!("TCP port {want} is already in use; choose another --port"));
            }
            if p != want {
                println!("TCP {want} is already in use; the web UI will use {p} instead.");
            }
            got = p;
        }
        cfg.web_listen = setup::web_listen(&mesh_ip, got, public, true);
        cfg.web_plain_http = plain;
        let pass = f.get_str("admin-pass");
        if !pass.is_empty() {
            api.post_ok("admin", &serde_json::json!({"username": f.get_str("admin-user"), "password": pass})).await?;
        }
    }
    config::save(cfg_path, &cfg).map_err(|e| e.to_string())?;
    service::restart().map_err(|e| format!("saved, but restarting meshgate failed: {e}"))?;
    if cfg.web_listen.is_empty() {
        println!("Web UI disabled on this node.");
    } else {
        println!("Web UI enabled: {}", cfg.web_listen.join(", "));
        if public {
            println!("Note: on LAN or public addresses only the certificate protects the login. Prefer the");
            println!("mesh IP (WireGuard checks the server); otherwise compare the browser's certificate");
            println!("fingerprint with `meshgate status` before typing the admin password.");
        }
        if plain {
            println!("Note: plain http sends the admin password unencrypted on any address but the mesh IP.");
        }
        println!("If this mesh has no admin login yet, rerun with --admin-pass.");
    }
    Ok(())
}

/// Shows this server's web UI CA and how to install it, prints it (--pem),
/// or replaces it (--new).
fn cmd_webui_ca(cfg_path: &str, args: &[String]) -> Result<(), String> {
    let mut f = Flags::new("webui ca");
    f.bool("pem", false, "print the CA certificate (PEM) to stdout").bool(
        "new",
        false,
        "make a new CA (devices that installed the old one must install the new one)",
    );
    f.parse(args);
    let cfg = config::load(cfg_path).map_err(|e| format!("open {cfg_path}: {}", go_err(&e)))?;
    if f.get_bool("new") {
        for p in [cfg.web_ca_cert_path(), cfg.web_ca_key_path(), cfg.web_cert_path(), cfg.web_key_path()] {
            if let Err(e) = std::fs::remove_file(&p)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                return Err(e.to_string());
            }
        }
        service::restart().map_err(|e| format!("removed the old CA, but restarting meshgate failed: {e}"))?;
        println!("Made a new web UI CA. Install it on your devices again (meshgate webui ca).");
        return Ok(());
    }
    let path = cfg.web_ca_cert_path();
    let b = std::fs::read(&path)
        .map_err(|e| format!("no web UI CA yet (it is made when the web UI starts with https): open {}: {}", path.display(), go_err(&e)))?;
    if f.get_bool("pem") {
        use std::io::Write;
        let _ = std::io::stdout().write_all(&b);
        return Ok(());
    }
    use rustls_pki_types::pem::PemObject;
    let der = rustls_pki_types::CertificateDer::from_pem_slice(&b).map_err(|_| format!("{}: not a PEM certificate", path.display()))?;
    println!(
        "Web UI CA of this server: {}
SHA-256 fingerprint: {}

Install it once on each device you open the web UI from; the browser then
trusts the web UI without a warning, and a man in the middle gets an error.
It can only vouch for this server's names and addresses and the mesh range.

Get it: from this file, \"sudo meshgate webui ca --pem > meshgate-ca.crt\", or the
web UI (Settings -> Web UI certificate) opened over the mesh IP. Before
installing, check its fingerprint matches the one above.
  Windows:  double-click it -> Install Certificate -> Local Machine ->
            \"Trusted Root Certification Authorities\"
  macOS:    open it, then in Keychain Access set it to \"Always Trust\"
  Linux:    sudo cp meshgate-ca.crt /usr/local/share/ca-certificates/ &&
            sudo update-ca-certificates  (Firefox: Settings -> Certificates -> Import)
  Android:  Settings -> Security -> Encryption & credentials -> Install a
            certificate -> CA certificate
  iPhone:   open it, install the profile in Settings, then turn it on in
            General -> About -> Certificate Trust Settings",
        path.display(),
        crate::webtls::fingerprint(&der)
    );
    Ok(())
}

/// The ports this node listens on publicly, one "proto port" per line.
fn cmd_ports(cfg_path: &str) -> Result<(), String> {
    let cfg = config::load(cfg_path).map_err(|e| format!("open {cfg_path}: {}", go_err(&e)))?;
    let s = crate::store::Store::open(Some(cfg.state_path()), &cfg.node_id)?;
    let me: Node = s.get(&model::key(model::KIND_NODE, &cfg.node_id)).unwrap_or_default();
    let wg = if me.listen_port == 0 { model::DEFAULT_WG_PORT } else { me.listen_port };
    println!("udp {wg}\nudp {}", wg + crate::probe::OFFSET);
    let p = setup::listen_port(&cfg.join_listen);
    if p != 0 {
        println!("tcp {p}");
    }
    Ok(())
}

const DIAG_USAGE: &str = "usage: meshgate diag ping <host>
       meshgate diag trace <host>
       meshgate diag tcp <host> <port>
       meshgate diag udp <host> <port>     (answers only from a meshgate test service)
       meshgate diag http <url>
       meshgate diag myip                  (public IP websites see from this node)";

/// Runs a check from this node through the agent.
async fn cmd_diag(cfg_path: &str, args: &[String]) -> Result<(), String> {
    let mut args = args.to_vec();
    if args.len() == 1 && args[0] == "myip" {
        args.push(String::new());
    }
    if args.len() < 2 {
        return Err(DIAG_USAGE.into());
    }
    let mut c = crate::diag::Check { kind: args[0].clone(), target: args[1].clone(), port: 0 };
    match c.kind.as_str() {
        "ping" | "trace" | "http" | "myip" => {}
        "tcp" | "udp" => {
            let p = args.get(2).ok_or(DIAG_USAGE)?;
            c.port = crate::gojson::atoi(p).unwrap_or(0);
        }
        _ => return Err(DIAG_USAGE.into()),
    }
    let cfg = config::load(cfg_path).map_err(|e| format!("open {cfg_path}: {}", go_err(&e)))?;
    let r: crate::diag::Outcome = Client::new(&cfg.socket).post("diag", &c).await?;
    println!("{}", r.output);
    if !r.ok {
        return Err("check failed".into());
    }
    Ok(())
}

/// Installs the latest release (checksum-verified) and restarts.
async fn cmd_update(args: &[String]) -> Result<(), String> {
    let mut f = Flags::new("update");
    f.bool("check", false, "only report whether an update is available");
    f.parse(args);
    let tag = crate::update::latest().await.map_err(|e| format!("checking for updates: {e}"))?;
    println!("installed {}, latest release {tag}", crate::VERSION);
    if !crate::update::newer(crate::VERSION, &tag) {
        println!("meshgate is up to date.");
        return Ok(());
    }
    if f.get_bool("check") {
        println!("An update is available: run `meshgate update` to install it.");
        return Ok(());
    }
    let exe = std::env::current_exe().and_then(|p| p.canonicalize()).map_err(|e| e.to_string())?;
    if !cfg!(windows) {
        need_root("meshgate update")?;
        if exe != Path::new("/usr/local/bin/meshgate") {
            println!("note: updating {}, but the service runs /usr/local/bin/meshgate", exe.display());
        }
    }
    println!("Downloading {} and verifying its checksum...", crate::update::asset());
    crate::update::install(&tag, &exe).await?;
    println!("Installed {tag}. Restarting meshgate...");
    service::restart().map_err(|e| format!("installed, but restarting meshgate failed ({e}): restart it yourself"))?;
    println!("Done.");
    Ok(())
}

/// Adds meshgate to the pfSense GUI or removes it again.
async fn cmd_pfsense(cfg_path: &str, args: &[String]) -> Result<(), String> {
    use crate::pfsense;
    if args.len() != 1 || (args[0] != "install" && args[0] != "remove") {
        return Err("usage: meshgate pfsense install | remove".into());
    }
    if !crate::fw::is_pfsense() {
        return Err("this is not pfSense".into());
    }
    let mut cfg = config::load(cfg_path).map_err(|e| format!("open {cfg_path}: {}", go_err(&e)))?;
    let api = Client::new(&cfg.socket);
    if args[0] == "remove" {
        pfsense::configure("remove")?;
        pfsense::remove_files();
        // Without the MESHGATE rules, fall back to meshgate's own lockdown.
        if let Err(e) = set_policy(&api, model::POLICY_FIREWALL, model::POLICY_RESTRICTED).await {
            println!("warning: could not reset the LAN policy: {e}");
        }
        println!("Removed VPN > meshgate and the MESHGATE interface and rules.");
        return Ok(());
    }
    if !cfg.kind.is_empty() && cfg.kind != model::NODE_SERVER {
        return Err("only server nodes can be managed from pfSense".into());
    }
    wait_agent(&api).await?;
    let mut changed = false;
    if cfg.iface != pfsense::IFACE {
        println!("Renaming the mesh interface {} -> {}.", cfg.iface, pfsense::IFACE);
        cfg.iface = pfsense::IFACE.into();
        changed = true;
    }
    // meshgate's own web UI on the mesh IP and localhost (the phone app's
    // Admin button opens it).
    if cfg.web_listen.is_empty() {
        let v: View = api.get("view").await?;
        let mesh_ip = v.self_node().map(|n| n.mesh_ip.clone()).unwrap_or_default();
        let port = crate::ports::tcp(model::DEFAULT_WEB_PORT, &Default::default());
        let (false, Some(port)) = (mesh_ip.is_empty(), port) else { return Err("cannot pick an address for the web UI".into()) };
        cfg.web_listen = setup::web_listen(&mesh_ip, port, false, true);
        changed = true;
        println!("Turning on the web UI for mesh devices (phone app Admin): https://{mesh_ip}:{port}/");
    }
    if changed {
        config::save(cfg_path, &cfg).map_err(|e| e.to_string())?;
        println!("Restarting meshgate...");
        service::restart().map_err(|e| format!("restart meshgate: {e}"))?;
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        wait_agent(&api).await?;
    }
    let first_install = !pfsense::installed();
    pfsense::write_files(&cfg.socket, crate::VERSION)?;
    let opt = pfsense::configure("install")?;
    if !first_install {
        println!("pfSense GUI pages updated; LAN policy left as it is.");
        return Ok(());
    }
    set_policy(&api, "", model::POLICY_FIREWALL).await.map_err(|e| format!("set LAN policy: {e}"))?;
    println!(
        "Added to the pfSense GUI:
  VPN > meshgate                  the meshgate dashboard (your pfSense login)
  Firewall > Rules > MESHGATE     what mesh devices may reach (interface {}, {opt})
The MESHGATE tab starts with one rule that allows everything. Replace it with
rules for the hosts and ports you want, e.g. pass TCP to 192.168.1.20 port 443.",
        pfsense::IFACE
    );
    Ok(())
}

/// Sets this node's LAN policy to want, only if it is currently from (any
/// policy when from is empty).
async fn set_policy(api: &Client, from: &str, want: &str) -> Result<(), String> {
    let v: View = api.get("view").await?;
    let me = v.self_node().ok_or("this node is not in the mesh view")?;
    if (!from.is_empty() && me.lan_policy != from) || me.lan_policy == want {
        return Ok(());
    }
    api.post_ok("node", &serde_json::json!({"id": v.self_id, "patch": {"lan_policy": want}, "scope": "cluster"})).await
}

async fn wait_agent(api: &Client) -> Result<(), String> {
    let mut err = String::new();
    for _ in 0..30 {
        match api.get::<View>("view").await {
            Ok(_) => return Ok(()),
            Err(e) => err = e,
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Err(format!("meshgate agent did not come back: {err}"))
}
