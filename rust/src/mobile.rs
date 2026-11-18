//! The phone apps' engine (Go: mobile/core): the same path selection as
//! the nodes on top of the userspace WireGuard device. The platform layer
//! (Kotlin, Swift, or the Linux phone simulator) only creates the TUN
//! device, keeps sockets outside the VPN and reports network changes.
//! Files in the app's directory are the Go core's: identity.json,
//! state.json, exit-choice, killswitch.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use crate::gojson::zero;
use crate::join::{self, Server};
use crate::meshcfg;
use crate::model::{self, Acl, Network, Node, Status};
use crate::pathsel;
use crate::probe::{self, Prober};
use crate::store::{Entry, Scope, Store};
use crate::util::SockHook;
use crate::wg::types::{WgConfig, WgPeerConfig};
use crate::wgdev;

pub const MTU: i64 = 1280;
/// The resolvers used through an exit node.
const EXIT_DNS: [&str; 2] = ["1.1.1.1", "9.9.9.9"];

/// Implemented by the app (Kotlin, Swift) or the phone simulator.
pub trait Platform: Send + Sync {
    /// Keeps a socket outside the VPN (Android VpnService.protect).
    fn protect(&self, fd: i32) -> bool;
    /// Applies TunnelSettings JSON; returns the TUN descriptor, -1 on failure.
    fn configure_tunnel(&self, settings_json: String) -> i32;
    /// This device's non-VPN IPv4 addresses, comma separated.
    fn local_addresses(&self) -> String;
    fn log(&self, msg: String);
}

/// Passed to Platform::configure_tunnel.
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
#[serde(default)]
pub struct TunnelSettings {
    pub address: String,
    pub prefix: i64,
    pub routes: Vec<String>,
    pub mtu: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<String>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
struct Identity {
    node_id: String,
    private_key: String,
    api_secret: String,
    #[serde(deserialize_with = "crate::gojson::nullable")]
    servers: Vec<Server>,
}

#[derive(Default)]
struct State {
    id: Option<Identity>,
    store: Option<Arc<Store>>,
    key: [u8; 32],
    dev: Option<wgdev::Device>,
    tun_fd: i32,
    settings: String,
    applied: HashSet<[u8; 32]>,
    last_cfg: Option<meshcfg::Config>,
    prev: Option<pathsel::Result>,
    prober: Option<Arc<Prober>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    seq: u64,
    pushed: u64,
    last_err: String,
    last_sync: i64,
}

#[derive(Default)]
struct AdminState {
    token: String,
    user: String,
    expiry: i64,
    last: String,
}

/// One device's mesh client.
pub struct Engine {
    dir: PathBuf,
    plat: Arc<dyn Platform>,
    rt: tokio::runtime::Runtime,
    st: Mutex<State>,
    admin: Mutex<AdminState>,
    kick: Notify,
    sync_kick: Notify,
}

fn e2s<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

impl Engine {
    /// Opens (or prepares) state in dir (the app's files directory or the
    /// iOS App Group container).
    pub fn new(dir: &str, plat: Arc<dyn Platform>) -> Result<Arc<Engine>, String> {
        let dir = PathBuf::from(dir);
        crate::config::secure_dir(&dir).map_err(e2s)?;
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().thread_name("meshcore").build().map_err(e2s)?;
        let e = Arc::new(Engine {
            dir,
            plat,
            rt,
            st: Mutex::new(State { tun_fd: -1, ..Default::default() }),
            admin: Mutex::new(AdminState::default()),
            kick: Notify::new(),
            sync_kick: Notify::new(),
        });
        if let Ok(b) = std::fs::read(e.id_path()) {
            let id: Identity = serde_json::from_slice(&b).map_err(e2s)?;
            let mut st = e.st.lock().unwrap();
            e.load(&mut st, id)?;
        }
        Ok(e)
    }

    fn id_path(&self) -> PathBuf {
        self.dir.join("identity.json")
    }
    fn state_path(&self) -> PathBuf {
        self.dir.join("state.json")
    }
    fn choice_path(&self) -> PathBuf {
        self.dir.join("exit-choice")
    }
    fn kill_path(&self) -> PathBuf {
        self.dir.join("killswitch")
    }

    fn load(&self, st: &mut State, id: Identity) -> Result<(), String> {
        st.key = crate::wg::parse_key(&id.private_key).ok_or("private key: invalid key")?;
        st.store = Some(Arc::new(Store::open(Some(self.state_path()), &id.node_id)?));
        st.id = Some(id);
        Ok(())
    }

    /// Protects sockets through the platform.
    fn hook(&self) -> SockHook {
        let plat = self.plat.clone();
        Arc::new(move |s: &socket2::Socket| {
            #[cfg(unix)]
            {
                use std::os::fd::AsRawFd;
                plat.protect(s.as_raw_fd());
            }
            #[cfg(not(unix))]
            let _ = (&plat, s);
            Ok(())
        })
    }

    pub fn is_joined(&self) -> bool {
        self.st.lock().unwrap().id.is_some()
    }

    /// Redeems a token (from the QR code) and stores the identity.
    pub fn join(&self, token: &str, device_name: &str) -> Result<(), String> {
        let tok = join::decode(token)?;
        let key = crate::wg::generate_private_key();
        let req = join::Request {
            name: device_name.into(),
            kind: model::NODE_CLIENT.into(),
            public_key: crate::wg::key_string(&crate::wg::public_key(&key)),
            ..Default::default()
        };
        let hook = self.hook();
        let resp = self
            .rt
            .block_on(async { tokio::time::timeout(Duration::from_secs(30), join::redeem_hooked(&tok, req, Some(&hook))).await })
            .unwrap_or_else(|_| Err("context deadline exceeded".into()))?;
        if resp.api_secret.is_empty() {
            return Err("server did not issue a sync secret (is it up to date?)".into());
        }
        let id = Identity {
            node_id: resp.node.id.clone(),
            private_key: crate::wg::key_string(&key),
            api_secret: resp.api_secret,
            servers: tok.servers,
        };
        let _ = std::fs::remove_file(self.state_path());
        crate::config::write_private(&self.id_path(), &crate::gojson::marshal_indent(&id, " ")).map_err(e2s)?;
        let mut st = self.st.lock().unwrap();
        self.load(&mut st, id)?;
        st.store.as_ref().unwrap().merge(resp.entries)?;
        Ok(())
    }

    /// Stops the tunnel and forgets the mesh.
    pub fn leave(&self) -> Result<(), String> {
        self.stop();
        let mut st = self.st.lock().unwrap();
        st.id = None;
        st.store = None;
        let _ = std::fs::remove_file(self.state_path());
        std::fs::remove_file(self.id_path()).map_err(e2s)
    }

    /// Brings the tunnel up and keeps it tuned until stop.
    pub fn start(self: &Arc<Self>) -> Result<(), String> {
        {
            let mut st = self.st.lock().unwrap();
            let Some(id) = st.id.clone() else { return Err("not joined".into()) };
            if !st.tasks.is_empty() {
                return Ok(());
            }
            let netw: Network = st.store.as_ref().unwrap().get("network/main").ok_or("no network config")?;
            let mesh = netw.prefix()?;
            st.prober = Some(Prober::new(&id.node_id, mesh, Some(self.hook())));
        }
        let _g = self.rt.enter();
        let prober = self.st.lock().unwrap().prober.clone().unwrap();
        let me = self.clone();
        let t1 = self.rt.spawn(async move {
            let _ = prober.run(move || me.probe_targets()).await;
        });
        self.st.lock().unwrap().tasks.push(t1);
        if let Err(e) = self.reconcile() {
            self.stop();
            return Err(e);
        }
        let me = self.clone();
        let t2 = self.rt.spawn(async move { me.run_loop().await });
        let me = self.clone();
        let t3 = self.rt.spawn(async move { me.sync_loop().await });
        self.st.lock().unwrap().tasks.extend([t2, t3]);
        Ok(())
    }

    /// Tears the tunnel down.
    pub fn stop(&self) {
        let mut st = self.st.lock().unwrap();
        for t in st.tasks.drain(..) {
            t.abort();
        }
        st.dev = None;
        st.tun_fd = -1;
        st.settings.clear();
        st.applied.clear();
        st.last_cfg = None;
        st.prev = None;
    }

    /// Wi-Fi/cellular changed: drop old measurements and re-probe now.
    pub fn network_changed(&self) {
        if let Some(p) = self.st.lock().unwrap().prober.clone() {
            p.forget();
        }
        self.kick.notify_one();
        self.sync_kick.notify_one();
    }

    /// Keeps paths and the tunnel up to date (no network I/O itself).
    async fn run_loop(self: Arc<Self>) {
        loop {
            let me = self.clone();
            if let Ok(Err(e)) = tokio::task::spawn_blocking(move || me.reconcile()).await {
                self.plat.log(format!("reconcile: {e}"));
            }
            tokio::select! {
                _ = tokio::time::sleep(probe::INTERVAL) => {}
                _ = self.kick.notified() => {
                    // Adapt routes to the new network first, then re-probe
                    // and decide again once the answers are in.
                    let me = self.clone();
                    let _ = tokio::task::spawn_blocking(move || me.reconcile()).await;
                    if let Some(p) = self.st.lock().unwrap().prober.clone() {
                        p.kick();
                    }
                    tokio::time::sleep(Duration::from_millis(700)).await;
                }
            }
        }
    }

    /// Exchanges state with servers in the background.
    async fn sync_loop(self: Arc<Self>) {
        loop {
            let wait = match self.sync().await {
                Ok(()) => Duration::from_secs(15),
                Err(e) => {
                    self.plat.log(format!("sync: {e}"));
                    Duration::from_secs(5)
                }
            };
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = self.sync_kick.notified() => {}
            }
        }
    }

    fn probe_targets(&self) -> Vec<probe::Target> {
        let st = self.st.lock().unwrap();
        let (Some(s), Some(id)) = (st.store.clone(), st.id.as_ref()) else { return vec![] };
        let me = id.node_id.clone();
        drop(st);
        let mut out = vec![];
        for n in s.list::<Node>(model::KIND_NODE) {
            if n.id == me || n.kind == model::NODE_STATIC {
                continue;
            }
            for ep in &n.endpoints {
                out.push(probe::Target { node_id: n.id.clone(), endpoint: ep.clone() });
            }
        }
        out
    }

    /// Our status goes up, topology changes come down, with the first
    /// server that answers.
    async fn sync(&self) -> Result<(), String> {
        let (id, s, since, pushed, home) = {
            let st = self.st.lock().unwrap();
            let Some(id) = st.id.clone() else { return Ok(()) };
            (id, st.store.clone().unwrap(), st.seq, st.pushed, st.prev.as_ref().map(|p| p.home_relay.clone()).unwrap_or_default())
        };
        let servers = servers(&s, &id, &home);
        let (mine, cur) = s.since(pushed);
        let own = model::key(model::KIND_STATUS, &id.node_id);
        let up: Vec<Entry> = mine.into_iter().filter(|e| e.key == own && e.origin == id.node_id).collect();
        let hook = self.hook();
        let mut last = String::from("no server with a join address");
        for srv in servers {
            let body = join::ClientSync { since, entries: up.clone() };
            match join::sync_client_hooked(&srv, &id.node_id, &id.api_secret, &body, Some(&hook)).await {
                Err(e) => last = e,
                Ok(mut res) => {
                    s.merge(std::mem::take(&mut res.entries))?;
                    let mut st = self.st.lock().unwrap();
                    st.pushed = cur;
                    if res.since < since {
                        res.since = 0; // server state reset; resync fully next time
                    }
                    st.seq = res.since;
                    st.last_sync = crate::util::now_unix();
                    return Ok(());
                }
            }
        }
        Err(last)
    }

    fn reconcile(&self) -> Result<(), String> {
        let mut st = self.st.lock().unwrap();
        let (Some(id), Some(prober), Some(s)) = (st.id.clone(), st.prober.clone(), st.store.clone()) else { return Ok(()) };
        let Some(mut me) = s.get::<Node>(&model::key(model::KIND_NODE, &id.node_id)) else {
            st.last_err = "this device was removed from the mesh".into();
            return Err(st.last_err.clone());
        };
        if self.kill_switch() {
            me.exit_only = true; // the phone's own kill switch adds to the admin's setting
        }
        let netw: Network = s.get("network/main").unwrap_or_default();
        let nodes: Vec<Node> = s.list(model::KIND_NODE);
        let statuses: HashMap<String, Status> = s.list::<Status>(model::KIND_STATUS).into_iter().map(|x| (x.node_id.clone(), x)).collect();
        let (probes, inbound) = prober.snapshot();
        let restarted = prober.take_restarted();
        if !restarted.is_empty() && st.dev.is_some() {
            let peers: Vec<WgPeerConfig> = nodes
                .iter()
                .filter(|n| restarted.contains(&n.id))
                .filter_map(|n| crate::wg::parse_key(&n.public_key))
                .map(|k| WgPeerConfig { public_key: k, remove: true, ..Default::default() })
                .collect();
            for p in &peers {
                st.applied.remove(&p.public_key);
            }
            let _ = st.dev.as_ref().unwrap().set(&WgConfig { peers, ..Default::default() });
            st.last_cfg = None;
        }
        let res = pathsel::decide(&pathsel::Input {
            self_: &me,
            nodes: &nodes,
            statuses: &statuses,
            probes: &probes,
            inbound: &inbound,
            prev: st.prev.as_ref(),
            now: crate::util::mono_ns(),
        });
        self.publish_status(&s, &id.node_id, &res, statuses.get(&me.id));
        st.prev = Some(res.clone());
        let local: Vec<IpAddr> = self.plat.local_addresses().split(',').filter_map(|a| a.trim().parse().ok()).collect();
        let cfg = meshcfg::build(&meshcfg::Input {
            network: netw.clone(),
            self_: me.clone(),
            nodes: nodes.clone(),
            paths: res,
            local_addrs: local,
            exit_capable: true,
            exit_choice: self.exit_choice(),
            ..Default::default()
        })?;
        let addr = cfg.address.ok_or("no address")?;
        let mut ts = TunnelSettings {
            address: addr.addr.to_string(),
            prefix: addr.bits as i64,
            routes: vec![netw.cidr.clone()],
            mtu: MTU,
            dns: vec![],
        };
        ts.routes.extend(cfg.routes.iter().map(|r| r.to_string()));
        if !cfg.exit_via.is_empty() || cfg.exit_blocked {
            ts.dns = EXIT_DNS.iter().map(|s| s.to_string()).collect();
        }
        let settings = String::from_utf8(crate::gojson::marshal(&ts)).unwrap_or_default();
        if settings != st.settings || st.dev.is_none() {
            let fd = self.plat.configure_tunnel(settings.clone());
            if fd < 0 {
                st.last_err = "could not configure the VPN interface".into();
                return Err(st.last_err.clone());
            }
            st.settings = settings;
            if fd != st.tun_fd || st.dev.is_none() {
                st.dev = None;
                #[cfg(unix)]
                let tun: Arc<dyn wgdev::Tun> = Arc::new(wgdev::FdTun::borrowed(fd, cfg!(any(target_os = "ios", target_os = "macos"))));
                #[cfg(not(unix))]
                let tun: Arc<dyn wgdev::Tun> = Err("no TUN support on this system".to_string())?;
                let dev = wgdev::Device::new(tun, Some(self.hook())).map_err(|e| format!("tun: {e}"))?;
                dev.set(&WgConfig { private_key: Some(st.key), listen_port: Some(0), ..Default::default() })?;
                st.dev = Some(dev);
                st.tun_fd = fd;
                st.applied.clear();
                st.last_cfg = None;
            }
        }
        if st.last_cfg.as_ref() != Some(&cfg) {
            let mut want = HashSet::new();
            let mut peers = vec![];
            for p in &cfg.peers {
                let Some(k) = crate::wg::parse_key(&p.public_key) else { continue };
                want.insert(k);
                let endpoint =
                    if p.endpoint.is_empty() { None } else { p.endpoint.to_socket_addrs().ok().and_then(|mut a| a.find(|x| x.is_ipv4())) };
                peers.push(WgPeerConfig {
                    public_key: k,
                    replace_allowed_ips: true,
                    endpoint,
                    keepalive: Some(p.keepalive as u16),
                    allowed_ips: p.allowed_ips.iter().map(|a| (a.addr, a.bits)).collect(),
                    ..Default::default()
                });
            }
            for k in st.applied.iter().filter(|k| !want.contains(*k)) {
                peers.push(WgPeerConfig { public_key: *k, remove: true, ..Default::default() });
            }
            if let Err(e) = st.dev.as_ref().unwrap().set(&WgConfig { peers, ..Default::default() }) {
                st.last_err = format!("wireguard: {e}");
                return Err(st.last_err.clone());
            }
            st.applied = want;
            st.last_cfg = Some(cfg);
        }
        st.last_err.clear();
        Ok(())
    }

    fn publish_status(&self, s: &Store, me: &str, res: &pathsel::Result, cur: Option<&Status>) {
        let paths: BTreeMap<String, String> =
            res.paths.iter().map(|(id, p)| (id.clone(), if p.direct() { "direct".into() } else { p.via.clone() })).collect();
        if let Some(cur) = cur
            && cur.home_relay == res.home_relay
            && cur.paths == paths
            && crate::util::now_unix() - cur.updated_at < 600
        {
            return;
        }
        let st = Status {
            node_id: me.into(),
            home_relay: res.home_relay.clone(),
            paths,
            version: "mobile".into(),
            updated_at: crate::util::now_unix(),
            ..Default::default()
        };
        let _ = s.put(&model::key(model::KIND_STATUS, me), &st, Scope::Cluster);
        self.sync_kick.notify_one(); // push the new relay choice right away
    }

    /// A check from the phone (myip, ping, tcp, udp, http) as diag::Outcome
    /// JSON. Its traffic goes through the VPN like any app's.
    pub fn diag(&self, kind: &str, target: &str, port: i64) -> String {
        let mut r = self.rt.block_on(crate::diag::run(crate::diag::Check { kind: kind.into(), target: target.into(), port }));
        if kind == "myip" && r.ok {
            r.output.push_str(&self.exit_verdict(&r.output));
        }
        String::from_utf8(crate::gojson::marshal(&r)).unwrap_or_default()
    }

    /// Whether a public-IP answer matches the exit node in use.
    fn exit_verdict(&self, out: &str) -> String {
        let st = self.st.lock().unwrap();
        let (Some(cfg), Some(s)) = (st.last_cfg.as_ref(), st.store.as_ref()) else {
            return "\nNo exit node in use: that is this phone's own network.".into();
        };
        if cfg.exit_via.is_empty() {
            return "\nNo exit node in use: that is this phone's own network.".into();
        }
        let Some(ex) = s.get::<Node>(&model::key(model::KIND_NODE, &cfg.exit_via)) else { return String::new() };
        for ep in &ex.endpoints {
            if let Ok((host, _)) = crate::netx::split_host_port(ep)
                && out.trim().ends_with(&format!(" {host}"))
            {
                return format!("\nThat is {}: your traffic leaves through the exit node.", ex.name);
            }
        }
        format!(
            "\nExit node {} is on, but that IP is not one of its addresses (its traffic may leave from another IP, or the exit is not working).",
            ex.name
        )
    }

    fn exit_choice(&self) -> String {
        std::fs::read_to_string(self.choice_path()).map(|s| s.trim().to_string()).unwrap_or_default()
    }

    /// This phone's exit node: a node ID, "off", or "" for the admin's default.
    pub fn set_exit_choice(&self, id: &str) -> Result<(), String> {
        let r = if id.is_empty() {
            match std::fs::remove_file(self.choice_path()) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
                _ => Ok(()),
            }
        } else {
            crate::config::write_private(&self.choice_path(), format!("{id}\n").as_bytes()).map_err(e2s)
        };
        self.kick.notify_one();
        r
    }

    pub fn kill_switch(&self) -> bool {
        self.kill_path().exists()
    }

    /// On: internet only through an exit node.
    pub fn set_kill_switch(&self, on: bool) -> Result<(), String> {
        let r = if on {
            crate::config::write_private(&self.kill_path(), b"on\n").map_err(e2s)
        } else {
            match std::fs::remove_file(self.kill_path()) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
                _ => Ok(()),
            }
        };
        self.kick.notify_one();
        r
    }

    /// The current state for the app UI (same JSON as the Go core).
    pub fn status_json(&self) -> String {
        let st = self.st.lock().unwrap();
        let mut out = StatusOut {
            joined: st.id.is_some(),
            running: st.dev.is_some(),
            error: st.last_err.clone(),
            last_sync: st.last_sync,
            kill_switch: self.kill_switch(),
            exit_choice: self.exit_choice(),
            ..Default::default()
        };
        let (Some(id), Some(s)) = (st.id.as_ref(), st.store.as_ref()) else {
            return String::from_utf8(crate::gojson::marshal(&out)).unwrap_or_default();
        };
        let stats: HashMap<[u8; 32], crate::wg::types::WgPeer> =
            st.dev.as_ref().map(|d| d.get().peers.into_iter().map(|p| (p.public_key, p)).collect()).unwrap_or_default();
        let nodes: Vec<Node> = s.list(model::KIND_NODE);
        let names: HashMap<&str, &str> = nodes.iter().map(|n| (n.id.as_str(), n.name.as_str())).collect();
        let name = |id: &str| names.get(id).copied().unwrap_or("").to_string();
        if let Some(p) = &st.prev {
            out.home_relay = name(&p.home_relay);
        }
        if let Some(c) = &st.last_cfg {
            out.home = c.home;
            out.exit = name(&c.exit_via);
            out.warnings = c.warnings.clone();
            out.exit_blocked = c.exit_blocked;
        }
        let me = nodes.iter().find(|n| n.id == id.node_id).cloned().unwrap_or_default();
        for n in &nodes {
            if n.exit && n.id != me.id && me.may_use_exit(&n.id) {
                let up = st.prev.as_ref().and_then(|p| p.up.as_ref()).is_some_and(|u| u.get(&n.id).copied().unwrap_or(false));
                out.exits.push(ExitOption { id: n.id.clone(), name: n.name.clone(), up });
            }
        }
        out.access = access_for(&me, &nodes, &s.list::<Acl>(model::KIND_ACL));
        for n in &nodes {
            if n.id == id.node_id {
                out.name = n.name.clone();
                out.mesh_ip = n.mesh_ip.clone();
                out.exit_wanted = name(&n.exit_via);
                out.exit_only = n.exit_only;
                continue;
            }
            if n.webui && !n.mesh_ip.is_empty() {
                let port = if n.web_port == 0 { model::DEFAULT_WEB_PORT } else { n.web_port };
                let scheme = if n.web_tls { "https" } else { "http" };
                out.admin.push(AdminLink {
                    name: n.name.clone(),
                    url: format!("{scheme}://{}/", crate::netx::join_host_port(&n.mesh_ip, port)),
                });
            }
            let mut ps = PeerStatus {
                id: n.id.clone(),
                name: n.name.clone(),
                kind: n.kind.clone(),
                mesh_ip: n.mesh_ip.clone(),
                ..Default::default()
            };
            if let Some(p) = st.prev.as_ref().and_then(|p| p.paths.get(&n.id)) {
                ps.path = if p.direct() { "direct".into() } else { format!("via {}", name(&p.via)) };
            }
            if let Some(w) = crate::wg::parse_key(&n.public_key).and_then(|k| stats.get(&k)) {
                ps.endpoint = w.endpoint.map(|e| e.to_string()).unwrap_or_default();
                ps.rx_bytes = w.rx_bytes as i64;
                ps.tx_bytes = w.tx_bytes as i64;
                ps.last_handshake = w.last_handshake.0;
            }
            out.peers.push(ps);
        }
        out.peers.sort_by(|a, b| a.name.cmp(&b.name));
        String::from_utf8(crate::gojson::marshal(&out)).unwrap_or_default()
    }

    // ------------------------------------------------------------ admin

    /// One request of the app's built-in dashboard ("/auth/login",
    /// "/api/view", ...); answers {"status","body","server"} JSON. Blocks.
    pub fn admin(&self, method: &str, path: &str, body: &str) -> String {
        let r = self.rt.block_on(self.admin1(method, path, body));
        String::from_utf8(crate::gojson::marshal(&r)).unwrap_or_default()
    }

    async fn admin1(&self, method: &str, path: &str, body: &str) -> AdminReply {
        match path {
            "/auth/me" => {
                let a = self.admin.lock().unwrap();
                let ok = !a.token.is_empty() && crate::util::now_unix() < a.expiry;
                let b = serde_json::json!({"ok": ok, "user": a.user}).to_string();
                return AdminReply { status: 200, body: b, server: String::new() };
            }
            "/auth/logout" => {
                let mut a = self.admin.lock().unwrap();
                a.token.clear();
                a.user.clear();
                return AdminReply { status: 200, body: r#"{"ok":true}"#.into(), server: String::new() };
            }
            "/auth/login" => {
                let mut r = self.admin_send("POST", "/admin/login", body, "").await;
                if r.status == 200 {
                    #[derive(Deserialize, Default)]
                    #[serde(default)]
                    struct L {
                        token: String,
                        user: String,
                        expires: i64,
                    }
                    let l: L = serde_json::from_str(&r.body).unwrap_or_default();
                    let mut a = self.admin.lock().unwrap();
                    a.token = l.token;
                    a.user = l.user;
                    a.expiry = l.expires;
                    r.body = r#"{"ok":true}"#.into();
                }
                return r;
            }
            _ => {}
        }
        let Some(rest) = path.strip_prefix("/api/") else {
            return AdminReply { status: 404, body: r#"{"error":"not found"}"#.into(), server: String::new() };
        };
        let tok = self.admin.lock().unwrap().token.clone();
        if tok.is_empty() {
            return AdminReply { status: 401, body: r#"{"error":"login required"}"#.into(), server: String::new() };
        }
        let r = self.admin_send(method, &format!("/admin/api/{rest}"), body, &tok).await;
        if r.status == 401 {
            self.admin.lock().unwrap().token.clear();
        }
        r
    }

    /// Tries the servers that answer app management, the last good first.
    async fn admin_send(&self, method: &str, path: &str, body: &str, token: &str) -> AdminReply {
        let servers = self.admin_servers();
        if servers.is_empty() {
            return AdminReply {
                status: 503,
                body: r#"{"error":"no server in this mesh accepts app management"}"#.into(),
                server: String::new(),
            };
        }
        let m = hyper::Method::from_bytes(method.as_bytes()).unwrap_or(hyper::Method::GET);
        let auth = format!("Bearer {token}");
        let mut errs = vec![];
        for n in servers {
            let addr = crate::netx::join_host_port(&n.mesh_ip, n.mesh_port_or_default());
            let mut h = vec![("Content-Type", "application/json")];
            if !token.is_empty() {
                h.push(("Authorization", auth.as_str()));
            }
            let r = crate::http::plain(&addr, m.clone(), path, &h, body.to_string().into(), Duration::from_secs(20)).await;
            match r {
                Err(_) => errs.push(format!("{}: unreachable", n.name)),
                Ok(r) if r.status == hyper::StatusCode::NOT_FOUND && path.starts_with("/admin/login") => {
                    errs.push(format!("{}: app management off or meshgate too old", n.name))
                }
                Ok(r) => {
                    self.admin.lock().unwrap().last = n.id.clone();
                    return AdminReply {
                        status: r.status.as_u16() as i64,
                        body: String::from_utf8_lossy(&r.body).into_owned(),
                        server: n.name,
                    };
                }
            }
        }
        let msg = serde_json::json!({"error": format!("no server answered ({}). Is the tunnel on?", errs.join(", "))}).to_string();
        AdminReply { status: 503, body: msg, server: String::new() }
    }

    fn admin_servers(&self) -> Vec<Node> {
        let Some(s) = self.st.lock().unwrap().store.clone() else { return vec![] };
        let last = self.admin.lock().unwrap().last.clone();
        let mut out: Vec<Node> = s
            .list::<Node>(model::KIND_NODE)
            .into_iter()
            .filter(|n| n.kind == model::NODE_SERVER && !n.mesh_ip.is_empty() && !n.app_admin_off)
            .collect();
        // Last good server first; then those hosting a web UI; then by name.
        out.sort_by(|a, b| (b.id == last).cmp(&(a.id == last)).then((b.webui).cmp(&a.webui)).then(a.name.cmp(&b.name)));
        out
    }

    /// The newest release tag if newer than the app's version, else "".
    pub fn update_available(&self, app_version: &str) -> String {
        match self.rt.block_on(crate::update::latest()) {
            Ok(tag) if crate::update::newer(app_version, &tag) => tag,
            _ => String::new(),
        }
    }

    /// Saves release tag's APK to path after checking it against SHA256SUMS.
    pub fn download_apk(&self, tag: &str, path: &str) -> Result<(), String> {
        let b = self.rt.block_on(crate::update::fetch(tag, "meshgate-android.apk"))?;
        let p = std::path::Path::new(path);
        if let Some(d) = p.parent() {
            crate::config::secure_dir(d).map_err(e2s)?;
        }
        crate::config::write_private(p, &b).map_err(e2s)
    }

    pub fn changelog(&self) -> String {
        crate::changelog::TEXT.into()
    }
}

/// Join APIs to sync with, our current relay first.
fn servers(s: &Store, id: &Identity, home: &str) -> Vec<Server> {
    let (mut first, mut rest) = (vec![], vec![]);
    let mut seen = HashSet::new();
    for n in s.list::<Node>(model::KIND_NODE) {
        if n.join_addr.is_empty() || n.join_fp.is_empty() || !seen.insert(n.join_addr.clone()) {
            continue;
        }
        let srv = Server { addr: n.join_addr.clone(), fp: n.join_fp.clone() };
        if n.id == home { first.push(srv) } else { rest.push(srv) }
    }
    for srv in &id.servers {
        if !seen.contains(&srv.addr) {
            rest.push(srv.clone());
        }
    }
    first.extend(rest);
    first
}

/// What self may reach on routers that share LANs.
fn access_for(me: &Node, nodes: &[Node], acls: &[Acl]) -> Vec<AccessLine> {
    let mut out = vec![];
    for n in nodes {
        if n.kind != model::NODE_SERVER || n.routes.is_empty() || n.id == me.id {
            continue;
        }
        if n.firewall_managed() {
            out.push(AccessLine { node: n.name.clone(), what: format!("{}: as pfSense's MESHGATE rules allow", n.routes.join(", ")) });
        } else if !n.restricted() {
            out.push(AccessLine { node: n.name.clone(), what: format!("{}: everything", n.routes.join(", ")) });
        } else {
            let mut found = false;
            for a in acls.iter().filter(|a| a.enabled && a.node == n.id) {
                let to = if a.to == model::TO_SELF { "the node itself".to_string() } else { a.to.clone() };
                let mut what = if a.proto == "both" { format!("{to} tcp+udp") } else { format!("{to} {}", a.proto) };
                if !a.ports.is_empty() {
                    what.push_str(&format!(" {}", a.ports));
                }
                out.push(AccessLine { node: n.name.clone(), what });
                found = true;
            }
            if !found {
                out.push(AccessLine { node: n.name.clone(), what: "nothing (locked down, no rule for this device)".into() });
            }
        }
    }
    out
}

#[derive(Serialize, Default)]
struct AdminReply {
    status: i64,
    body: String,
    #[serde(skip_serializing_if = "zero")]
    server: String,
}

#[derive(Serialize, Default)]
struct PeerStatus {
    id: String,
    name: String,
    kind: String,
    mesh_ip: String,
    path: String,
    #[serde(skip_serializing_if = "zero")]
    endpoint: String,
    last_handshake: i64,
    rx_bytes: i64,
    tx_bytes: i64,
}

#[derive(Serialize, Default)]
struct ExitOption {
    id: String,
    name: String,
    up: bool,
}

#[derive(Serialize, Default)]
struct AccessLine {
    node: String,
    what: String,
}

#[derive(Serialize, Default)]
struct AdminLink {
    name: String,
    url: String,
}

#[derive(Serialize, Default)]
struct StatusOut {
    joined: bool,
    running: bool,
    #[serde(skip_serializing_if = "zero")]
    name: String,
    #[serde(skip_serializing_if = "zero")]
    mesh_ip: String,
    #[serde(skip_serializing_if = "zero")]
    home_relay: String,
    last_sync: i64,
    #[serde(skip_serializing_if = "zero")]
    error: String,
    peers: Vec<PeerStatus>,
    admin: Vec<AdminLink>,
    home: bool,
    #[serde(skip_serializing_if = "zero")]
    exit: String,
    #[serde(skip_serializing_if = "zero")]
    exit_wanted: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
    #[serde(skip_serializing_if = "zero")]
    exit_blocked: bool,
    kill_switch: bool,
    exit_only: bool,
    exits: Vec<ExitOption>,
    exit_choice: String,
    access: Vec<AccessLine>,
}
