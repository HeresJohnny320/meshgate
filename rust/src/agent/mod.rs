//! Runs a meshgate node (Go: internal/agent): keeps the WireGuard
//! interface, firewall rules and HTTPS proxy in line with the replicated
//! config and live path measurements, and serves the sync, join, local and
//! web APIs.

mod events;
mod history;
mod linkwatch;
mod traffic;
mod update;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use hyper::{Method, StatusCode};

use crate::config;
use crate::fw;
use crate::hostfw;
use crate::http::{self, BoxFut, Peer, Req, Resp};
use crate::join;
use crate::meshcfg;
use crate::model::{self, ExitRoute, Forward, HttpRoute, Network, Node, Status};
use crate::ops::{self, PeerRuntime, Runtime};
use crate::pathsel;
use crate::probe::{self, Prober};
use crate::proxy::{self, Proxy};
use crate::store::{Scope, Store};
use crate::syncer::Syncer;
use crate::webtls;
use crate::webui;
use crate::wg;

pub use linkwatch::dur;
pub use update::latest_release;

#[derive(Default)]
struct AState {
    prev: Option<pathsel::Result>,
    last_wg: Option<meshcfg::Config>,
    last_fw: String,
    last_fw_at: Option<Instant>,
    last_ipt: String,
    last_host: String,
    last_host_at: Option<Instant>,
    host_err: String,
    warnings: Vec<String>,
    proxy_err: String,
    test_port: i64,
    test_task: Option<tokio::task::JoinHandle<()>>,
}

pub struct Agent {
    me: std::sync::Weak<Agent>,
    pub cfg: config::Node,
    pub store: Arc<Store>,
    wg: wg::Manager,
    prober: OnceLock<Arc<Prober>>,
    sync: Arc<Syncer>,
    proxy: Arc<Proxy>,
    pub ops: Arc<ops::Service>,
    app: Arc<webui::AppApi>,
    started_at: (i64, i64),
    started: Instant,
    st: Mutex<AState>,
    test_err: Arc<Mutex<String>>,
    web_cert: OnceLock<Arc<webtls::Cert>>,
    meters: traffic::Meters,
    hist: history::HistState,
    links: Mutex<linkwatch::LinkWatch>,
    ev: events::EventState,
}

impl Agent {
    /// Prepares an agent from the node config.
    pub fn new(cfg: config::Node) -> Result<Arc<Agent>, String> {
        let store = Arc::new(Store::open(Some(cfg.state_path()), &cfg.node_id)?);
        let key = wg::parse_key(&cfg.private_key).ok_or("private key: invalid key")?;
        let ops = ops::Service::new(store.clone(), &cfg.node_id);
        let now = crate::util::now_ms();
        let a = Arc::new_cyclic(|me| Agent {
            me: me.clone(),
            wg: wg::Manager::new(&cfg.iface, key),
            sync: Syncer::new(store.clone(), &cfg.node_id, cfg.mesh_port),
            proxy: Proxy::new(cfg.cert_magic_dir()),
            app: webui::AppApi::new(ops.clone()),
            ops,
            store,
            prober: OnceLock::new(),
            started_at: (now / 1000, (now % 1000) * 1_000_000),
            started: Instant::now(),
            st: Mutex::new(AState::default()),
            test_err: Arc::new(Mutex::new(String::new())),
            web_cert: OnceLock::new(),
            meters: Default::default(),
            hist: history::HistState::new(&cfg.data_dir),
            links: Mutex::new(Default::default()),
            ev: events::EventState::new(&cfg.node_id, &cfg.data_dir),
            cfg,
        });
        let _ = a.ops.backend.set(a.clone() as Arc<dyn ops::Backend>);
        a.capture_log();
        Ok(a)
    }

    fn self_node(&self) -> Result<Node, String> {
        self.store
            .get(&model::key(model::KIND_NODE, &self.cfg.node_id))
            .ok_or_else(|| "this node is not registered in the mesh (removed?)".to_string())
    }

    fn network(&self) -> Network {
        self.store.get("network/main").unwrap_or_default()
    }

    fn prober(&self) -> &Arc<Prober> {
        self.prober.get().expect("prober started")
    }

    /// Runs until shutdown resolves. The kernel tunnel outlives this
    /// process: a restart or update does not interrupt traffic.
    pub async fn run(self: Arc<Self>, shutdown: impl std::future::Future<Output = ()>) -> Result<(), String> {
        let me = self.self_node()?;
        let netw: Network = self.store.get("network/main").ok_or("no network config; run `meshgate init` or `meshgate join`")?;
        let mesh = netw.prefix()?;
        {
            let a = self.clone();
            tokio::task::spawn_blocking(move || a.wg.up(a.cfg.userspace))
                .await
                .map_err(|e| e.to_string())?
                .map_err(|e| format!("wireguard: {e}"))?;
        }
        if me.kind == model::NODE_SERVER {
            wg::enable_forwarding();
            self.sync_self(&me);
        }
        let (mut nat, mut rdr, mut filter) = (String::new(), String::new(), String::new());
        if cfg!(target_os = "freebsd") && fw::is_pfsense() {
            rdr = fw::DEFAULT_PFSENSE_RDR_ANCHOR.into();
        }
        if !self.cfg.pf_nat_anchor.is_empty() {
            nat = self.cfg.pf_nat_anchor.clone();
        }
        if !self.cfg.pf_rdr_anchor.is_empty() {
            rdr = self.cfg.pf_rdr_anchor.clone();
        }
        if !self.cfg.pf_filter_anchor.is_empty() {
            filter = self.cfg.pf_filter_anchor.clone();
        }
        fw::set_pf_anchors(&nat, &rdr, &filter);
        logf!("meshgate {}: node {} ({}) mesh ip {}", crate::VERSION, me.name, me.kind, me.mesh_ip);

        #[cfg(target_os = "linux")]
        let control: Option<probe::Control> = Some(Arc::new(wg::mark_socket));
        #[cfg(not(target_os = "linux"))]
        let control: Option<probe::Control> = None;
        let prober = Prober::new(&self.cfg.node_id, mesh, control);
        prober.set_boot_id(&self.tunnel_id(self.wg.is_created()));
        let _ = self.prober.set(prober.clone());
        let listen = if me.listen_port == 0 { model::DEFAULT_WG_PORT } else { me.listen_port };
        let probe_port = (listen + probe::OFFSET) as u16;
        let mut tasks: Vec<tokio::task::JoinHandle<()>> = vec![];
        let p = prober.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                if let Err(e) = p.clone().serve(probe_port).await {
                    logf!("probe server: {e} (retrying)");
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }));
        let a = self.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = prober.run(move || a.probe_targets()).await {
                logf!("probe: {e}");
            }
        }));
        tasks.push(tokio::spawn(self.clone().events_loop()));

        self.clone().reconcile_async().await; // brings up the mesh address before we bind to it

        let mesh_addr = crate::netx::join_host_port(&me.mesh_ip, self.cfg.mesh_port);
        let a = self.clone();
        let mesh_h: Arc<dyn http::Handler> = Arc::new(move |r: Req, p: Peer| a.clone().serve_mesh(r, p));
        tasks.push(tokio::spawn(serve_retry(mesh_addr, None, mesh_h)));
        tasks.push(tokio::spawn(self.clone().serve_local()));
        if me.kind == model::NODE_SERVER && !self.cfg.join_listen.is_empty() {
            match join::ensure_cert(&self.cfg.cert_path(), &self.cfg.key_path()) {
                Ok((kp, _)) => {
                    let tls = std::sync::Arc::new({
                        let mut c = rustls::ServerConfig::builder_with_provider(crate::tlsx::provider())
                            .with_protocol_versions(&[&rustls::version::TLS13])
                            .map_err(|e| e.to_string())?
                            .with_no_client_auth()
                            .with_single_cert(kp.chain, kp.key)
                            .map_err(|e| e.to_string())?;
                        c.alpn_protocols = vec![b"http/1.1".to_vec()];
                        c
                    });
                    let st = self.store.clone();
                    let h: Arc<dyn http::Handler> = Arc::new(move |r: Req, _p: Peer| {
                        let st = st.clone();
                        async move { join::handle(&st, r).await.unwrap_or_else(http::not_found) }
                    });
                    tasks.push(tokio::spawn(serve_retry(self.cfg.join_listen.clone(), Some(tokio_rustls::TlsAcceptor::from(tls)), h)));
                }
                Err(e) => logf!("join api: {e}"),
            }
        }
        if me.kind == model::NODE_SERVER {
            let mut cert = None;
            if !self.cfg.web_listen.is_empty() && !self.cfg.web_plain_http {
                let name = me.name.to_lowercase();
                let c = webtls::Cert::new(
                    self.cfg.web_cert_path(),
                    self.cfg.web_key_path(),
                    self.cfg.web_ca_cert_path(),
                    self.cfg.web_ca_key_path(),
                    &me.name,
                    webtls::hosts(&self.cfg.web_listen, &[&me.mesh_ip, &name]),
                    Some(mesh),
                );
                c.refresh(crate::util::now_unix()).map_err(|e| format!("web UI certificate: {e}"))?;
                logf!("web ui: https, certificate fingerprint (SHA-256) {}, CA {}", c.fingerprint(), c.ca_fingerprint());
                let _ = self.web_cert.set(c.clone());
                self.sync_self_now();
                let a = self.clone();
                tasks.push(tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_secs(12 * 3600)).await;
                        if let Err(e) = c.refresh(crate::util::now_unix()) {
                            logf!("web ui certificate: {e}");
                        }
                        a.sync_self_now();
                    }
                }));
                cert = self.web_cert.get().cloned();
            }
            let ui = webui::Ui::new(self.ops.clone(), cert.clone());
            for addr in self.cfg.web_listen.clone() {
                let ui = ui.clone();
                let h: Arc<dyn http::Handler> = Arc::new(move |r: Req, p: Peer| ui.clone().handle(r, p));
                let tls = cert.as_ref().map(|c| tokio_rustls::TlsAcceptor::from(c.tls_config()));
                tasks.push(tokio::spawn(serve_mixed_retry(addr, tls, h)));
            }
        }
        tasks.push(tokio::spawn(self.sync.clone().run()));
        if me.kind == model::NODE_SERVER {
            tasks.push(tokio::spawn(self.clone().traffic_loop()));
            tasks.push(tokio::spawn(update::latest_loop()));
        }
        if cfg!(target_os = "freebsd") && fw::is_pfsense() && crate::pfsense::installed() {
            // After an update: bring VPN > meshgate's pages to this version.
            if let Err(e) = crate::pfsense::write_files(&self.cfg.socket, crate::VERSION) {
                logf!("pfsense gui: {e}");
            }
        }

        let mut changes = self.store.subscribe();
        let mut tick = tokio::time::interval(probe::INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                _ = changes.changed() => self.clone().reconcile_async().await,
                _ = tick.tick() => self.clone().reconcile_async().await,
            }
        }
        logf!("stopping");
        for t in tasks {
            t.abort();
        }
        let a = self.clone();
        let _ = tokio::task::spawn_blocking(move || {
            a.flush_events();
            a.wg.release();
        })
        .await;
        Ok(())
    }

    fn probe_targets(&self) -> Vec<probe::Target> {
        let mut out = vec![];
        for n in self.store.list::<Node>(model::KIND_NODE) {
            if n.id == self.cfg.node_id || n.kind == model::NODE_STATIC {
                continue;
            }
            for ep in &n.endpoints {
                out.push(probe::Target { node_id: n.id.clone(), endpoint: ep.clone() });
            }
        }
        out
    }

    async fn reconcile_async(self: Arc<Self>) {
        let a = self.clone();
        let _ = tokio::task::spawn_blocking(move || a.reconcile()).await;
    }

    /// Recomputes paths and applies WireGuard, firewall and proxy.
    fn reconcile(self: &Arc<Self>) {
        let mut st = self.st.lock().unwrap();
        let mut warn: Vec<String> = vec![];
        let me = match self.self_node() {
            Ok(n) => n,
            Err(e) => {
                st.warnings = vec![e];
                return;
            }
        };
        let netw = self.network();
        let nodes: Vec<Node> = self.store.list(model::KIND_NODE);
        let forwards: Vec<Forward> = self.store.list(model::KIND_FORWARD);
        let statuses: HashMap<String, Status> =
            self.store.list::<Status>(model::KIND_STATUS).into_iter().map(|s| (s.node_id.clone(), s)).collect();
        let prober = self.prober();
        let (probes, inbound) = prober.snapshot();
        let restarted = prober.take_restarted();
        if !restarted.is_empty() {
            let mut keys = vec![];
            for n in &nodes {
                if restarted.contains(&n.id) {
                    keys.push(n.public_key.clone());
                    logf!("peer {} restarted; re-handshaking", n.name);
                }
            }
            if let Err(e) = self.wg.reset_peers(&keys) {
                logf!("reset peers: {e}");
            }
            st.last_wg = None;
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
        self.publish_status(&res, statuses.get(&me.id));
        st.prev = Some(res.clone());

        let exit_routes: Vec<ExitRoute> = self.store.list(model::KIND_EXIT_ROUTE);
        let cfg = match meshcfg::build(&meshcfg::Input {
            network: netw.clone(),
            self_: me.clone(),
            nodes: nodes.clone(),
            forwards: forwards.clone(),
            paths: res.clone(),
            local_addrs: wg::local_addrs(&self.cfg.iface),
            lan_exit_capable: cfg!(any(target_os = "linux", target_os = "freebsd")),
            exit_routes: &exit_routes,
            ..Default::default()
        }) {
            Ok(c) => c,
            Err(e) => {
                st.warnings = vec![e];
                return;
            }
        };
        warn.extend(cfg.warnings.iter().cloned());
        match self.wg.ensure(self.cfg.userspace) {
            Err(e) => warn.push(format!("wireguard interface: {e}")),
            Ok(true) => {
                logf!("wg: interface {} was removed by something else; recreated it", self.cfg.iface);
                st.last_wg = None;
                st.last_fw.clear();
                prober.set_boot_id(&self.tunnel_id(true)); // peers: our sessions are gone
            }
            Ok(false) => {}
        }
        self.wg.sync_underlay();
        if st.last_wg.as_ref() != Some(&cfg) {
            match self.wg.apply(&cfg) {
                Err(e) => warn.push(format!("wireguard: {e}")),
                Ok(()) => st.last_wg = Some(cfg.clone()),
            }
        }

        if me.kind == model::NODE_SERVER {
            let listen = if me.listen_port == 0 { model::DEFAULT_WG_PORT } else { me.listen_port };
            let routes: Vec<HttpRoute> = self.store.list(model::KIND_ROUTE);
            let plan = fw::build(&fw::Input {
                iface: self.cfg.iface.clone(),
                network: netw.clone(),
                self_: me.clone(),
                nodes: nodes.clone(),
                forwards,
                routes,
                acls: self.store.list(model::KIND_ACL),
                monitors: self.store.list(model::KIND_MONITOR),
                preserve_edge: cfg.default_via_peer.clone(),
                wg_port: listen,
                probe_port: listen + probe::OFFSET,
                mesh_port: self.cfg.mesh_port,
                join_port: join_port(&self.cfg.join_listen),
                web_port: self.cfg.web_listen.first().map(|a| join_port(a)).unwrap_or(0),
                wan_iface: fw::detect_wan(),
                test_port: me.test_port,
                lan_exit_srcs: cfg.lan_exit_srcs.iter().map(|p| p.to_string()).collect(),
                lan_exit_gw: nodes.iter().find(|n| n.id == cfg.lan_exit_via).map(|n| n.mesh_ip.clone()).unwrap_or_default(),
                lan_exit_block: cfg.lan_exit_block.iter().map(|p| p.to_string()).collect(),
                exit_routes: exit_routes.clone(),
            });
            warn.extend(plan.warnings.iter().cloned());
            if cfg!(any(windows, target_os = "macos"))
                && (!plan.dnat.is_empty() || !plan.lans.is_empty() || plan.restricted || !plan.preserve_edge_ip.is_empty())
            {
                let os = if cfg!(windows) { "Windows" } else { "macOS" };
                warn.push(format!("{os} nodes cannot be a forward edge, share LAN subnets, enforce a restricted LAN policy or receive real client IPs; use Linux or pfSense for that"));
            }
            for l in &plan.lans {
                if l.iface.is_empty() && cfg!(target_os = "freebsd") {
                    warn.push(format!("shared subnet {} is not on any local interface", l.cidr));
                }
            }
            let script = fw::render(&plan);
            // Reload on change, and once a minute in case something flushed it.
            let ipt = plan.iptables_rules();
            let ipt_key = format!("{} {:?}", me.iptables_off, ipt);
            if script != st.last_fw || ipt_key != st.last_ipt || st.last_fw_at.is_none_or(|t| t.elapsed() > Duration::from_secs(60)) {
                self.read_traffic(); // reloading restarts the counters; keep what they hold
                if me.iptables_off {
                    fw::remove_iptables();
                }
                match fw::load(&script) {
                    Err(e) => warn.push(format!("firewall: {e}")),
                    Ok(()) => {
                        if !me.iptables_off
                            && let Err(e) = fw::sync_iptables(&ipt)
                        {
                            warn.push(format!("firewall (iptables FORWARD): {e}"));
                        }
                        st.last_fw = script;
                        st.last_fw_at = Some(Instant::now());
                        st.last_ipt = ipt_key;
                    }
                }
            }
            // Open what this node needs in ufw/firewalld; re-checked every minute.
            let host_rules = hostfw::wanted(&plan);
            let host_key = format!("{} {:?}", me.host_firewall_off, host_rules);
            if host_key != st.last_host || st.last_host_at.is_none_or(|t| t.elapsed() > Duration::from_secs(60)) {
                st.host_err =
                    hostfw::sync(&self.cfg.host_firewall_state_path(), &host_rules, me.host_firewall_off).err().unwrap_or_default();
                st.last_host = host_key;
                st.last_host_at = Some(Instant::now());
            }
            if !st.host_err.is_empty() {
                warn.push(format!("host firewall (ufw/firewalld): {}", st.host_err));
            }
            self.update_proxy(&mut st, &netw, &nodes);
            self.update_test(&mut st, &me);
        }
        let terr = self.test_err.lock().unwrap().clone();
        if !terr.is_empty() {
            warn.push(format!("test service: {terr}"));
        }
        if !st.proxy_err.is_empty() {
            warn.push(format!("https proxy: {}", st.proxy_err));
        }
        self.watch_links(&nodes, &res, &warn);
        st.warnings = warn;
    }

    fn publish_status(&self, res: &pathsel::Result, cur: Option<&Status>) {
        let paths: std::collections::BTreeMap<String, String> =
            res.paths.iter().map(|(id, p)| (id.clone(), if p.direct() { "direct".to_string() } else { p.via.clone() })).collect();
        let mut lans = fw::local_lans(&self.cfg.iface);
        if fw::is_pfsense() {
            // Offer LAN/VLAN interfaces as rule targets, not the WAN.
            let wan = fw::detect_wan();
            lans.retain(|l| l.iface != wan);
        }
        if let Some(cur) = cur
            && cur.home_relay == res.home_relay
            && cur.paths == paths
            && cur.version == crate::VERSION
            && cur.lans == lans
            && crate::util::now_unix() - cur.updated_at < 600
        {
            return;
        }
        let st = Status {
            node_id: self.cfg.node_id.clone(),
            home_relay: res.home_relay.clone(),
            paths,
            version: crate::VERSION.into(),
            lans,
            os: crate::update::goos().into(),
            updated_at: crate::util::now_unix(),
        };
        if let Err(e) = self.store.put(&model::key(model::KIND_STATUS, &self.cfg.node_id), &st, Scope::Cluster) {
            logf!("status: {e}");
        }
    }

    /// Keeps this node's record in line with its local config.
    fn sync_self(&self, me: &Node) {
        let want = !self.cfg.web_listen.is_empty();
        let port = self.cfg.web_listen.first().map(|a| join_port(a)).unwrap_or(0);
        let web_tls = want && !self.cfg.web_plain_http;
        let (web_fp, ca_fp) = match self.web_cert.get() {
            Some(c) => (c.fingerprint(), c.ca_fingerprint()),
            None if web_tls => (me.web_fp.clone(), me.web_ca_fp.clone()),
            None => (String::new(), String::new()),
        };
        if me.webui == want
            && me.web_port == port
            && me.mesh_port == self.cfg.mesh_port
            && me.web_tls == web_tls
            && me.web_fp == web_fp
            && me.web_ca_fp == ca_fp
        {
            return;
        }
        if me.kind != model::NODE_SERVER {
            return;
        }
        let mut n = me.clone();
        n.webui = want;
        n.web_port = port;
        n.mesh_port = self.cfg.mesh_port;
        n.web_tls = web_tls;
        n.web_fp = web_fp;
        n.web_ca_fp = ca_fp;
        if let Err(e) = self.store.put(&model::key(model::KIND_NODE, &n.id), &n, Scope::Cluster) {
            logf!("update self: {e}");
        }
    }

    fn sync_self_now(&self) {
        if let Ok(me) = self.self_node()
            && me.kind == model::NODE_SERVER
        {
            self.sync_self(&me);
        }
    }

    /// Starts, moves or stops the test service to match self.test_port.
    fn update_test(&self, st: &mut AState, me: &Node) {
        if me.test_port == st.test_port {
            return;
        }
        if let Some(t) = st.test_task.take() {
            t.abort();
        }
        st.test_port = me.test_port;
        self.test_err.lock().unwrap().clear();
        if me.test_port == 0 {
            return;
        }
        let (port, name, err) = (me.test_port as u16, me.name.clone(), self.test_err.clone());
        st.test_task = Some(tokio::runtime::Handle::current().spawn(async move {
            logf!("test service on port {port} (tcp+udp)");
            if let Err(e) = crate::diag::serve(port, name).await {
                logf!("test service: {e}");
                *err.lock().unwrap() = e;
            }
        }));
    }

    fn update_proxy(&self, st: &mut AState, netw: &Network, nodes: &[Node]) {
        let by_id: HashMap<&str, &Node> = nodes.iter().map(|n| (n.id.as_str(), n)).collect();
        let mut routes = vec![];
        for r in self.store.list::<HttpRoute>(model::KIND_ROUTE) {
            if r.edge_node != self.cfg.node_id {
                continue;
            }
            let Some(t) = by_id.get(r.target_node.as_str()) else { continue };
            let host = if r.target_ip.is_empty() { t.mesh_ip.clone() } else { r.target_ip.clone() };
            let scheme = if r.target_tls { "https" } else { "http" };
            routes.push(proxy::Route {
                hostname: r.hostname.clone(),
                target: format!("{scheme}://{}", crate::netx::join_host_port(&host, r.target_port)),
                force_https: r.force_https,
                disabled: !r.enabled,
            });
        }
        let p = self.proxy.clone();
        let email = netw.acme_email.clone();
        st.proxy_err = tokio::runtime::Handle::current().block_on(p.update(routes, &email)).err().unwrap_or_default();
    }

    /// Live state for the UIs.
    pub fn runtime(&self) -> Runtime {
        let (prev, mut warnings, cfg) = {
            let st = self.st.lock().unwrap();
            (st.prev.clone(), st.warnings.clone(), st.last_wg.clone())
        };
        let mut rt = Runtime {
            last_sync: self.sync.last_contact().into_iter().collect(),
            userspace: self.wg.is_userspace(),
            started_at: self.started_at,
            latest: latest_release(),
            ..Default::default()
        };
        if let Some(c) = self.web_cert.get() {
            rt.web_cert_fp = c.fingerprint();
            rt.web_ca_fp = c.ca_fingerprint();
            let sk = c.skipped();
            if !sk.is_empty() {
                warnings.push(format!(
                    "web UI certificate leaves out {} (newer than this server's CA): `sudo meshgate webui ca --new`, then install the new CA",
                    sk.join(", ")
                ));
            }
        }
        rt.warnings = warnings;
        let stats = self.wg.stats();
        if let Some(p) = &prev {
            rt.home_relay = p.home_relay.clone();
        }
        if let Some(cfg) = cfg {
            for p in cfg.peers {
                let mut pr = PeerRuntime::default();
                if let Some(prev) = &prev {
                    let path = prev.paths.get(&p.node_id).cloned().unwrap_or_default();
                    pr.path = if path.direct() { "direct".into() } else { format!("via {}", path.via) };
                }
                if let Some(s) = stats.get(&p.public_key) {
                    pr.endpoint = s.endpoint.clone();
                    pr.last_handshake = s.last_handshake;
                    pr.rx_bytes = s.rx_bytes;
                    pr.tx_bytes = s.tx_bytes;
                }
                rt.peers.insert(p.node_id, pr);
            }
        }
        rt
    }

    /// The mesh API: sync, traffic, updates, history, events, raw log and
    /// the phone app's management API.
    async fn serve_mesh(self: Arc<Self>, req: Req, peer: Peer) -> Resp {
        let path = req.uri().path().to_string();
        let m = req.method().clone();
        let get = m == Method::GET || m == Method::HEAD;
        match path.as_str() {
            "/v1/ping" | "/v1/sync" => return self.sync.handle(req, peer).await.unwrap_or_else(http::not_found),
            "/v1/traffic" if !get => return http::method_not_allowed(),
            "/v1/traffic" => return self.serve_traffic(peer),
            "/v1/update" if m != Method::POST => return http::method_not_allowed(),
            "/v1/update" => return self.serve_update(peer),
            "/v1/history" => return self.serve_history(req, peer).await,
            "/v1/history/import" if m != Method::POST => return http::method_not_allowed(),
            "/v1/history/import" => return self.serve_history_import(req, peer).await,
            "/v1/events" => return self.serve_events(req, peer).await,
            "/v1/rawlog" if !get => return http::method_not_allowed(),
            "/v1/rawlog" => return self.serve_raw_log(req, peer).await,
            _ => {}
        }
        let off = self.self_node().map(|n| n.app_admin_off).unwrap_or(true);
        if let Some(r) = self.app.handle(req, peer, off).await {
            return r;
        }
        http::not_found()
    }

    /// The mesh server making a request, or the 403 to send.
    fn server_caller(&self, peer: &Peer) -> Result<Node, Box<Resp>> {
        let ip = peer.addr.map(|a| a.ip().to_string()).unwrap_or_default();
        self.store
            .list::<Node>(model::KIND_NODE)
            .into_iter()
            .find(|n| n.mesh_ip == ip && n.kind == model::NODE_SERVER)
            .ok_or_else(|| Box::new(http::error(StatusCode::FORBIDDEN, "only servers")))
    }

    fn mesh_addr(n: &Node) -> String {
        crate::netx::join_host_port(&n.mesh_ip, n.mesh_port_or_default())
    }

    /// The local API on the unix socket (CLI, TUI, pfSense pages).
    async fn serve_local(self: Arc<Self>) {
        let ops = self.ops.clone();
        let h: Arc<dyn http::Handler> = Arc::new(move |r: Req, _p: Peer| {
            let ops = ops.clone();
            async move {
                if r.uri().path() == "/v1/qr" && r.method() == Method::POST {
                    return webui::qr(r).await;
                }
                ops.handle("/v1/", r).await.unwrap_or_else(http::not_found)
            }
        });
        if let Err(e) = crate::localapi::serve(&self.cfg.socket, h).await {
            logf!("local api: {e}");
        }
    }
}

impl ops::Backend for Agent {
    fn runtime(&self) -> Runtime {
        Agent::runtime(self)
    }
    fn traffic(&self) -> BoxFut<Vec<crate::traffic::Node>> {
        let a = self.arc();
        Box::pin(async move { a.traffic().await })
    }
    fn history(&self, q: String) -> BoxFut<Result<Vec<u8>, String>> {
        let a = self.arc();
        Box::pin(async move { a.history(&q).await })
    }
    fn events(&self, q: String) -> BoxFut<Result<Vec<u8>, String>> {
        let a = self.arc();
        Box::pin(async move { a.events(&q).await })
    }
    fn rawlog(&self, node: String, n: i64) -> BoxFut<Result<Vec<u8>, String>> {
        let a = self.arc();
        Box::pin(async move { a.raw_log(&node, n).await })
    }
    fn update(&self, node: String) -> BoxFut<Result<String, String>> {
        let a = self.arc();
        Box::pin(async move { a.update(&node).await })
    }
}

impl Agent {
    /// The Arc this agent lives in.
    fn arc(&self) -> Arc<Agent> {
        self.me.upgrade().expect("agent alive")
    }
}

fn join_port(listen: &str) -> i64 {
    crate::netx::split_host_port(listen).ok().and_then(|(_, p)| p.parse().ok()).unwrap_or(0)
}

/// Serves on addr, retrying while the address is not yet available (the
/// mesh IP appears once WireGuard is configured).
async fn serve_retry(addr: String, tls: Option<tokio_rustls::TlsAcceptor>, h: Arc<dyn http::Handler>) {
    let l = loop {
        match http::listen(&addr).await {
            Ok(l) => break l,
            Err(_) => tokio::time::sleep(Duration::from_secs(2)).await,
        }
    };
    http::serve(l, tls, h).await;
}

/// HTTPS and plain HTTP on the same port (a TLS handshake starts with
/// 0x16); plain requests get redirected by the web UI.
async fn serve_mixed_retry(addr: String, tls: Option<tokio_rustls::TlsAcceptor>, h: Arc<dyn http::Handler>) {
    let Some(acc) = tls else { return serve_retry(addr, None, h).await };
    let l = loop {
        match http::listen(&addr).await {
            Ok(l) => break l,
            Err(_) => tokio::time::sleep(Duration::from_secs(2)).await,
        }
    };
    loop {
        let Ok((c, from)) = l.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let (h, acc) = (h.clone(), acc.clone());
        tokio::spawn(async move {
            let mut b = [0u8; 1];
            let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(10), c.peek(&mut b)).await else { return };
            if n == 0 {
                return;
            }
            let _ = c.set_nodelay(true);
            if b[0] == 0x16 {
                if let Ok(Ok(s)) = tokio::time::timeout(Duration::from_secs(10), acc.accept(c)).await {
                    http::serve_conn(s, h, Peer { addr: Some(from), tls: true }).await;
                }
            } else {
                http::serve_conn(c, h, Peer { addr: Some(from), tls: false }).await;
            }
        });
    }
}
