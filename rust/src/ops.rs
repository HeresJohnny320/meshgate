//! The admin API shared by the TUI/CLI (local socket, /v1/) and the web UI
//! (/api/) and phone app (/admin/api/) (Go: internal/ops). Same paths, same
//! JSON. Changes with scope "cluster" replicate; "local" stays here.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use hyper::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::gojson::{nullable, zero};
use crate::http::{self, BoxFut, Req, Resp};
use crate::join;
use crate::model::{self, Acl, ExitRoute, Forward, HttpRoute, LanExit, Monitor, Network, Node, Status, Token};
use crate::netx;
use crate::store::{Scope, Store};
use crate::traffic;

/// Live data about one peer.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PeerRuntime {
    pub path: String,
    #[serde(skip_serializing_if = "zero")]
    pub endpoint: String,
    #[serde(serialize_with = "crate::util::ser_go_time", deserialize_with = "crate::util::de_go_time")]
    pub last_handshake: (i64, i64),
    pub rx_bytes: i64,
    pub tx_bytes: i64,
}

fn ser_time_map<S: serde::Serializer>(m: &BTreeMap<String, (i64, i64)>, s: S) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    let mut mm = s.serialize_map(Some(m.len()))?;
    for (k, v) in m {
        mm.serialize_entry(k, &crate::util::go_time(v.0, v.1))?;
    }
    mm.end()
}

fn de_time_map<'de, D: serde::Deserializer<'de>>(d: D) -> Result<BTreeMap<String, (i64, i64)>, D::Error> {
    let m: Option<BTreeMap<String, String>> = Deserialize::deserialize(d)?;
    Ok(m.unwrap_or_default().into_iter().filter_map(|(k, v)| crate::util::parse_go_time(&v).map(|t| (k, t))).collect())
}

/// What the agent reports.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Runtime {
    #[serde(skip_serializing_if = "zero")]
    pub home_relay: String,
    #[serde(deserialize_with = "nullable")]
    pub peers: BTreeMap<String, PeerRuntime>,
    #[serde(serialize_with = "ser_time_map", deserialize_with = "de_time_map")]
    pub last_sync: BTreeMap<String, (i64, i64)>,
    #[serde(deserialize_with = "nullable")]
    pub warnings: Vec<String>,
    pub userspace: bool,
    #[serde(serialize_with = "crate::util::ser_go_time", deserialize_with = "crate::util::de_go_time")]
    pub started_at: (i64, i64),
    #[serde(skip_serializing_if = "zero")]
    pub proxy_error: String,
    #[serde(skip_serializing_if = "zero")]
    pub latest: String,
    #[serde(skip_serializing_if = "zero")]
    pub web_cert_fp: String,
    #[serde(skip_serializing_if = "zero")]
    pub web_ca_fp: String,
}

/// What the agent provides to the API (absent in tests and on clients).
pub trait Backend: Send + Sync {
    fn runtime(&self) -> Runtime;
    fn traffic(&self) -> BoxFut<Vec<traffic::Node>>;
    /// JSON answers.
    fn history(&self, query: String) -> BoxFut<Result<Vec<u8>, String>>;
    fn events(&self, query: String) -> BoxFut<Result<Vec<u8>, String>>;
    fn rawlog(&self, node: String, lines: i64) -> BoxFut<Result<Vec<u8>, String>>;
    fn update(&self, node: String) -> BoxFut<Result<String, String>>;
}

pub struct Service {
    pub store: Arc<Store>,
    pub self_id: String,
    pub backend: OnceLock<Arc<dyn Backend>>,
}

/// A record with its local-override flag.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Item<T: Default> {
    pub value: T,
    pub local: bool,
}

/// Everything a UI needs to render.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct View {
    pub self_id: String,
    pub network: Network,
    #[serde(deserialize_with = "nullable")]
    pub nodes: Vec<Item<Node>>,
    #[serde(deserialize_with = "nullable")]
    pub forwards: Vec<Item<Forward>>,
    #[serde(deserialize_with = "nullable")]
    pub routes: Vec<Item<HttpRoute>>,
    #[serde(deserialize_with = "nullable")]
    pub acls: Vec<Item<Acl>>,
    #[serde(deserialize_with = "nullable")]
    pub exit_routes: Vec<Item<ExitRoute>>,
    #[serde(deserialize_with = "nullable")]
    pub monitors: Vec<Item<Monitor>>,
    #[serde(deserialize_with = "nullable")]
    pub tokens: Vec<Token>,
    #[serde(deserialize_with = "nullable")]
    pub statuses: BTreeMap<String, Status>,
    pub runtime: Runtime,
}

impl View {
    /// Node names by ID.
    pub fn names(&self) -> BTreeMap<String, String> {
        self.nodes.iter().map(|n| (n.value.id.clone(), n.value.name.clone())).collect()
    }

    pub fn self_node(&self) -> Option<&Node> {
        self.nodes.iter().map(|n| &n.value).find(|n| n.id == self.self_id)
    }
}

/// The editable part of a node.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NodePatch {
    pub name: Option<String>,
    pub endpoints: Option<Vec<String>>,
    pub routes: Option<Vec<String>>,
    pub relay: Option<bool>,
    pub via_relay: Option<String>,
    pub lan_policy: Option<String>,
    pub exit: Option<bool>,
    pub exit_via: Option<String>,
    pub test_port: Option<i64>,
    pub app_admin: Option<bool>,
    pub beep: Option<bool>,
    pub lan_exits: Option<Vec<LanExit>>,
    pub exit_only: Option<bool>,
    pub exits_allowed: Option<Vec<String>>,
    pub iptables: Option<bool>,
    pub host_firewall: Option<bool>,
}

/// A stock-WireGuard-app device config.
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
pub struct StaticDevice {
    pub node: Node,
    pub config: String,
}

type R<T> = Result<T, String>;

fn dummy_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| bcrypt::hash("meshgate-dummy", 10).unwrap_or_default())
}

impl Service {
    pub fn new(store: Arc<Store>, self_id: &str) -> Arc<Service> {
        Arc::new(Service { store, self_id: self_id.into(), backend: OnceLock::new() })
    }

    fn backend(&self) -> Option<&Arc<dyn Backend>> {
        self.backend.get()
    }

    fn items<T: DeserializeOwned + Default>(&self, kind: &str) -> Vec<Item<T>> {
        self.store
            .keys(kind)
            .into_iter()
            .filter_map(|k| self.store.get::<T>(&k).map(|v| Item { value: v, local: self.store.is_local(&k) }))
            .collect()
    }

    /// The current view.
    pub fn view(&self) -> View {
        let mut v = View {
            self_id: self.self_id.clone(),
            network: self.store.get("network/main").unwrap_or_default(),
            nodes: self.items(model::KIND_NODE),
            forwards: self.items(model::KIND_FORWARD),
            routes: self.items(model::KIND_ROUTE),
            acls: self.items(model::KIND_ACL),
            exit_routes: self.items(model::KIND_EXIT_ROUTE),
            monitors: self.items(model::KIND_MONITOR),
            tokens: self
                .store
                .list::<Token>(model::KIND_TOKEN)
                .into_iter()
                .map(|mut t| {
                    t.secret_hash.clear();
                    t
                })
                .collect(),
            statuses: self.store.list::<Status>(model::KIND_STATUS).into_iter().map(|s| (s.node_id.clone(), s)).collect(),
            runtime: Runtime::default(),
        };
        v.nodes.sort_by(|a, b| a.value.name.cmp(&b.value.name));
        v.forwards.sort_by(|a, b| a.value.name.cmp(&b.value.name));
        v.routes.sort_by(|a, b| a.value.hostname.cmp(&b.value.hostname));
        v.acls.sort_by(|a, b| a.value.name.cmp(&b.value.name));
        v.monitors.sort_by(|a, b| a.value.name.cmp(&b.value.name));
        if let Some(b) = self.backend() {
            v.runtime = b.runtime();
        }
        v
    }

    fn self_node(&self) -> Node {
        self.store.get(&model::key(model::KIND_NODE, &self.self_id)).unwrap_or_default()
    }

    fn require_writer(&self) -> R<()> {
        if self.self_node().writer() { Ok(()) } else { Err("only server nodes can change mesh config".into()) }
    }

    fn node_exists(&self, id: &str) -> bool {
        self.store.raw(&model::key(model::KIND_NODE, id)).is_some()
    }

    fn node(&self, id: &str) -> Option<Node> {
        self.store.get(&model::key(model::KIND_NODE, id))
    }

    pub fn put_forward(&self, mut f: Forward, scope: Scope) -> R<Forward> {
        self.require_writer()?;
        if f.id.is_empty() {
            f.id = join::random_id();
        }
        f.name = f.name.trim().to_string();
        f.validate()?;
        model::check_name(&f.name)?;
        if !self.node_exists(&f.edge_node) || !self.node_exists(&f.target_node) {
            return Err("unknown edge or target node".into());
        }
        for o in self.store.list::<Forward>(model::KIND_FORWARD) {
            if o.id == f.id || !o.enabled || !f.enabled || o.edge_node != f.edge_node {
                continue;
            }
            if overlaps(&o, &f) {
                return Err(format!("port overlaps forward {:?} on the same edge", o.name));
            }
        }
        self.store.put(&model::key(model::KIND_FORWARD, &f.id), &f, scope)?;
        Ok(f)
    }

    pub fn put_route(&self, mut r: HttpRoute, scope: Scope) -> R<HttpRoute> {
        self.require_writer()?;
        if r.id.is_empty() {
            r.id = join::random_id();
        }
        r.hostname = r.hostname.trim().to_lowercase();
        r.validate()?;
        if !self.node_exists(&r.edge_node) || !self.node_exists(&r.target_node) {
            return Err("unknown edge or target node".into());
        }
        if self.store.list::<HttpRoute>(model::KIND_ROUTE).iter().any(|o| o.id != r.id && o.hostname == r.hostname) {
            return Err(format!("hostname {} is already routed", r.hostname));
        }
        self.store.put(&model::key(model::KIND_ROUTE, &r.id), &r, scope)?;
        Ok(r)
    }

    /// Picks the traffic log server ("" = automatic) and retention in days.
    pub fn set_history_settings(&self, server: &str, days: i64) -> R<()> {
        self.require_writer()?;
        if !server.is_empty() && !self.node(server).is_some_and(|n| n.kind == model::NODE_SERVER) {
            return Err("the log server must be a server node".into());
        }
        if !(0..=3650).contains(&days) {
            return Err("keep history for 1-3650 days".into());
        }
        let mut netw: Network = self.store.get("network/main").unwrap_or_default();
        netw.log_server = server.into();
        netw.log_days = days;
        self.store.put("network/main", &netw, Scope::Cluster).map(|_| ())
    }

    pub fn put_exit_route(&self, mut r: ExitRoute, scope: Scope) -> R<ExitRoute> {
        self.require_writer()?;
        if r.id.is_empty() {
            r.id = join::random_id();
        }
        r.name = r.name.trim().to_string();
        model::check_name(&r.name)?;
        let pfx = r.prefix()?;
        r.src = pfx.to_string();
        if let Some(netw) = self.store.get::<Network>("network/main")
            && netw.prefix().is_ok_and(|m| m.overlaps(&pfx))
        {
            return Err("that is the mesh range, not a LAN device".into());
        }
        let nodes: Vec<Node> = self.store.list(model::KIND_NODE);
        if r.router.is_empty() {
            for n in &nodes {
                for sub in &n.routes {
                    if let Some(p) = netx::parse_prefix(sub)
                        && n.kind == model::NODE_SERVER
                        && p.masked().contains(pfx.addr)
                        && p.bits <= pfx.bits
                    {
                        r.router = n.id.clone();
                    }
                }
            }
            if r.router.is_empty() {
                return Err(format!(
                    "no node shares a subnet containing {}: add it to the router's Shared LAN subnets, or pick the router",
                    r.src
                ));
            }
        }
        let router =
            self.node(&r.router).filter(|n| n.kind == model::NODE_SERVER).ok_or("pick the router those devices use (a server node)")?;
        if !self.node(&r.via).is_some_and(|ex| ex.exit) || r.via == r.router {
            return Err("pick a node offered as an exit node".into());
        }
        if r.enabled {
            for o in self.store.list::<ExitRoute>(model::KIND_EXIT_ROUTE) {
                if o.id != r.id && o.enabled && o.router == r.router && o.via != r.via {
                    return Err(format!(
                        "{} already sends LAN devices through {} (route {:?}): one router uses one exit node at a time for now",
                        router.name,
                        name_of(&nodes, &o.via),
                        o.name
                    ));
                }
            }
        }
        self.store.put(&model::key(model::KIND_EXIT_ROUTE, &r.id), &r, scope)?;
        Ok(r)
    }

    pub fn put_acl(&self, mut a: Acl, scope: Scope) -> R<Acl> {
        self.require_writer()?;
        if a.id.is_empty() {
            a.id = join::random_id();
        }
        a.name = a.name.trim().to_string();
        a.to = a.to.trim().to_string();
        if !a.name.is_empty() {
            model::check_name(&a.name)?;
        }
        if a.name.is_empty() {
            a.name = a.to.clone();
        }
        a.validate()?;
        if !self.node(&a.node).is_some_and(|n| n.kind == model::NODE_SERVER) {
            return Err("rules are enforced by server nodes; pick one".into());
        }
        for id in &a.from {
            if !self.node_exists(id) {
                return Err(format!("unknown device {id}"));
            }
        }
        self.store.put(&model::key(model::KIND_ACL, &a.id), &a, scope)?;
        Ok(a)
    }

    /// Switches a forward, route, rule or exit route on or off, keeping a
    /// local override local.
    pub fn toggle(&self, kind: &str, id: &str, enabled: bool) -> R<()> {
        self.require_writer()?;
        let key = model::key(kind, id);
        let scope = if self.store.is_local(&key) { Scope::Local } else { Scope::Cluster };
        match kind {
            model::KIND_FORWARD => {
                let mut v: Forward = self.store.get(&key).ok_or("no such forward")?;
                v.enabled = enabled;
                self.put_forward(v, scope).map(|_| ())
            }
            model::KIND_ROUTE => {
                let mut v: HttpRoute = self.store.get(&key).ok_or("no such route")?;
                v.enabled = enabled;
                self.put_route(v, scope).map(|_| ())
            }
            model::KIND_ACL => {
                let mut v: Acl = self.store.get(&key).ok_or("no such rule")?;
                v.enabled = enabled;
                self.put_acl(v, scope).map(|_| ())
            }
            model::KIND_EXIT_ROUTE => {
                let mut v: ExitRoute = self.store.get(&key).ok_or("no such exit route")?;
                v.enabled = enabled;
                self.put_exit_route(v, scope).map(|_| ())
            }
            _ => Err("only forwards, routes, rules and exit routes can be toggled".into()),
        }
    }

    /// Edits a node.
    pub fn update_node(&self, id: &str, mut p: NodePatch, scope: Scope) -> R<Node> {
        self.require_writer()?;
        let mut n = self.node(id).ok_or("no such node")?;
        if let Some(name) = &p.name {
            let name = name.trim().to_string();
            model::check_name(&name)?;
            n.name = name;
        }
        if let Some(eps) = p.endpoints.take() {
            for e in &eps {
                model::check_endpoint(e)?;
            }
            n.endpoints = eps;
        }
        if let Some(rs) = p.routes.take() {
            for r in &rs {
                if netx::parse_prefix(r).is_none() {
                    return Err(format!("route {r:?}: netip.ParsePrefix({r:?}): invalid prefix"));
                }
            }
            n.routes = rs;
        }
        if let Some(v) = p.relay {
            n.relay = v && n.kind == model::NODE_SERVER;
        }
        if let Some(v) = p.via_relay.take() {
            n.via_relay = v;
        }
        if let Some(v) = p.exit {
            n.exit = v && n.kind == model::NODE_SERVER;
        }
        if let Some(mut lx) = p.lan_exits.take() {
            let mut via = String::new();
            for e in lx.iter_mut() {
                let pfx = e.prefix().map_err(|err| format!("LAN exit: {err}"))?;
                if let Some(netw) = self.store.get::<Network>("network/main")
                    && netw.prefix().is_ok_and(|m| m.overlaps(&pfx))
                {
                    return Err(format!("LAN exit {}: that is the mesh range, not a LAN", e.src));
                }
                if !self.node(&e.via).is_some_and(|ex| ex.exit) || e.via == id {
                    return Err(format!("LAN exit {}: pick a node offered as an exit node", e.src));
                }
                if !via.is_empty() && e.via != via {
                    return Err("a router can send LAN devices through one exit node at a time".into());
                }
                via = e.via.clone();
                e.src = pfx.to_string();
            }
            if !lx.is_empty() && n.kind != model::NODE_SERVER {
                return Err("LAN exits are set on the router (a server node that shares the LAN)".into());
            }
            n.lan_exits = lx;
        }
        if let Some(al) = p.exits_allowed.take() {
            for a in &al {
                if a != "*" && !self.node(a).is_some_and(|ex| ex.exit) {
                    return Err(format!("allowed exit {a:?} is not an exit node"));
                }
            }
            n.exits_allowed = al;
        }
        if let Some(v) = p.iptables {
            n.iptables_off = !v;
        }
        if let Some(v) = p.host_firewall {
            n.host_firewall_off = !v;
        }
        if let Some(v) = p.exit_only {
            n.exit_only = v;
        }
        if let Some(v) = p.beep {
            n.beep_off = !v;
        }
        if let Some(v) = p.app_admin {
            n.app_admin_off = !v;
        }
        if let Some(v) = p.test_port {
            if v != 0 && (!model::valid_port(v) || n.kind != model::NODE_SERVER) {
                return Err("test service: server nodes only, port 1-65535".into());
            }
            n.test_port = v;
        }
        if let Some(v) = p.exit_via.take() {
            if !v.is_empty() && (!self.node(&v).is_some_and(|ex| ex.exit) || v == id) {
                return Err("that node is not an exit node".into());
            }
            n.exit_via = v;
        }
        if let Some(v) = p.lan_policy.take() {
            match v.as_str() {
                model::POLICY_OPEN | model::POLICY_RESTRICTED | model::POLICY_FIREWALL | "" => n.lan_policy = v,
                _ => return Err("lan policy must be open, restricted or firewall".into()),
            }
        }
        self.store.put(&model::key(model::KIND_NODE, id), &n, scope)?;
        Ok(n)
    }

    /// Creates or updates a traffic monitor (count only).
    pub fn put_monitor(&self, mut m: Monitor, scope: Scope) -> R<Monitor> {
        self.require_writer()?;
        if m.id.is_empty() {
            m.id = join::random_id();
        }
        m.name = m.name.trim().to_string();
        m.ip = m.ip.trim().to_string();
        m.ports = m.ports.trim().to_string();
        if m.name.is_empty() {
            m.name = format!("{}:{}", m.ip, m.ports).trim_matches(':').to_string();
        } else {
            model::check_name(&m.name)?;
        }
        m.validate()?;
        if !self.node(&m.node).is_some_and(|n| n.kind == model::NODE_SERVER) {
            return Err("traffic is measured on server nodes; pick one".into());
        }
        self.store.put(&model::key(model::KIND_MONITOR, &m.id), &m, scope)?;
        Ok(m)
    }

    /// Deletes a node along with what uses it.
    pub fn remove_node(&self, id: &str) -> R<()> {
        self.require_writer()?;
        if id == self.self_id {
            return Err("cannot remove the node you are on; run `meshgate leave` there".into());
        }
        let del = |k: String| {
            let _ = self.store.delete(&k, Scope::Cluster);
        };
        for f in self.store.list::<Forward>(model::KIND_FORWARD) {
            if f.edge_node == id || f.target_node == id {
                del(model::key(model::KIND_FORWARD, &f.id));
            }
        }
        for r in self.store.list::<HttpRoute>(model::KIND_ROUTE) {
            if r.edge_node == id || r.target_node == id {
                del(model::key(model::KIND_ROUTE, &r.id));
            }
        }
        for a in self.store.list::<Acl>(model::KIND_ACL) {
            if a.node == id {
                del(model::key(model::KIND_ACL, &a.id));
            }
        }
        for m in self.store.list::<Monitor>(model::KIND_MONITOR) {
            if m.node == id {
                del(model::key(model::KIND_MONITOR, &m.id));
            }
        }
        del(model::key(model::KIND_STATUS, id));
        self.store.delete(&model::key(model::KIND_NODE, id), Scope::Cluster).map(|_| ())
    }

    pub fn create_token(&self, kind: &str, uses: i64, ttl_secs: i64, note: &str) -> R<String> {
        self.require_writer()?;
        if kind != model::NODE_SERVER && kind != model::NODE_CLIENT {
            return Err("kind must be server or client".into());
        }
        join::new_token(&self.store, kind, uses, ttl_secs, note, crate::util::now_unix()).map(|(t, _)| t)
    }

    /// Registers a device that uses the official WireGuard app; its private
    /// key is generated here and returned once, never stored.
    pub fn add_static_device(&self, name: &str, relay_id: &str) -> R<StaticDevice> {
        self.require_writer()?;
        let relay = self
            .node(relay_id)
            .filter(|r| r.relay && !r.endpoints.is_empty())
            .ok_or("pick a relay node (a server with a public endpoint)")?;
        let key = crate::wg::generate_private_key();
        let pubk = crate::wg::key_string(&crate::wg::public_key(&key));
        let req = join::Request { name: name.into(), kind: model::NODE_STATIC.into(), public_key: pubk, ..Default::default() };
        let resp = join::register_local(&self.store, req, crate::util::now_unix())?;
        let mut n = resp.node;
        n.via_relay = relay_id.into();
        self.store.put(&model::key(model::KIND_NODE, &n.id), &n, Scope::Cluster)?;
        let mut allowed = vec![resp.network.cidr.clone()];
        for o in self.store.list::<Node>(model::KIND_NODE) {
            allowed.extend(o.routes);
        }
        let config = format!(
            "[Interface]\nPrivateKey = {}\nAddress = {}/32\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = {}\nPersistentKeepalive = 25\n",
            crate::wg::key_string(&key),
            n.mesh_ip,
            relay.public_key,
            relay.endpoints[0],
            allowed.join(", ")
        );
        Ok(StaticDevice { node: n, config })
    }

    pub fn set_network(&self, acme_email: &str) -> R<()> {
        self.require_writer()?;
        let mut n: Network = self.store.get("network/main").unwrap_or_default();
        n.acme_email = acme_email.trim().into();
        self.store.put("network/main", &n, Scope::Cluster).map(|_| ())
    }

    /// Creates or changes a web UI login.
    pub fn set_admin(&self, user: &str, pass: &str) -> R<()> {
        let user = user.trim();
        if user.is_empty() || pass.len() < 8 {
            return Err("username required and password must be at least 8 characters".into());
        }
        let h = hash_password(pass)?;
        self.store
            .put(&model::key(model::KIND_ADMIN, user), &model::Admin { username: user.into(), password_hash: h }, Scope::Cluster)
            .map(|_| ())
    }

    pub fn admin_hash(&self, user: &str) -> Option<String> {
        self.store.get::<model::Admin>(&model::key(model::KIND_ADMIN, user)).map(|a| a.password_hash)
    }

    /// Verifies a login (unknown users take as long as known ones).
    pub fn check_admin(&self, user: &str, pass: &str) -> bool {
        match self.admin_hash(user) {
            None => {
                let _ = bcrypt::verify(pass, dummy_hash());
                false
            }
            Some(h) => bcrypt::verify(pass, &h).unwrap_or(false),
        }
    }

    /// Serves `prefix + <op>`; None when the path is not under prefix.
    pub async fn handle(self: &Arc<Self>, prefix: &str, req: Req) -> Option<Resp> {
        let path = req.uri().path().to_string();
        let op = path.strip_prefix(prefix)?.to_string();
        let get = req.method() == Method::GET || req.method() == Method::HEAD;
        let post = req.method() == Method::POST;
        const GETS: [&str; 6] = ["view", "history", "events", "rawlog", "changelog", "traffic"];
        const POSTS: [&str; 17] = [
            "update",
            "history-settings",
            "diag",
            "forward",
            "route",
            "exitroute",
            "acl",
            "monitor",
            "node",
            "delete",
            "toggle",
            "clear-local",
            "token",
            "static-device",
            "network",
            "admin",
            "qr",
        ];
        let known_get = GETS.contains(&op.as_str());
        let known_post = POSTS.contains(&op.as_str()) && op != "qr";
        if !known_get && !known_post {
            return if op == "qr" { None } else { Some(http::not_found()) };
        }
        if (known_get && !get) || (known_post && !post) {
            return Some(http::method_not_allowed());
        }
        let query = req.uri().query().unwrap_or("").to_string();
        let r = self.op(&op, &query, req).await;
        Some(match r {
            Ok(body) => http::resp(StatusCode::OK, "application/json", with_newline(body)),
            Err(e) => http::json(StatusCode::BAD_REQUEST, &BTreeMap::from([("error", e)])),
        })
    }

    async fn op(self: &Arc<Self>, op: &str, query: &str, req: Req) -> R<Vec<u8>> {
        let q = |k: &str| http::query_of(query, k);
        let ok = || Ok(crate::gojson::marshal(&BTreeMap::from([("ok", true)])));
        match op {
            "view" => Ok(crate::gojson::marshal(&self.view())),
            "update" => {
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct B {
                    node: String,
                }
                let b: B = decode(req).await?;
                let be = self.backend().ok_or("updates are not available here")?.clone();
                let msg = be.update(b.node).await?;
                Ok(crate::gojson::marshal(&BTreeMap::from([("message", msg)])))
            }
            "history" => {
                let be = self.backend().ok_or("traffic history is not available here")?.clone();
                be.history(query.to_string()).await
            }
            "history-settings" => {
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct B {
                    log_server: String,
                    log_days: i64,
                }
                let b: B = decode(req).await?;
                self.set_history_settings(&b.log_server, b.log_days)?;
                ok()
            }
            "events" => {
                let be = self.backend().ok_or("the event log is not available here")?.clone();
                be.events(query.to_string()).await
            }
            "rawlog" => {
                let be = self.backend().ok_or("node logs are not available here")?.clone();
                be.rawlog(q("node"), q("n").parse().unwrap_or(0)).await
            }
            "changelog" => Ok(crate::gojson::marshal(&BTreeMap::from([("text", crate::changelog::TEXT)]))),
            "traffic" => {
                let t = match self.backend() {
                    Some(be) => be.clone().traffic().await,
                    None => vec![],
                };
                Ok(crate::gojson::marshal(&t))
            }
            "diag" => {
                let c: crate::diag::Check = decode(req).await?;
                Ok(crate::gojson::marshal(&crate::diag::run(c).await))
            }
            "forward" => {
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct B {
                    forward: Forward,
                    scope: String,
                }
                let b: B = decode(req).await?;
                Ok(crate::gojson::marshal(&self.put_forward(b.forward, Scope::parse(&b.scope))?))
            }
            "route" => {
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct B {
                    route: HttpRoute,
                    scope: String,
                }
                let b: B = decode(req).await?;
                Ok(crate::gojson::marshal(&self.put_route(b.route, Scope::parse(&b.scope))?))
            }
            "exitroute" => {
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct B {
                    exit_route: ExitRoute,
                    scope: String,
                }
                let b: B = decode(req).await?;
                Ok(crate::gojson::marshal(&self.put_exit_route(b.exit_route, Scope::parse(&b.scope))?))
            }
            "acl" => {
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct B {
                    acl: Acl,
                    scope: String,
                }
                let b: B = decode(req).await?;
                Ok(crate::gojson::marshal(&self.put_acl(b.acl, Scope::parse(&b.scope))?))
            }
            "monitor" => {
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct B {
                    monitor: Monitor,
                    scope: String,
                }
                let b: B = decode(req).await?;
                Ok(crate::gojson::marshal(&self.put_monitor(b.monitor, Scope::parse(&b.scope))?))
            }
            "node" => {
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct B {
                    id: String,
                    patch: NodePatch,
                    scope: String,
                }
                let b: B = decode(req).await?;
                Ok(crate::gojson::marshal(&self.update_node(&b.id, b.patch, Scope::parse(&b.scope))?))
            }
            "delete" => {
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct B {
                    kind: String,
                    id: String,
                    scope: String,
                }
                let b: B = decode(req).await?;
                self.require_writer()?;
                match b.kind.as_str() {
                    model::KIND_NODE => {
                        self.remove_node(&b.id)?;
                        Ok(b"null".to_vec())
                    }
                    model::KIND_FORWARD
                    | model::KIND_ROUTE
                    | model::KIND_TOKEN
                    | model::KIND_ACL
                    | model::KIND_EXIT_ROUTE
                    | model::KIND_MONITOR => {
                        self.store.delete(&model::key(&b.kind, &b.id), Scope::parse(&b.scope))?;
                        ok()
                    }
                    _ => Err("cannot delete that kind".into()),
                }
            }
            "toggle" => {
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct B {
                    kind: String,
                    id: String,
                    enabled: bool,
                }
                let b: B = decode(req).await?;
                self.toggle(&b.kind, &b.id, b.enabled)?;
                ok()
            }
            "clear-local" => {
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct B {
                    kind: String,
                    id: String,
                }
                let b: B = decode(req).await?;
                self.store.clear_local(&model::key(&b.kind, &b.id))?;
                ok()
            }
            "token" => {
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct B {
                    kind: String,
                    uses: i64,
                    ttl_hours: i64,
                    note: String,
                }
                let mut b: B = decode(req).await?;
                if b.uses == 0 {
                    b.uses = 1;
                }
                let tok = self.create_token(&b.kind, b.uses, b.ttl_hours * 3600, &b.note)?;
                Ok(crate::gojson::marshal(&BTreeMap::from([("token", tok)])))
            }
            "static-device" => {
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct B {
                    name: String,
                    relay: String,
                }
                let b: B = decode(req).await?;
                Ok(crate::gojson::marshal(&self.add_static_device(&b.name, &b.relay)?))
            }
            "network" => {
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct B {
                    acme_email: String,
                }
                let b: B = decode(req).await?;
                self.set_network(&b.acme_email)?;
                ok()
            }
            "admin" => {
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct B {
                    username: String,
                    password: String,
                }
                let b: B = decode(req).await?;
                self.set_admin(&b.username, &b.password)?;
                ok()
            }
            _ => Err("unknown operation".into()),
        }
    }
}

fn with_newline(mut b: Vec<u8>) -> Vec<u8> {
    if b.last() != Some(&b'\n') {
        b.push(b'\n');
    }
    b
}

/// bcrypt with Go's default cost and version prefix.
pub fn hash_password(pass: &str) -> R<String> {
    bcrypt::hash_with_result(pass, 10).map(|h| h.format_for_version(bcrypt::Version::TwoA)).map_err(|e| e.to_string())
}

async fn decode<T: DeserializeOwned>(req: Req) -> R<T> {
    let b = http::body(req, 1 << 20).await;
    http::first_json(&b).map_err(|e| format!("bad request: {e}"))
}

fn overlaps(a: &Forward, b: &Forward) -> bool {
    let proto_clash = a.proto == b.proto || a.proto == model::PROTO_BOTH || b.proto == model::PROTO_BOTH;
    let (al, ah) = a.ports();
    let (bl, bh) = b.ports();
    proto_clash && al <= bh && bl <= ah
}

fn name_of(nodes: &[Node], id: &str) -> String {
    nodes.iter().find(|n| n.id == id).map(|n| n.name.clone()).unwrap_or_else(|| id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(kind: &str) -> Arc<Service> {
        let s = Arc::new(Store::memory("self"));
        s.put("node/self", &Node { id: "self".into(), name: "pfsense".into(), kind: kind.into(), ..Default::default() }, Scope::Cluster)
            .unwrap();
        s.put("node/lap", &Node { id: "lap".into(), name: "laptop".into(), kind: "client".into(), ..Default::default() }, Scope::Cluster)
            .unwrap();
        Service::new(s, "self")
    }

    fn acl(node: &str, from: &[&str], to: &str, proto: &str, ports: &str) -> Acl {
        Acl {
            node: node.into(),
            from: from.iter().map(|s| s.to_string()).collect(),
            to: to.into(),
            proto: proto.into(),
            ports: ports.into(),
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn put_acl() {
        let o = service("server");
        let good = acl("self", &["lap"], "192.168.20.0/24", "tcp", "80,443,8000-8100");
        let a = o.put_acl(good.clone(), Scope::Cluster).unwrap();
        assert!(!a.id.is_empty() && a.name == "192.168.20.0/24");
        for b in [
            acl("lap", &[], "self", "any", ""),
            acl("self", &["ghost"], "self", "any", ""),
            acl("self", &[], "nas.local", "tcp", ""),
            acl("self", &[], "self", "icmp", "80"),
            acl("self", &[], "self", "tcp", "90-80"),
            acl("self", &[], "self", "gre", ""),
        ] {
            assert!(o.put_acl(b.clone(), Scope::Cluster).is_err(), "{b:?}");
        }
        assert!(service("client").put_acl(good, Scope::Cluster).is_err());
    }

    #[test]
    fn toggle_keeps_scope() {
        let o = service("server");
        o.store
            .put("node/home", &Node { id: "home".into(), name: "home".into(), kind: "server".into(), ..Default::default() }, Scope::Cluster)
            .unwrap();
        let f = o
            .put_forward(
                Forward {
                    name: "mc".into(),
                    proto: "tcp".into(),
                    edge_node: "self".into(),
                    listen_port: 25565,
                    target_node: "home".into(),
                    target_port: 25565,
                    enabled: true,
                    ..Default::default()
                },
                Scope::Local,
            )
            .unwrap();
        o.toggle(model::KIND_FORWARD, &f.id, false).unwrap();
        let got: Forward = o.store.get(&format!("forward/{}", f.id)).unwrap();
        assert!(!got.enabled && got.name == "mc" && o.store.is_local(&format!("forward/{}", f.id)));
        assert!(o.toggle(model::KIND_NODE, "home", false).is_err());
    }

    #[test]
    fn lan_policy_patch_and_remove_node_drops_rules() {
        let o = service("server");
        o.store
            .put("node/home", &Node { id: "home".into(), name: "home".into(), kind: "server".into(), ..Default::default() }, Scope::Cluster)
            .unwrap();
        let n = o.update_node("home", NodePatch { lan_policy: Some("restricted".into()), ..Default::default() }, Scope::Cluster).unwrap();
        assert!(n.restricted());
        assert!(o.update_node("home", NodePatch { lan_policy: Some("closed".into()), ..Default::default() }, Scope::Cluster).is_err());
        let a = o.put_acl(acl("home", &[], "self", "any", ""), Scope::Cluster).unwrap();
        o.remove_node("home").unwrap();
        assert!(o.store.raw(&format!("acl/{}", a.id)).is_none());
    }

    #[test]
    fn admin_login_and_go_hashes() {
        let o = service("server");
        o.set_admin("admin", "correct horse").unwrap();
        assert!(o.check_admin("admin", "correct horse"));
        assert!(!o.check_admin("admin", "wrong"));
        assert!(!o.check_admin("nobody", "x"));
        assert!(o.admin_hash("admin").unwrap().starts_with("$2a$10$"));
        // A hash made by the Go build (x/crypto/bcrypt) for "benchpassword".
        let go = "$2a$10$qNRWWpTQ84UGlCdxq2lo6OO4g6vhfdUJxWer4pMeweHDri4ozab3y";
        assert!(bcrypt::verify("benchpassword", go).unwrap());
        assert!(!bcrypt::verify("benchpassword2", go).unwrap());
    }
}
