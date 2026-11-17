//! Replicates the store between nodes over the mesh (Go: internal/syncer).
//! Nodes push their changes to all servers immediately and pull from every
//! server periodically (anti-entropy). The API only listens on the mesh IP,
//! so WireGuard has authenticated every request; the source IP identifies
//! the calling node.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use crate::gojson::nullable;
use crate::http::{self, Peer, Req, Resp};
use crate::join;
use crate::model::{self, Node};
use crate::store::{Entry, Store};

/// The anti-entropy period.
pub const PULL_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Batch {
    #[serde(deserialize_with = "nullable")]
    entries: Vec<Entry>,
    seq: u64,
}

#[derive(Default)]
struct State {
    pulled: HashMap<String, u64>,
    pushed: HashMap<String, u64>,
    last_ok: HashMap<String, (i64, i64)>,
}

pub struct Syncer {
    pub store: Arc<Store>,
    pub self_id: String,
    pub mesh_port: i64,
    st: Mutex<State>,
    trigger: Notify,
}

impl Syncer {
    pub fn new(store: Arc<Store>, self_id: &str, mesh_port: i64) -> Arc<Syncer> {
        Arc::new(Syncer { store, self_id: self_id.into(), mesh_port, st: Mutex::new(State::default()), trigger: Notify::new() })
    }

    fn self_node(&self) -> Option<Node> {
        self.store.get(&model::key(model::KIND_NODE, &self.self_id))
    }

    /// The node that owns a mesh IP.
    pub fn node_by_ip(&self, ip: &str) -> Option<Node> {
        self.store.list::<Node>(model::KIND_NODE).into_iter().find(|n| n.mesh_ip == ip)
    }

    fn caller(&self, peer: &Peer) -> Option<Node> {
        let ip = peer.addr?.ip();
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        self.node_by_ip(&ip.to_string())
    }

    /// Serves /v1/ping and /v1/sync; None for other paths.
    pub async fn handle(&self, req: Req, peer: Peer) -> Option<Resp> {
        let path = req.uri().path();
        let get = req.method() == Method::GET || req.method() == Method::HEAD;
        match path {
            "/v1/ping" if get => Some(http::resp(StatusCode::OK, "text/plain; charset=utf-8", self.self_id.clone())),
            "/v1/sync" if get => {
                let Some(caller) = self.caller(&peer) else { return Some(http::error(StatusCode::FORBIDDEN, "unknown node")) };
                let since = http::query(&req, "since").parse::<u64>().unwrap_or(0);
                let (entries, seq) = self.store.since(since);
                Some(http::ok_json(&Batch { entries: join::filter_for(&caller, entries), seq }))
            }
            "/v1/sync" if req.method() == Method::POST => {
                let Some(caller) = self.caller(&peer) else { return Some(http::error(StatusCode::FORBIDDEN, "unknown node")) };
                let b: Batch = match http::decode(req, 32 << 20).await {
                    Ok(b) => b,
                    Err(e) => return Some(*e),
                };
                let accepted = authorize(&caller, b.entries);
                let n = accepted.len();
                if let Err(e) = self.store.merge(accepted) {
                    logf!("sync: merge from {}: {e}", caller.name);
                }
                Some(http::ok_json(&HashMap::from([("accepted", n)])))
            }
            "/v1/ping" | "/v1/sync" => Some(http::method_not_allowed()),
            _ => None,
        }
    }

    /// Schedules an immediate push.
    pub fn kick(&self) {
        self.trigger.notify_one();
    }

    /// Pushes on change and pulls periodically, forever.
    pub async fn run(self: Arc<Self>) {
        let mut changes = self.store.subscribe();
        let mut t = tokio::time::interval(PULL_INTERVAL);
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        t.tick().await;
        self.round(true).await;
        loop {
            tokio::select! {
                r = changes.changed() => {
                    if r.is_err() { return; }
                    self.round(false).await;
                }
                _ = self.trigger.notified() => self.round(false).await,
                _ = t.tick() => self.round(true).await,
            }
        }
    }

    pub async fn round(self: &Arc<Self>, pull: bool) {
        let Some(me) = self.self_node() else { return };
        let mut tasks = vec![];
        for n in self.store.list::<Node>(model::KIND_NODE) {
            if n.id == self.self_id || !n.writer() || n.mesh_ip.is_empty() {
                continue;
            }
            let s = self.clone();
            let me = me.clone();
            tasks.push(tokio::spawn(async move {
                s.push(&me, &n).await;
                if pull {
                    s.pull(&n).await;
                }
            }));
        }
        for t in tasks {
            let _ = t.await;
        }
    }

    fn addr(&self, n: &Node) -> String {
        let port = if n.mesh_port == 0 { self.mesh_port } else { n.mesh_port };
        crate::netx::join_host_port(&n.mesh_ip, port)
    }

    async fn push(&self, me: &Node, peer: &Node) {
        let from = self.st.lock().unwrap().pushed.get(&peer.id).copied().unwrap_or(0);
        let (mut entries, seq) = self.store.since(from);
        if !me.writer() {
            entries = authorize(me, entries);
        }
        if entries.is_empty() {
            self.set_pushed(&peer.id, seq);
            return;
        }
        let body = crate::gojson::marshal(&Batch { entries, seq: 0 });
        let res = http::plain(
            &self.addr(peer),
            Method::POST,
            "/v1/sync",
            &[("Content-Type", "application/json")],
            body.into(),
            Duration::from_secs(8),
        )
        .await;
        if res.is_ok_and(|r| r.status == StatusCode::OK) {
            self.set_pushed(&peer.id, seq);
        }
    }

    fn set_pushed(&self, id: &str, seq: u64) {
        let mut st = self.st.lock().unwrap();
        let e = st.pushed.entry(id.into()).or_insert(0);
        if seq > *e {
            *e = seq;
        }
    }

    async fn pull(&self, peer: &Node) {
        let since = self.st.lock().unwrap().pulled.get(&peer.id).copied().unwrap_or(0);
        let path = format!("/v1/sync?since={since}");
        let Ok(res) = http::plain(&self.addr(peer), Method::GET, &path, &[], bytes::Bytes::new(), Duration::from_secs(8)).await else {
            return;
        };
        if res.status != StatusCode::OK {
            return;
        }
        let Ok(mut b) = http::first_json::<Batch>(&res.body) else { return };
        if let Err(e) = self.store.merge(std::mem::take(&mut b.entries)) {
            logf!("sync: merge from {}: {e}", peer.name);
            return;
        }
        let mut st = self.st.lock().unwrap();
        if b.seq < since {
            b.seq = 0; // peer state was reset (reinstalled); start over
        }
        st.pulled.insert(peer.id.clone(), b.seq);
        let now = crate::util::now_ms();
        st.last_ok.insert(peer.id.clone(), (now / 1000, (now % 1000) * 1_000_000));
    }

    /// When each server was last pulled successfully (unix s, ns).
    pub fn last_contact(&self) -> HashMap<String, (i64, i64)> {
        self.st.lock().unwrap().last_ok.clone()
    }
}

/// Drops entries the caller may not write: servers may write anything;
/// clients only their own status.
pub fn authorize(caller: &Node, input: Vec<Entry>) -> Vec<Entry> {
    if caller.writer() {
        return input;
    }
    let own = model::key(model::KIND_STATUS, &caller.id);
    input.into_iter().filter(|e| e.key == own && e.origin == caller.id).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Scope;

    async fn serve(s: Arc<Syncer>) -> i64 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port() as i64;
        let h: Arc<dyn http::Handler> = Arc::new(move |r: Req, p: Peer| {
            let s = s.clone();
            async move { s.handle(r, p).await.unwrap_or_else(http::not_found) }
        });
        tokio::spawn(http::serve(l, None, h));
        port
    }

    fn node(id: &str, kind: &str, ip: &str) -> Node {
        Node { id: id.into(), kind: kind.into(), mesh_ip: ip.into(), ..Default::default() }
    }

    #[tokio::test]
    async fn client_push_is_restricted() {
        let srv_store = Arc::new(Store::memory("srv"));
        let port = serve(Syncer::new(srv_store.clone(), "srv", 0)).await;
        let phone = node("phone", "client", "127.0.0.1");
        srv_store.put("node/phone", &phone, Scope::Cluster).unwrap();

        let cli_store = Arc::new(Store::memory("phone"));
        cli_store.put("node/srv", &node("srv", "server", "127.0.0.1"), Scope::Cluster).unwrap();
        cli_store.put("node/phone", &phone, Scope::Cluster).unwrap();
        cli_store
            .put("status/phone", &model::Status { node_id: "phone".into(), home_relay: "vps".into(), ..Default::default() }, Scope::Cluster)
            .unwrap();
        cli_store.put("forward/evil", &model::Forward { id: "evil".into(), ..Default::default() }, Scope::Cluster).unwrap();
        Syncer::new(cli_store, "phone", port).round(true).await;

        let st: model::Status = srv_store.get("status/phone").expect("status not accepted");
        assert_eq!(st.home_relay, "vps");
        assert!(srv_store.raw("forward/evil").is_none(), "client wrote cluster config");
    }

    #[tokio::test]
    async fn servers_replicate_everything() {
        let a_store = Arc::new(Store::memory("a"));
        let port = serve(Syncer::new(a_store.clone(), "a", 0)).await;
        a_store.put("node/a", &node("a", "server", "127.0.0.2"), Scope::Cluster).unwrap();
        a_store.put("node/b", &node("b", "server", "127.0.0.1"), Scope::Cluster).unwrap();
        a_store
            .put("forward/mc", &model::Forward { id: "mc".into(), name: "minecraft".into(), ..Default::default() }, Scope::Cluster)
            .unwrap();

        let b_store = Arc::new(Store::memory("b"));
        b_store.put("node/a", &node("a", "server", "127.0.0.1"), Scope::Cluster).unwrap();
        b_store.put("node/b", &node("b", "server", "127.0.0.1"), Scope::Cluster).unwrap();
        b_store.put("httproute/web", &model::HttpRoute { id: "web".into(), ..Default::default() }, Scope::Cluster).unwrap();
        Syncer::new(b_store.clone(), "b", port).round(true).await;

        let f: model::Forward = b_store.get("forward/mc").expect("pull failed");
        assert_eq!(f.name, "minecraft");
        assert!(a_store.raw("httproute/web").is_some(), "push failed");
    }
}
