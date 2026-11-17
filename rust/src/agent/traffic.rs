//! Traffic counters (Go: internal/agent/traffic.go): raw counters (which
//! restart when the firewall reloads or a peer is re-added) become totals
//! and speeds, reported to the UIs and to other servers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hyper::{Method, StatusCode};

use super::Agent;
use crate::fw::counter_name;
use crate::http::{self, Peer, Resp};
use crate::model::{self, Acl, Forward, HttpRoute, Monitor, Node};
use crate::traffic::{self, Rate};

/// How often counters are read; speeds are averaged over it.
pub const INTERVAL: Duration = Duration::from_secs(5);

#[derive(Default)]
struct Meter {
    last: u64,
    total: u64,
    rate: f64,
}

#[derive(Default)]
pub struct Meters {
    st: Mutex<(HashMap<String, Meter>, Option<Instant>)>,
}

impl Meters {
    /// Records raw counter values read now.
    pub fn observe(&self, raw: HashMap<String, u64>) {
        let mut g = self.st.lock().unwrap();
        let now = Instant::now();
        let dt = g.1.map(|t| now.duration_since(t).as_secs_f64()).unwrap_or(0.0);
        for (name, v) in raw {
            match g.0.get_mut(&name) {
                None => {
                    g.0.insert(name, Meter { last: v, total: v, rate: 0.0 });
                }
                Some(m) => {
                    let d = if v < m.last { v } else { v - m.last };
                    m.total += d;
                    m.last = v;
                    if dt > 0.5 {
                        m.rate = d as f64 / dt;
                    }
                }
            }
        }
        if dt > 0.5 || g.1.is_none() {
            g.1 = Some(now);
        }
    }

    pub fn get(&self, name: &str) -> (u64, f64) {
        self.st.lock().unwrap().0.get(name).map(|m| (m.total, m.rate)).unwrap_or((0, 0.0))
    }

    pub fn rate(&self, inn: &str, out: &str) -> Rate {
        let (ti, ri) = self.get(inn);
        let (to, ro) = self.get(out);
        Rate { in_: ti, out: to, in_rate: ri, out_rate: ro }
    }
}

impl Agent {
    /// Samples every counter this node has.
    pub(super) fn read_traffic(&self) {
        let mut raw: HashMap<String, u64> = HashMap::new();
        for (name, v) in crate::fw::read_counters().unwrap_or_default() {
            // Access rules: packets of new connections; the rest: bytes.
            let val = if name.starts_with("a_") { v[0] } else { v[1] };
            raw.insert(name, val);
        }
        let by_key: HashMap<String, String> = self.store.list::<Node>(model::KIND_NODE).into_iter().map(|n| (n.public_key, n.id)).collect();
        for (key, st) in self.wg.stats() {
            if let Some(id) = by_key.get(&key) {
                raw.insert(format!("p_{id}_in"), st.rx_bytes as u64);
                raw.insert(format!("p_{id}_out"), st.tx_bytes as u64);
            }
        }
        let (hosts, _) = self.proxy.stats();
        for (h, s) in hosts {
            raw.insert(format!("r_{h}_req"), s.requests);
            raw.insert(format!("r_{h}_err"), s.errors);
            raw.insert(format!("r_{h}_in"), s.in_);
            raw.insert(format!("r_{h}_out"), s.out);
            raw.insert(format!("r_{h}_hin"), s.http_in);
            raw.insert(format!("r_{h}_hout"), s.http_out);
        }
        self.meters.observe(raw);
    }

    /// This node's report.
    pub(super) fn local_traffic(&self) -> traffic::Node {
        let me = &self.cfg.node_id;
        let ms = &self.meters;
        let mut t = traffic::Node { node: me.clone(), ..Default::default() };
        for f in self.store.list::<Forward>(model::KIND_FORWARD) {
            if f.edge_node == *me {
                t.forwards.insert(f.id.clone(), ms.rate(&counter_name("f", &f.id, "in"), &counter_name("f", &f.id, "out")));
            }
        }
        for r in self.store.list::<HttpRoute>(model::KIND_ROUTE) {
            if r.edge_node != *me {
                continue;
            }
            let h = r.hostname.to_lowercase();
            let mut rt = traffic::Route {
                rate: ms.rate(&format!("r_{h}_in"), &format!("r_{h}_out")),
                http: ms.rate(&format!("r_{h}_hin"), &format!("r_{h}_hout")),
                ..Default::default()
            };
            (rt.requests, rt.req_rate) = ms.get(&format!("r_{h}_req"));
            rt.errors = ms.get(&format!("r_{h}_err")).0;
            t.routes.insert(r.id, rt);
        }
        for a in self.store.list::<Acl>(model::KIND_ACL) {
            if a.node == *me {
                t.acls.insert(a.id.clone(), ms.get(&counter_name("a", &a.id, "")).0);
            }
        }
        for m in self.store.list::<Monitor>(model::KIND_MONITOR) {
            if m.node == *me {
                t.monitors.insert(m.id.clone(), ms.rate(&counter_name("m", &m.id, "in"), &counter_name("m", &m.id, "out")));
            }
        }
        for n in self.store.list::<Node>(model::KIND_NODE) {
            if n.id != *me {
                let r = ms.rate(&format!("p_{}_in", n.id), &format!("p_{}_out", n.id));
                if r.in_ + r.out > 0 {
                    t.peers.insert(n.id, r);
                }
            }
        }
        t.recent = self.proxy.stats().1;
        t
    }

    /// Every server's report: this one directly, the others over the mesh
    /// (servers that do not answer in time are left out).
    pub(super) async fn traffic(self: Arc<Self>) -> Vec<traffic::Node> {
        let mut out = vec![self.local_traffic()];
        let mut tasks = vec![];
        for n in self.store.list::<Node>(model::KIND_NODE) {
            if n.id == self.cfg.node_id || n.kind != model::NODE_SERVER || n.mesh_ip.is_empty() {
                continue;
            }
            let addr = Agent::mesh_addr(&n);
            tasks.push(tokio::spawn(async move {
                let r = http::plain(&addr, Method::GET, "/v1/traffic", &[], bytes::Bytes::new(), Duration::from_secs(3)).await.ok()?;
                if r.status != StatusCode::OK {
                    return None;
                }
                http::first_json::<traffic::Node>(&r.body).ok()
            }));
        }
        for t in tasks {
            if let Ok(Some(n)) = t.await {
                out.push(n);
            }
        }
        out
    }

    /// Other servers' Traffic calls (mesh port, servers only).
    pub(super) fn serve_traffic(&self, peer: Peer) -> Resp {
        match self.server_caller(&peer) {
            Ok(_) => http::ok_json(&self.local_traffic()),
            Err(_) => http::error(StatusCode::FORBIDDEN, "unknown node"),
        }
    }

    pub(super) async fn traffic_loop(self: Arc<Self>) {
        let mut t = tokio::time::interval(INTERVAL);
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        t.tick().await;
        let step = crate::history::interval();
        let mut interval = crate::util::now_unix() / step * step;
        loop {
            t.tick().await;
            let a = self.clone();
            let _ = tokio::task::spawn_blocking(move || a.read_traffic()).await;
            let cur = crate::util::now_unix() / step * step;
            if cur > interval {
                let a = self.clone();
                tokio::spawn(async move { a.flush_history(interval).await }); // the interval that just ended
                interval = cur;
            }
            self.sample_history();
        }
    }
}
