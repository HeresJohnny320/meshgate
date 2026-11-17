//! Traffic history delivery (Go: internal/agent/history.go): points every
//! interval to the log server, labels, moving history when the log server
//! changes, and the history queries of the UIs.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::{Method, StatusCode};
use serde::{Deserialize, Serialize};

use super::Agent;
use crate::gojson::nullable;
use crate::history::{self, Bucket, Label, Point};
use crate::http::{self, Peer, Req, Resp};
use crate::model::{self, Forward, HttpRoute, Monitor, Network, Node};

/// Bounds what is kept while the log server is unreachable.
const MAX_PENDING: usize = 50000;
/// Bounds a download (points per series).
const MAX_EXPORT_POINTS: i64 = 9000;

pub struct HistState {
    acc: history::Accumulator,
    pending: Mutex<Vec<Point>>,
    store: history::Store,
}

impl HistState {
    pub fn new(data_dir: &str) -> HistState {
        HistState {
            acc: Default::default(),
            pending: Mutex::new(vec![]),
            store: history::Store::new(std::path::Path::new(data_dir).join("history")),
        }
    }
}

/// What servers send the log server (v0.2.17 sent only the points array).
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct HistPost {
    #[serde(deserialize_with = "nullable")]
    points: Vec<Point>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", deserialize_with = "nullable")]
    labels: BTreeMap<String, Label>,
}

/// A history query's answer. Buckets: [start, bytes in, bytes out, peak in,
/// peak out].
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct HistAnswer {
    range: String,
    from: i64,
    to: i64,
    step: i64,
    server: String,
    units: String,
    #[serde(deserialize_with = "nullable")]
    series: BTreeMap<String, Vec<Bucket>>,
    #[serde(deserialize_with = "nullable")]
    labels: BTreeMap<String, Label>,
}

struct HistQuery {
    rng: String,
    from: i64,
    to: i64,
    step: i64,
}

fn parse_hist_query(q: &str) -> Result<HistQuery, String> {
    let g = |k: &str| http::query_of(q, k);
    if g("from").is_empty() {
        let mut rng = g("range");
        let (span, step) = match history::range(&rng) {
            Some(r) => r,
            None => {
                rng = "1d".into();
                history::range("1d").unwrap()
            }
        };
        let to = crate::util::now_unix() / step * step + step;
        return Ok(HistQuery { rng, from: to - span, to, step });
    }
    let (from, to, step) = (g("from").parse::<i64>(), g("to").parse::<i64>(), g("step").parse::<i64>());
    let (Ok(from), Ok(to), Ok(step)) = (from, to, step) else { return Err("pick a start and an end after it".into()) };
    if from <= 0 || to <= from {
        return Err("pick a start and an end after it".into());
    }
    if ![300, 900, 3600, 86400].contains(&step) {
        return Err("detail must be 5 minutes, 15 minutes, 1 hour or 1 day".into());
    }
    if (to - from) / step > MAX_EXPORT_POINTS {
        return Err(format!(
            "too much detail for that period ({} points per series, at most {MAX_EXPORT_POINTS}): pick a coarser detail or a shorter period",
            (to - from) / step
        ));
    }
    Ok(HistQuery { rng: "custom".into(), from, to, step })
}

impl HistQuery {
    fn values(&self) -> String {
        if self.rng != "custom" {
            return format!("range={}", http::url_encode(&self.rng));
        }
        format!("from={}&step={}&to={}", self.from, self.step, self.to)
    }
}

impl Agent {
    /// Feeds current rates into the accumulator.
    pub(super) fn sample_history(&self) {
        let t = self.local_traffic();
        let acc = &self.hist.acc;
        for (id, r) in &t.forwards {
            acc.sample(&format!("f:{id}"), r.in_, r.out, r.in_rate, r.out_rate);
        }
        for (id, r) in &t.routes {
            // HTTPS and plain HTTP separately (the counters hold both).
            acc.sample(
                &format!("r:{id}"),
                r.rate.in_ - r.rate.in_.min(r.http.in_),
                r.rate.out - r.rate.out.min(r.http.out),
                (r.rate.in_rate - r.http.in_rate).max(0.0),
                (r.rate.out_rate - r.http.out_rate).max(0.0),
            );
            acc.sample(&format!("h:{id}"), r.http.in_, r.http.out, r.http.in_rate, r.http.out_rate);
        }
        for (id, r) in &t.monitors {
            acc.sample(&format!("m:{id}"), r.in_, r.out, r.in_rate, r.out_rate);
        }
        for (id, r) in &t.peers {
            acc.sample(&format!("d:{id}@{}", self.cfg.node_id), r.in_, r.out, r.in_rate, r.out_rate);
        }
    }

    /// Describes the series this server measures.
    fn history_labels(&self) -> BTreeMap<String, Label> {
        let nodes: BTreeMap<String, Node> = self.store.list::<Node>(model::KIND_NODE).into_iter().map(|n| (n.id.clone(), n)).collect();
        let name = |id: &str| nodes.get(id).filter(|n| !n.name.is_empty()).map(|n| n.name.clone()).unwrap_or_else(|| id.to_string());
        let target = |ip: &str, node: &str| {
            if !ip.is_empty() { ip.to_string() } else { nodes.get(node).map(|n| n.mesh_ip.clone()).unwrap_or_default() }
        };
        let me = &self.cfg.node_id;
        let lab = |pairs: &[(&str, String)]| -> Label { pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect() };
        let mut l = BTreeMap::new();
        for f in self.store.list::<Forward>(model::KIND_FORWARD) {
            if f.edge_node != *me {
                continue;
            }
            let (lo, hi) = f.ports();
            let port = if hi > lo { format!("{lo}-{hi}") } else { f.listen_port.to_string() };
            l.insert(
                format!("f:{}", f.id),
                lab(&[
                    ("kind", "forward".into()),
                    ("name", f.name.clone()),
                    ("proto", f.proto.clone()),
                    ("port", port),
                    ("target_ip", target(&f.target_ip, &f.target_node)),
                    ("target_port", f.target_port.to_string()),
                    ("target_node", name(&f.target_node)),
                    ("node", name(me)),
                ]),
            );
        }
        for r in self.store.list::<HttpRoute>(model::KIND_ROUTE) {
            if r.edge_node != *me {
                continue;
            }
            for (pre, kind, port) in [("r:", "https", "443"), ("h:", "http", "80")] {
                l.insert(
                    format!("{pre}{}", r.id),
                    lab(&[
                        ("kind", kind.into()),
                        ("hostname", r.hostname.to_lowercase()),
                        ("port", port.into()),
                        ("target_ip", target(&r.target_ip, &r.target_node)),
                        ("target_port", r.target_port.to_string()),
                        ("target_node", name(&r.target_node)),
                        ("node", name(me)),
                    ]),
                );
            }
        }
        for m in self.store.list::<Monitor>(model::KIND_MONITOR) {
            if m.node == *me {
                l.insert(
                    format!("m:{}", m.id),
                    lab(&[
                        ("kind", "monitor".into()),
                        ("name", m.name.clone()),
                        ("proto", m.proto.clone()),
                        ("port", m.ports.clone()),
                        ("target_ip", m.ip.clone()),
                        ("node", name(me)),
                    ]),
                );
            }
        }
        for (id, n) in &nodes {
            if id != me {
                l.insert(
                    format!("d:{id}@{me}"),
                    lab(&[("kind", "link".into()), ("node", name(me)), ("peer", name(id)), ("peer_ip", n.mesh_ip.clone())]),
                );
            }
        }
        l
    }

    /// Closes the interval that started at start and delivers all pending
    /// points to the log server (or keeps them for the next try).
    pub(super) async fn flush_history(self: Arc<Self>, start: i64) {
        let pts = self.hist.acc.flush(start);
        let send = {
            let mut p = self.hist.pending.lock().unwrap();
            p.extend(pts);
            if p.len() > MAX_PENDING {
                let over = p.len() - MAX_PENDING;
                p.drain(..over);
            }
            p.clone()
        };
        let netw = self.network();
        let srv = self.log_server(&netw);
        let labels = self.history_labels();
        let res: Result<(), String> = if send.is_empty() {
            Ok(())
        } else if srv.id == self.cfg.node_id {
            self.hist.store.append(&send).and_then(|_| self.hist.store.set_labels(labels, true))
        } else {
            post_json(&Agent::mesh_addr(&srv), "/v1/history", &HistPost { points: send.clone(), labels }).await
        };
        if let Err(e) = res {
            logf!("traffic history: {} points kept for later: {e}", send.len());
            return;
        }
        {
            let mut p = self.hist.pending.lock().unwrap();
            let n = send.len().min(p.len());
            p.drain(..n);
        }
        if srv.id == self.cfg.node_id {
            let _ = self.hist.store.maintain(crate::util::now_unix(), netw.history_days());
        } else {
            self.move_history(&srv).await;
        }
    }

    /// Hands the days this server stored while it was the log server to the
    /// current one, deleting each file once the new server has it.
    async fn move_history(&self, srv: &Node) {
        for name in self.hist.store.files() {
            let Ok(data) = self.hist.store.export(&name) else { continue };
            let path = format!("/v1/history/import?name={}", http::url_encode(&name));
            let r = http::plain(
                &Agent::mesh_addr(srv),
                Method::POST,
                &path,
                &[("Content-Type", "application/octet-stream")],
                data.into(),
                Duration::from_secs(60),
            )
            .await;
            match r {
                Err(e) => {
                    logf!("traffic history: moving {name} to log server {}: {e} (retrying later)", srv.name);
                    return;
                }
                Ok(r) if r.status != StatusCode::OK => {
                    logf!("traffic history: moving {name} to log server {}: {} (retrying later)", srv.name, r.status_line());
                    return;
                }
                Ok(_) => {
                    let _ = self.hist.store.remove(&name);
                    logf!("traffic history: moved {name} to the log server {}", srv.name);
                }
            }
        }
    }

    /// The node that stores the history: the chosen one, else the first
    /// relay by name, else the first server.
    pub(super) fn log_server(&self, netw: &Network) -> Node {
        let mut nodes: Vec<Node> = self.store.list(model::KIND_NODE);
        nodes.sort_by(|a, b| a.name.cmp(&b.name));
        let mut first: Option<Node> = None;
        for n in nodes {
            if n.kind != model::NODE_SERVER {
                continue;
            }
            if n.id == netw.log_server {
                return n;
            }
            if first.as_ref().is_none_or(|f| n.relay && !f.relay) {
                first = Some(n);
            }
        }
        first.or_else(|| self.self_node().ok()).unwrap_or_default()
    }

    /// Answers the UIs: points for a range or a download, from the log server.
    pub(super) async fn history(self: Arc<Self>, q: &str) -> Result<Vec<u8>, String> {
        let hq = parse_hist_query(q)?;
        let srv = self.log_server(&self.network());
        if srv.id != self.cfg.node_id {
            let path = format!("/v1/history?{}", hq.values());
            let res = http::plain(&Agent::mesh_addr(&srv), Method::GET, &path, &[], bytes::Bytes::new(), Duration::from_secs(60))
                .await
                .map_err(|e| format!("log server {} is not reachable: {e}", srv.name))?;
            if res.status != StatusCode::OK {
                let msg = String::from_utf8_lossy(&res.body[..res.body.len().min(300)]).trim().to_string();
                return Err(format!("log server {}: {} {msg}", srv.name, res.status_line()));
            }
            let mut out: HistAnswer = http::first_json(&res.body).map_err(|e| e.to_string())?;
            if out.units != "bytes" {
                // A v0.2.17 log server answers average speeds.
                for bs in out.series.values_mut() {
                    for b in bs.iter_mut() {
                        b[1] *= out.step as f64;
                        b[2] *= out.step as f64;
                    }
                }
                out.units = "bytes".into();
            }
            return Ok(crate::gojson::marshal(&out));
        }
        Ok(crate::gojson::marshal(&self.query_history(&hq, &srv.name)?))
    }

    fn query_history(&self, hq: &HistQuery, server: &str) -> Result<HistAnswer, String> {
        let series = self.hist.store.query(hq.from, hq.to, hq.step)?;
        let mut labels = self.hist.store.labels();
        labels.retain(|k, _| series.contains_key(k));
        Ok(HistAnswer {
            range: hq.rng.clone(),
            from: hq.from,
            to: hq.to,
            step: hq.step,
            server: server.into(),
            units: "bytes".into(),
            series,
            labels,
        })
    }

    /// The log server's side (mesh port): servers post points, any server
    /// may query.
    pub(super) async fn serve_history(self: Arc<Self>, req: Req, peer: Peer) -> Resp {
        let caller = match self.server_caller(&peer) {
            Ok(c) => c,
            Err(r) => return *r,
        };
        if req.method() == Method::POST {
            let body = http::body(req, 16 << 20).await;
            let t = body.trim_ascii();
            let post: Result<HistPost, _> = if t.first() == Some(&b'[') {
                serde_json::from_slice::<Vec<Point>>(t).map(|points| HistPost { points, labels: BTreeMap::new() })
            } else {
                http::first_json(&body)
            };
            let Ok(mut post) = post else { return http::error(StatusCode::BAD_REQUEST, "bad request") };
            // Each server reports its own device links only.
            let suffix = format!("@{}", caller.id);
            let own = |k: &str| !k.starts_with("d:") || k.ends_with(&suffix);
            for p in post.points.iter_mut() {
                if !own(&p.key) {
                    p.key.clear();
                }
            }
            post.labels.retain(|k, _| own(k));
            if let Err(e) = self.hist.store.append(&post.points) {
                return http::error(StatusCode::INTERNAL_SERVER_ERROR, e);
            }
            let _ = self.hist.store.set_labels(post.labels, true);
            return http::resp(StatusCode::OK, "", bytes::Bytes::new());
        }
        let q = req.uri().query().unwrap_or("").to_string();
        let hq = match parse_hist_query(&q) {
            Ok(h) => h,
            Err(e) => return http::error(StatusCode::BAD_REQUEST, e),
        };
        let name = self.self_node().map(|n| n.name).unwrap_or_default();
        match self.query_history(&hq, &name) {
            Ok(a) => http::ok_json(&a),
            Err(e) => http::error(StatusCode::INTERNAL_SERVER_ERROR, e),
        }
    }

    /// Takes a day file from the previous log server.
    pub(super) async fn serve_history_import(self: Arc<Self>, req: Req, peer: Peer) -> Resp {
        if let Err(r) = self.server_caller(&peer) {
            return *r;
        }
        if self.log_server(&self.network()).id != self.cfg.node_id {
            return http::error(StatusCode::CONFLICT, "not the log server");
        }
        let name = http::query(&req, "name");
        let data = http::body(req, 256 << 20).await;
        match self.hist.store.import(&name, &data) {
            Ok(_) => http::resp(StatusCode::OK, "", bytes::Bytes::new()),
            Err(e) => http::error(StatusCode::BAD_REQUEST, e),
        }
    }
}

/// POSTs JSON to a mesh node; anything but 200 is an error.
pub(super) async fn post_json<T: Serialize>(addr: &str, path: &str, v: &T) -> Result<(), String> {
    let r = http::plain(
        addr,
        Method::POST,
        path,
        &[("Content-Type", "application/json")],
        crate::gojson::marshal(v).into(),
        Duration::from_secs(15),
    )
    .await?;
    if r.status != StatusCode::OK {
        return Err(r.status_line());
    }
    Ok(())
}
