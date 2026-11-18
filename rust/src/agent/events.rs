//! The event log (Go: internal/agent/eventlog.go and rawlog.go): every node
//! copies its log lines into RAM and hands them to the log server every 10
//! seconds; undelivered lines stay in RAM and this node's UIs show them.
//! Plus the full log of a node (journal / log file) and the pfSense beep.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hyper::{Method, StatusCode};
use serde::{Deserialize, Serialize};

use super::Agent;
use crate::events::{self, Entry, Query};
use crate::gojson::{nullable, zero};
use crate::http::{self, Peer, Req, Resp};
use crate::model::{self, Node};

const INTERVAL: Duration = Duration::from_secs(10);
const BATCH: usize = 500;
/// Undelivered lines held in RAM (about 300 KB).
const KEEP: usize = 2000;
/// Last lines kept for this node's own view.
const RECENT: usize = 500;
/// Where FreeBSD/pfSense's rc script (daemon -o) writes.
const RAW_LOG_FILE: &str = "/var/log/meshgate.log";

pub struct EventState {
    pub buf: Arc<events::Buffer>,
    store: events::Store,
    failing: Mutex<bool>,
    pruned: Mutex<Option<Instant>>,
    pub last_beep: Mutex<Option<Instant>>,
}

impl EventState {
    pub fn new(node: &str, data_dir: &str) -> EventState {
        EventState {
            buf: Arc::new(events::Buffer::new(node, KEEP, RECENT)),
            store: events::Store::new(std::path::Path::new(data_dir).join("events")),
            failing: Mutex::new(false),
            pruned: Mutex::new(None),
            last_beep: Mutex::new(None),
        }
    }
}

/// What the UIs get: the log server's lines, and this node's RAM.
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct EventsAnswer {
    server: String,
    #[serde(skip_serializing_if = "zero")]
    error: String,
    #[serde(deserialize_with = "nullable")]
    entries: Vec<Entry>,
    node: String,
    pending: Vec<Entry>,
    recent: Vec<Entry>,
    #[serde(skip_serializing_if = "zero")]
    dropped: usize,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct RawLogAnswer {
    node: String,
    source: String,
    #[serde(deserialize_with = "nullable")]
    lines: Vec<String>,
    #[serde(skip_serializing_if = "zero")]
    error: String,
}

fn parse_event_query(q: &str) -> Query {
    let g = |k: &str| http::query_of(q, k);
    let num = |k: &str| g(k).parse::<i64>().unwrap_or(0);
    let mut eq =
        Query { since: num("since"), until: num("until"), node: g("node"), text: g("q"), important: g("important") == "1", limit: 0 };
    let l = num("limit");
    eq.limit = if l <= 0 || l > 5000 { 500 } else { l as usize };
    eq
}

fn raw_log_lines(n: i64) -> i64 {
    if n <= 0 || n > 5000 { 1000 } else { n }
}

/// The last n lines of this node's own log.
fn read_raw_log(n: i64) -> Result<(Vec<String>, String), String> {
    if cfg!(target_os = "linux") {
        let o = crate::util::run("journalctl", &["-u", "meshgate", "-n", &n.to_string(), "--no-pager", "-o", "short-iso"], None);
        if !o.ok {
            return Err(format!("journalctl: {} (is meshgate running under systemd?)", o.err));
        }
        return Ok((split_lines(&o.out), "journalctl -u meshgate".into()));
    }
    // FreeBSD's rc script and macOS's launchd job write the log file.
    if cfg!(any(target_os = "freebsd", target_os = "macos")) {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(RAW_LOG_FILE).map_err(|e| e.to_string())?;
        let size = f.metadata().map(|m| m.len()).unwrap_or(0);
        if size > 2 << 20 {
            let _ = f.seek(SeekFrom::Start(size - (2 << 20)));
        }
        let mut b = vec![];
        f.read_to_end(&mut b).map_err(|e| e.to_string())?;
        let mut lines = split_lines(&String::from_utf8_lossy(&b));
        if lines.len() > n as usize {
            lines.drain(..lines.len() - n as usize);
        }
        return Ok((lines, RAW_LOG_FILE.into()));
    }
    Err(format!("no log file on {}; see the event log", crate::update::goos()))
}

fn split_lines(s: &str) -> Vec<String> {
    s.trim_end_matches('\n').split('\n').filter(|l| !l.is_empty()).map(String::from).collect()
}

impl Agent {
    /// Copies the log's output into the RAM buffer.
    pub(super) fn capture_log(&self) {
        let buf = self.ev.buf.clone();
        crate::logx::set_sink(Arc::new(move |b: &[u8]| buf.write(b)));
    }

    pub(super) async fn events_loop(self: Arc<Self>) {
        loop {
            tokio::time::sleep(INTERVAL).await;
            let a = self.clone();
            let _ = tokio::task::spawn_blocking(move || a.flush_events()).await;
        }
    }

    /// Delivers what is held in RAM, batch by batch (blocking).
    pub(super) fn flush_events(&self) {
        let netw = self.network();
        let srv = self.log_server(&netw);
        if srv.id == self.cfg.node_id {
            let mut p = self.ev.pruned.lock().unwrap();
            if p.is_none_or(|t| t.elapsed() > Duration::from_secs(3600)) {
                self.ev.store.maintain(crate::util::now_unix(), netw.history_days());
                *p = Some(Instant::now());
            }
        }
        for _ in 0..10 {
            let batch = self.ev.buf.take(BATCH);
            if batch.is_empty() {
                return;
            }
            let res = if srv.id == self.cfg.node_id {
                self.ev.store.append(&batch)
            } else {
                let addr = Agent::mesh_addr(&srv);
                let b = batch.clone();
                block_on(async move { super::history::post_json(&addr, "/v1/events", &b).await })
            };
            let mut failing = self.ev.failing.lock().unwrap();
            if let Err(e) = res {
                if !*failing {
                    *failing = true;
                    drop(failing);
                    logf!("event log: log server {} not reachable ({e}); keeping lines in RAM until it is", srv.name);
                }
                return;
            }
            self.ev.buf.ack(&batch);
            if *failing {
                *failing = false;
                drop(failing);
                logf!("event log: log server {} reachable again; delivered the lines held in RAM", srv.name);
            }
        }
    }

    /// The log server's side (mesh port): servers post their lines, any
    /// server may search.
    pub(super) async fn serve_events(self: Arc<Self>, req: Req, peer: Peer) -> Resp {
        let caller = match self.server_caller(&peer) {
            Ok(c) => c,
            Err(r) => return *r,
        };
        if req.method() == Method::POST {
            let b = http::body(req, 4 << 20).await;
            let Ok(mut es) = http::first_json::<Vec<Entry>>(&b) else { return http::error(StatusCode::BAD_REQUEST, "bad request") };
            for e in es.iter_mut() {
                e.node = caller.id.clone(); // a node speaks for itself only
            }
            return match self.ev.store.append(&es) {
                Ok(()) => http::resp(StatusCode::OK, "", bytes::Bytes::new()),
                Err(e) => http::error(StatusCode::INTERNAL_SERVER_ERROR, e),
            };
        }
        let q = parse_event_query(req.uri().query().unwrap_or(""));
        match self.ev.store.query(&q) {
            Ok(found) => http::ok_json(&found),
            Err(e) => http::error(StatusCode::INTERNAL_SERVER_ERROR, e),
        }
    }

    /// Answers the UIs (ops "events").
    pub(super) async fn events(self: Arc<Self>, query: &str) -> Result<Vec<u8>, String> {
        let eq = parse_event_query(query);
        let srv = self.log_server(&self.network());
        let mut out = EventsAnswer { server: srv.name.clone(), node: self.cfg.node_id.clone(), ..Default::default() };
        if srv.id == self.cfg.node_id {
            match self.ev.store.query(&eq) {
                Ok(f) => out.entries = f,
                Err(e) => out.error = e,
            }
        } else {
            // Same query, with the limit the log server should use.
            let mut parts: Vec<String> = query.split('&').filter(|p| !p.is_empty() && !p.starts_with("limit=")).map(String::from).collect();
            parts.push(format!("limit={}", eq.limit));
            parts.sort();
            let path = format!("/v1/events?{}", parts.join("&"));
            match http::plain(&Agent::mesh_addr(&srv), Method::GET, &path, &[], bytes::Bytes::new(), Duration::from_secs(5)).await {
                Err(e) => out.error = format!("log server {} is not reachable: {e}", srv.name),
                Ok(r) if r.status != StatusCode::OK => out.error = format!("log server {}: {}", srv.name, r.status_line()),
                Ok(r) => out.entries = http::first_json(&r.body).unwrap_or_default(),
            }
        }
        let st = self.ev.buf.snapshot();
        out.dropped = st.dropped;
        let pick = |es: Vec<Entry>| {
            let mut got: Vec<Entry> = es.into_iter().filter(|e| eq.matches(e)).collect();
            got.sort_by_key(|e| std::cmp::Reverse(e.t));
            got
        };
        out.pending = pick(st.pending);
        if !out.error.is_empty() {
            out.recent = pick(st.recent);
        }
        Ok(crate::gojson::marshal(&out))
    }

    /// Lets other servers read this node's log (mesh port).
    pub(super) async fn serve_raw_log(self: Arc<Self>, req: Req, peer: Peer) -> Resp {
        if let Err(r) = self.server_caller(&peer) {
            return *r;
        }
        let n = raw_log_lines(http::query(&req, "n").parse().unwrap_or(0));
        let ans = tokio::task::spawn_blocking(move || read_raw_log(n)).await.unwrap_or_else(|e| Err(e.to_string()));
        let mut a = RawLogAnswer { node: self.cfg.node_id.clone(), ..Default::default() };
        match ans {
            Ok((lines, src)) => {
                a.lines = lines;
                a.source = src;
            }
            Err(e) => a.error = e,
        }
        http::ok_json(&a)
    }

    /// Answers the UIs (ops "rawlog"): this node's log, or another server's.
    pub(super) async fn raw_log(self: Arc<Self>, node: &str, n: i64) -> Result<Vec<u8>, String> {
        let n = raw_log_lines(n);
        if node.is_empty() || node == self.cfg.node_id {
            let mut a = RawLogAnswer { node: self.cfg.node_id.clone(), ..Default::default() };
            match tokio::task::spawn_blocking(move || read_raw_log(n)).await.unwrap_or_else(|e| Err(e.to_string())) {
                Ok((lines, src)) => {
                    a.lines = lines;
                    a.source = src;
                }
                Err(e) => a.error = e,
            }
            return Ok(crate::gojson::marshal(&a));
        }
        let target: Node = self
            .store
            .get(&model::key(model::KIND_NODE, node))
            .filter(|t: &Node| t.kind == model::NODE_SERVER)
            .ok_or("pick a server node")?;
        let mut a = RawLogAnswer { node: node.into(), ..Default::default() };
        let path = format!("/v1/rawlog?n={n}");
        match http::plain(&Agent::mesh_addr(&target), Method::GET, &path, &[], bytes::Bytes::new(), Duration::from_secs(10)).await {
            Err(e) => {
                a.error =
                    format!("{} is not reachable over the mesh ({e}); open its own dashboard or run `meshgate tui` there", target.name);
            }
            Ok(r) if r.status != StatusCode::OK => {
                let msg = String::from_utf8_lossy(&r.body[..r.body.len().min(300)]).trim().to_string();
                a.error = if r.status == StatusCode::NOT_FOUND {
                    format!("{} runs an older meshgate without this view; update it", target.name)
                } else {
                    format!("{}: {} {msg}", target.name, r.status_line())
                };
            }
            Ok(r) => a = http::first_json(&r.body).map_err(|e| e.to_string())?,
        }
        Ok(crate::gojson::marshal(&a))
    }

    /// Plays the link tune unless this node is set quiet, at most once a
    /// minute.
    pub(super) fn beep_for(&self, me: &Node, down: bool) {
        let mut last = self.ev.last_beep.lock().unwrap();
        if me.beep_off || last.is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
            return;
        }
        *last = Some(Instant::now());
        std::thread::spawn(move || beep(down));
    }
}

/// Runs a future to completion from a blocking thread.
pub(super) fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Handle::current().block_on(f)
}

/// A short tune on the PC speaker: falling when a link went down, rising
/// when it is back. pfSense ships /usr/local/bin/beep; otherwise speaker(4).
#[cfg(target_os = "freebsd")]
fn beep(down: bool) {
    let (tones, notes): (&[(u32, u32)], &str) = if down {
        (&[(880, 150), (660, 150), (440, 350)], "T200 O5 L8 A E O4 L4 A")
    } else {
        (&[(660, 120), (990, 250)], "T200 O5 L8 E L4 B")
    };
    if std::path::Path::new("/usr/local/bin/beep").exists() {
        for (f, d) in tones {
            crate::util::run("/usr/local/bin/beep", &["-p", &f.to_string(), &d.to_string()], None);
        }
        return;
    }
    crate::util::run("kldload", &["-n", "speaker"], None);
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open("/dev/speaker") {
        let _ = std::io::Write::write_all(&mut f, notes.as_bytes());
    }
}

/// Servers on Linux and Windows rarely have a speaker; the log line is the
/// signal there.
#[cfg(not(target_os = "freebsd"))]
fn beep(_down: bool) {}
