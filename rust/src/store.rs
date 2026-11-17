//! The replicated configuration store (Go: internal/store).
//!
//! Every node keeps a full copy on disk. Records are last-write-wins
//! registers versioned by a hybrid logical clock; ties break on origin node
//! ID, so every node converges no matter the order it hears about changes.
//! Local records never leave this node and override the cluster record with
//! the same key.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::RwLock;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use tokio::sync::watch;

use crate::config::{tmp_path, write_private};
use crate::gojson::{marshal_indent, nullable, zero};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Cluster,
    Local,
}

impl Scope {
    pub fn parse(s: &str) -> Scope {
        if s == "local" { Scope::Local } else { Scope::Cluster }
    }
}

/// One versioned record.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Entry {
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Box<RawValue>>,
    #[serde(skip_serializing_if = "zero")]
    pub deleted: bool,
    pub version: u64,
    pub origin: String,
    /// This store's arrival order; reassigned by every receiving store.
    pub seq: u64,
}

impl Entry {
    pub fn value_str(&self) -> &str {
        self.value.as_deref().map(RawValue::get).unwrap_or("")
    }
}

/// Whether a should replace b.
fn newer(a: &Entry, b: &Entry) -> bool {
    if a.version != b.version {
        return a.version > b.version;
    }
    a.origin > b.origin
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Disk<'a> {
    node_id: String,
    clock: u64,
    seq: u64,
    #[serde(deserialize_with = "nullable")]
    cluster: Vec<std::borrow::Cow<'a, Entry>>,
    #[serde(deserialize_with = "nullable")]
    local: Vec<std::borrow::Cow<'a, Entry>>,
}

struct Inner {
    node_id: String,
    clock: u64,
    seq: u64,
    cluster: HashMap<String, Entry>,
    local: HashMap<String, Entry>,
    /// Fixed wall clock in ms (tests).
    fixed_now: Option<i64>,
}

pub struct Store {
    path: Option<PathBuf>,
    inner: RwLock<Inner>,
    changed: watch::Sender<u64>,
}

pub type Error = String;

impl Store {
    /// Loads (or creates) the store at path; None keeps it in memory.
    pub fn open(path: Option<PathBuf>, node_id: &str) -> Result<Store, Error> {
        let mut inner =
            Inner { node_id: node_id.into(), clock: 0, seq: 0, cluster: HashMap::new(), local: HashMap::new(), fixed_now: None };
        if let Some(p) = &path {
            match std::fs::read(p) {
                Ok(b) => {
                    let d: Disk = serde_json::from_slice(&b).map_err(|e| format!("store {}: {e}", p.display()))?;
                    inner.clock = d.clock;
                    inner.seq = d.seq;
                    for e in d.cluster {
                        let e = e.into_owned();
                        inner.cluster.insert(e.key.clone(), e);
                    }
                    for e in d.local {
                        let e = e.into_owned();
                        inner.local.insert(e.key.clone(), e);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(Store { path, inner: RwLock::new(inner), changed: watch::Sender::new(0) })
    }

    pub fn memory(node_id: &str) -> Store {
        Store::open(None, node_id).expect("memory store")
    }

    #[cfg(test)]
    pub fn set_fixed_now_ms(&self, ms: i64) {
        self.inner.write().unwrap().fixed_now = Some(ms);
    }

    pub fn node_id(&self) -> String {
        self.inner.read().unwrap().node_id.clone()
    }

    /// Used once, when a fresh node learns its ID during join.
    pub fn set_node_id(&self, id: &str) {
        self.inner.write().unwrap().node_id = id.into();
    }

    /// Writes v (JSON-encoded) under key.
    pub fn put<T: Serialize + ?Sized>(&self, key: &str, v: &T, scope: Scope) -> Result<Entry, Error> {
        let raw = serde_json::to_string(v).map_err(|e| e.to_string())?;
        let raw = RawValue::from_string(raw).map_err(|e| e.to_string())?;
        self.write(key, Some(raw), false, scope)
    }

    /// Writes an already encoded JSON value.
    pub fn put_raw(&self, key: &str, raw: Box<RawValue>, scope: Scope) -> Result<Entry, Error> {
        self.write(key, Some(raw), false, scope)
    }

    /// Removes key. A local delete hides a cluster record on this node only.
    pub fn delete(&self, key: &str, scope: Scope) -> Result<Entry, Error> {
        self.write(key, None, true, scope)
    }

    /// Drops a local override so the cluster value applies again.
    pub fn clear_local(&self, key: &str) -> Result<(), Error> {
        let mut g = self.inner.write().unwrap();
        let had = g.local.remove(key).is_some();
        let r = self.save_locked(&g);
        drop(g);
        if had {
            self.notify();
        }
        r
    }

    fn write(&self, key: &str, raw: Option<Box<RawValue>>, del: bool, scope: Scope) -> Result<Entry, Error> {
        if key.is_empty() || !key.contains('/') {
            return Err(format!("invalid key {key:?}"));
        }
        let mut g = self.inner.write().unwrap();
        g.seq += 1;
        let version = tick(&mut g);
        let e = Entry { key: key.into(), value: raw, deleted: del, version, origin: g.node_id.clone(), seq: g.seq };
        let out = e.clone();
        if scope == Scope::Local {
            g.local.insert(key.into(), e);
        } else {
            g.cluster.insert(key.into(), e);
        }
        let r = self.save_locked(&g);
        drop(g);
        self.notify();
        r.map(|_| out)
    }

    /// Applies remote cluster entries and returns the ones that changed this
    /// store (to be gossiped onwards).
    pub fn merge(&self, input: Vec<Entry>) -> Result<Vec<Entry>, Error> {
        let mut g = self.inner.write().unwrap();
        let mut changed = Vec::new();
        for mut e in input {
            if e.version > g.clock {
                g.clock = e.version; // HLC receive rule
            }
            if g.cluster.get(&e.key).is_some_and(|cur| !newer(&e, cur)) {
                continue;
            }
            g.seq += 1;
            e.seq = g.seq;
            changed.push(e.clone());
            g.cluster.insert(e.key.clone(), e);
        }
        let mut r = Ok(());
        if !changed.is_empty() {
            r = self.save_locked(&g);
        }
        drop(g);
        if !changed.is_empty() {
            self.notify();
        }
        r.map(|_| changed)
    }

    /// Cluster entries received after seq, in arrival order, and the highest
    /// seq in the store.
    pub fn since(&self, seq: u64) -> (Vec<Entry>, u64) {
        let g = self.inner.read().unwrap();
        let mut out: Vec<Entry> = g.cluster.values().filter(|e| e.seq > seq).cloned().collect();
        out.sort_by_key(|e| e.seq);
        (out, g.seq)
    }

    pub fn seq(&self) -> u64 {
        self.inner.read().unwrap().seq
    }

    /// The effective JSON of key (local override first).
    pub fn raw(&self, key: &str) -> Option<Box<RawValue>> {
        let g = self.inner.read().unwrap();
        let e = effective(&g, key)?;
        if e.deleted {
            return None;
        }
        Some(e.value.clone().unwrap_or_else(|| RawValue::from_string("null".into()).unwrap()))
    }

    /// Whether key currently has a local override.
    pub fn is_local(&self, key: &str) -> bool {
        self.inner.read().unwrap().local.contains_key(key)
    }

    /// The live effective keys of a kind, sorted.
    pub fn keys(&self, kind: &str) -> Vec<String> {
        let g = self.inner.read().unwrap();
        let prefix = format!("{kind}/");
        let mut out: Vec<String> = g
            .local
            .keys()
            .chain(g.cluster.keys().filter(|k| !g.local.contains_key(*k)))
            .filter(|k| k.starts_with(&prefix))
            .filter(|k| effective(&g, k).is_some_and(|e| !e.deleted))
            .cloned()
            .collect();
        out.sort();
        out
    }

    /// A receiver that wakes after any change. Notifications coalesce;
    /// consumers re-read state.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    fn notify(&self) {
        self.changed.send_modify(|v| *v = v.wrapping_add(1));
    }

    fn save_locked(&self, g: &Inner) -> Result<(), Error> {
        let Some(path) = &self.path else { return Ok(()) };
        let mut cluster: Vec<&Entry> = g.cluster.values().collect();
        let mut local: Vec<&Entry> = g.local.values().collect();
        cluster.sort_by_key(|e| e.seq);
        local.sort_by_key(|e| e.seq);
        let d = Disk {
            node_id: g.node_id.clone(),
            clock: g.clock,
            seq: g.seq,
            cluster: cluster.into_iter().map(std::borrow::Cow::Borrowed).collect(),
            local: local.into_iter().map(std::borrow::Cow::Borrowed).collect(),
        };
        let b = marshal_indent(&d, " ");
        if let Some(dir) = path.parent() {
            crate::config::secure_dir(dir).map_err(|e| e.to_string())?;
        }
        let tmp = tmp_path(path);
        write_private(&tmp, &b).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())
    }

    /// Decodes the effective value of key.
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        let raw = self.raw(key)?;
        serde_json::from_str(raw.get()).ok()
    }

    /// Decodes every live record of a kind.
    pub fn list<T: DeserializeOwned>(&self, kind: &str) -> Vec<T> {
        self.keys(kind).iter().filter_map(|k| self.get(k)).collect()
    }
}

fn effective<'a>(g: &'a Inner, key: &str) -> Option<&'a Entry> {
    g.local.get(key).or_else(|| g.cluster.get(key))
}

/// Advances the hybrid logical clock.
fn tick(g: &mut Inner) -> u64 {
    let ms = g.fixed_now.unwrap_or_else(crate::util::now_ms);
    let phys = (ms as u64) << 16;
    if phys > g.clock {
        g.clock = phys;
    } else {
        g.clock += 1;
    }
    g.clock
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed(s: &Store, unix: i64) {
        s.set_fixed_now_ms(unix * 1000);
    }

    #[test]
    fn last_write_wins_converges() {
        let (a, b, c) = (Store::memory("a"), Store::memory("b"), Store::memory("c"));
        for s in [&a, &b, &c] {
            fixed(s, 1000);
        }
        a.put("forward/x", "from-a", Scope::Cluster).unwrap();
        b.put("forward/x", "from-b", Scope::Cluster).unwrap();
        c.put("forward/y", "from-c", Scope::Cluster).unwrap();
        c.delete("forward/x", Scope::Cluster).unwrap();
        let all: Vec<Vec<Entry>> = [&a, &b, &c].iter().map(|s| s.since(0).0).collect();
        let orders = [[2, 0, 1], [1, 2, 0], [0, 2, 1]];
        for (s, order) in [&a, &b, &c].iter().zip(orders) {
            for i in order {
                s.merge(all[i].clone()).unwrap();
            }
        }
        for s in [&a, &b, &c] {
            assert!(s.raw("forward/x").is_none(), "{}: forward/x should be deleted", s.node_id());
            assert_eq!(s.get::<String>("forward/y").as_deref(), Some("from-c"));
        }
    }

    #[test]
    fn newer_write_wins() {
        let (a, b) = (Store::memory("a"), Store::memory("b"));
        fixed(&a, 1000);
        fixed(&b, 2000);
        a.put("node/1", "old", Scope::Cluster).unwrap();
        b.put("node/1", "new", Scope::Cluster).unwrap();
        let ea = a.since(0).0;
        let eb = b.since(0).0;
        a.merge(eb).unwrap();
        b.merge(ea).unwrap();
        for s in [&a, &b] {
            assert_eq!(s.get::<String>("node/1").as_deref(), Some("new"));
        }
        a.put("node/1", "newest", Scope::Cluster).unwrap();
        b.merge(a.since(0).0).unwrap();
        assert_eq!(b.get::<String>("node/1").as_deref(), Some("newest"), "hlc");
    }

    #[test]
    fn local_override_not_replicated() {
        let a = Store::memory("a");
        a.put("forward/f", "cluster", Scope::Cluster).unwrap();
        a.put("forward/f", "local", Scope::Local).unwrap();
        assert_eq!(a.get::<String>("forward/f").as_deref(), Some("local"));
        assert!(a.since(0).0.iter().all(|e| e.value_str() != r#""local""#));
        a.clear_local("forward/f").unwrap();
        assert_eq!(a.get::<String>("forward/f").as_deref(), Some("cluster"));
    }

    #[test]
    fn incremental_sync_sees_late_old_entries() {
        let (a, b, c) = (Store::memory("a"), Store::memory("b"), Store::memory("c"));
        fixed(&c, 10);
        fixed(&b, 500);
        b.put("node/b", "b", Scope::Cluster).unwrap();
        let (eb, cursor) = b.since(0);
        a.merge(eb).unwrap();
        c.put("node/c", "c", Scope::Cluster).unwrap();
        b.merge(c.since(0).0).unwrap();
        a.merge(b.since(cursor).0).unwrap();
        assert!(a.raw("node/c").is_some(), "late entry lost");
    }

    #[test]
    fn persistence() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("state.json");
        let a = Store::open(Some(p.clone()), "a").unwrap();
        a.put("node/1", "x", Scope::Cluster).unwrap();
        a.put("forward/2", "y", Scope::Local).unwrap();
        let b = Store::open(Some(p), "a").unwrap();
        assert_eq!(b.get::<String>("node/1").as_deref(), Some("x"));
        assert!(b.is_local("forward/2"));
        assert_eq!(b.seq(), a.seq());
    }

    /// A state.json written by the Go build loads, including Go's `null`
    /// for an empty local list.
    #[test]
    fn reads_go_state_file() {
        let go = r#"{
 "node_id": "a1",
 "clock": 117,
 "seq": 2,
 "cluster": [
  {
   "key": "node/a1",
   "value": {
    "id": "a1",
    "name": "vps"
   },
   "version": 116,
   "origin": "a1",
   "seq": 1
  },
  {
   "key": "forward/x",
   "deleted": true,
   "version": 117,
   "origin": "a1",
   "seq": 2
  }
 ],
 "local": null
}"#;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("state.json");
        std::fs::write(&p, go).unwrap();
        let s = Store::open(Some(p), "a1").unwrap();
        assert_eq!(s.keys("node"), vec!["node/a1"]);
        assert!(s.keys("forward").is_empty());
        let n: crate::model::Node = s.get("node/a1").unwrap();
        assert_eq!(n.name, "vps");
        assert_eq!(s.seq(), 2);
    }
}
