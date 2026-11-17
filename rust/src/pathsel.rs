//! Decides how this node reaches every other node: directly or through a
//! relay (Go: internal/pathsel). Both ends of a pair must agree, so the
//! rules use only data both sides have; see the Go package for the design.
//!
//! Times are monotonic nanoseconds (`util::mono_ns`); 0 means "never".

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::gojson::zero;
use crate::model::{self, Node, Status};

pub const SEC: i64 = 1_000_000_000;
pub const MS: i64 = 1_000_000;

/// A probe success counts this long.
pub const PROBE_FRESH: i64 = 10 * SEC;
/// Peer probes keep us direct this long.
pub const INBOUND_FRESH: i64 = 12 * SEC;
const SWITCH_RATIO: f64 = 0.75;
const SWITCH_MIN_GAP: i64 = 8 * MS;

/// The latest result for one endpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Probe {
    pub last_ok: i64,
    pub rtt: i64,
}

/// How to reach one peer.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Path {
    /// Relay node ID; "" = direct.
    #[serde(skip_serializing_if = "zero")]
    pub via: String,
    /// "" = learn from handshake.
    #[serde(skip_serializing_if = "zero")]
    pub endpoint: String,
}

impl Path {
    pub fn direct(&self) -> bool {
        self.via.is_empty()
    }
}

/// The full decision for this node.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Result {
    #[serde(skip_serializing_if = "zero")]
    pub home_relay: String,
    pub paths: BTreeMap<String, Path>,
    /// Peers that answered probes recently (ours to them or theirs to us).
    /// None (Go: nil map) means unknown: everyone counts as up.
    #[serde(skip)]
    pub up: Option<HashMap<String, bool>>,
}

/// Everything the decision depends on.
pub struct Input<'a> {
    pub self_: &'a Node,
    pub nodes: &'a [Node],
    pub statuses: &'a HashMap<String, Status>,
    /// Endpoint "host:port" -> result.
    pub probes: &'a HashMap<String, Probe>,
    /// Peer node ID -> last time it probed us directly.
    pub inbound: &'a HashMap<String, i64>,
    pub prev: Option<&'a Result>,
    pub now: i64,
}

fn since(now: i64, t: i64) -> i64 {
    if t == 0 { i64::MAX } else { now.saturating_sub(t) }
}

/// Computes paths for every peer.
pub fn decide(input: &Input) -> Result {
    let by_id: HashMap<&str, &Node> = input.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let mut relays: Vec<&Node> = input.nodes.iter().filter(|n| n.id != input.self_.id && is_relay(n)).collect();
    relays.sort_by(|a, b| a.id.cmp(&b.id));

    let mut res = Result { up: Some(HashMap::new()), ..Default::default() };
    if !is_relay(input.self_) {
        res.home_relay = pick_home_relay(input, &relays);
    }
    for p in input.nodes {
        if p.id == input.self_.id {
            continue;
        }
        let path = decide_one(input, &by_id, &relays, &res.home_relay, p);
        res.paths.insert(p.id.clone(), path);
        let mut up = since(input.now, input.inbound.get(&p.id).copied().unwrap_or(0)) < INBOUND_FRESH;
        for ep in &p.endpoints {
            if input.probes.get(ep).is_some_and(|pr| since(input.now, pr.last_ok) <= PROBE_FRESH) {
                up = true;
            }
        }
        res.up.get_or_insert_default().insert(p.id.clone(), up);
    }
    res
}

/// Whether n can act as a relay.
pub fn is_relay(n: &Node) -> bool {
    n.relay && n.kind == model::NODE_SERVER && !n.endpoints.is_empty()
}

fn decide_one(input: &Input, by_id: &HashMap<&str, &Node>, relays: &[&Node], home_relay: &str, p: &Node) -> Path {
    let prev = input.prev.and_then(|r| r.paths.get(&p.id));
    let mut ep = best_endpoint(input, p, prev);

    if is_relay(p) {
        // Relays are always reached directly at their public endpoint.
        if ep.is_empty() {
            ep = p.endpoints[0].clone();
        }
        return Path { via: String::new(), endpoint: ep };
    }
    if p.kind == model::NODE_STATIC {
        // Stock WireGuard app: only ever talks to its pinned relay.
        if p.via_relay == input.self_.id {
            return Path::default();
        }
        if by_id.contains_key(p.via_relay.as_str()) {
            return Path { via: p.via_relay.clone(), endpoint: String::new() };
        }
        return Path::default();
    }
    if is_relay(input.self_) || !ep.is_empty() {
        return Path { via: String::new(), endpoint: ep };
    }
    if since(input.now, input.inbound.get(&p.id).copied().unwrap_or(0)) < INBOUND_FRESH {
        return Path::default(); // peer reaches us directly
    }
    if relays.is_empty() {
        // No relays configured: best effort direct.
        return Path { via: String::new(), endpoint: p.endpoints.first().cloned().unwrap_or_default() };
    }
    let mut relay = home_relay.to_string();
    let anchor = anchor(input.self_, p);
    if anchor.id != input.self_.id
        && let Some(st) = input.statuses.get(&anchor.id).filter(|st| !st.home_relay.is_empty())
    {
        relay = st.home_relay.clone();
    }
    if !by_id.get(relay.as_str()).is_some_and(|r| is_relay(r)) {
        relay = home_relay.to_string();
    }
    Path { via: relay, endpoint: String::new() }
}

/// The node of the pair whose home relay the pair uses: the more mobile node
/// (client before server), then the lower ID.
pub fn anchor<'a>(a: &'a Node, b: &'a Node) -> &'a Node {
    let (ra, rb) = (mobility(a), mobility(b));
    if ra != rb {
        return if ra > rb { a } else { b };
    }
    if a.id < b.id { a } else { b }
}

fn mobility(n: &Node) -> i32 {
    if n.kind == model::NODE_CLIENT { 1 } else { 0 }
}

/// The fastest freshly-probed endpoint of p, or "".
fn best_endpoint(input: &Input, p: &Node, prev: Option<&Path>) -> String {
    let (mut best, mut best_rtt) = (String::new(), 0i64);
    for ep in &p.endpoints {
        let Some(pr) = input.probes.get(ep) else { continue };
        if since(input.now, pr.last_ok) > PROBE_FRESH {
            continue;
        }
        if best.is_empty() || pr.rtt < best_rtt {
            best = ep.clone();
            best_rtt = pr.rtt;
        }
    }
    // Stick with the previous endpoint unless the new one is clearly better.
    if let Some(prev) = prev
        && prev.direct()
        && !prev.endpoint.is_empty()
        && prev.endpoint != best
        && !best.is_empty()
        && let Some(pr) = input.probes.get(&prev.endpoint)
        && since(input.now, pr.last_ok) <= PROBE_FRESH
        && !clearly_better(best_rtt, pr.rtt)
    {
        return prev.endpoint.clone();
    }
    best
}

fn pick_home_relay(input: &Input, relays: &[&Node]) -> String {
    if relays.is_empty() {
        return String::new();
    }
    let mut ok: Vec<(String, i64)> = Vec::new();
    let mut rtt_of: HashMap<&str, i64> = HashMap::new();
    for r in relays {
        let mut best = -1i64;
        for ep in &r.endpoints {
            let Some(pr) = input.probes.get(ep) else { continue };
            if since(input.now, pr.last_ok) > PROBE_FRESH {
                continue;
            }
            if best < 0 || pr.rtt < best {
                best = pr.rtt;
            }
        }
        if best >= 0 {
            ok.push((r.id.clone(), best));
            rtt_of.insert(&r.id, best);
        }
    }
    let prev = input.prev.map(|p| p.home_relay.as_str()).unwrap_or("");
    if ok.is_empty() {
        // Nothing answers right now; keep what we had rather than flapping.
        if relays.iter().any(|r| r.id == prev) {
            return prev.to_string();
        }
        return relays[0].id.clone();
    }
    ok.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    let best = &ok[0];
    if let Some(&prev_rtt) = rtt_of.get(prev)
        && prev != best.0
        && !clearly_better(best.1, prev_rtt)
    {
        return prev.to_string();
    }
    best.0.clone()
}

fn clearly_better(new_rtt: i64, old_rtt: i64) -> bool {
    (new_rtt as f64) < (old_rtt as f64) * SWITCH_RATIO && old_rtt - new_rtt >= SWITCH_MIN_GAP
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 100_000 * SEC;

    fn node(id: &str, kind: &str, relay: bool, ep: &[&str]) -> Node {
        Node { id: id.into(), kind: kind.into(), relay, endpoints: ep.iter().map(|s| s.to_string()).collect(), ..Default::default() }
    }

    fn nodes() -> Vec<Node> {
        let mut home = node("home", "server", false, &["192.168.1.10:51820"]);
        home.routes = vec!["192.168.1.0/24".into()];
        vec![
            node("phone", "client", false, &[]),
            home,
            node("vps1", "server", true, &["1.1.1.1:51820"]),
            node("vps2", "server", true, &["2.2.2.2:51820"]),
        ]
    }

    fn ok(rtt: i64) -> Probe {
        Probe { last_ok: NOW - SEC, rtt: rtt * MS }
    }

    fn probes(p: &[(&str, Probe)]) -> HashMap<String, Probe> {
        p.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    fn run(
        self_id: &str,
        all: &[Node],
        pr: &HashMap<String, Probe>,
        st: &HashMap<String, Status>,
        inb: &HashMap<String, i64>,
        prev: Option<&Result>,
    ) -> Result {
        let me = all.iter().find(|n| n.id == self_id).unwrap();
        decide(&Input { self_: me, nodes: all, statuses: st, probes: pr, inbound: inb, prev, now: NOW })
    }

    #[test]
    fn phone_on_home_wifi_goes_direct() {
        let ns = nodes();
        let e = HashMap::new();
        let r = run(
            "phone",
            &ns,
            &probes(&[("192.168.1.10:51820", ok(2)), ("1.1.1.1:51820", ok(30)), ("2.2.2.2:51820", ok(60))]),
            &HashMap::new(),
            &e,
            None,
        );
        let p = &r.paths["home"];
        assert!(p.direct() && p.endpoint == "192.168.1.10:51820", "{p:?}");
        let inb = HashMap::from([("phone".to_string(), NOW - 2 * SEC)]);
        let h = run("home", &ns, &probes(&[("1.1.1.1:51820", ok(30)), ("2.2.2.2:51820", ok(40))]), &HashMap::new(), &inb, None);
        let p = &h.paths["phone"];
        assert!(p.direct() && p.endpoint.is_empty(), "{p:?}");
    }

    #[test]
    fn phone_on_lte_uses_nearest_relay_symmetrically() {
        let ns = nodes();
        let e = HashMap::new();
        let r = run("phone", &ns, &probes(&[("1.1.1.1:51820", ok(80)), ("2.2.2.2:51820", ok(20))]), &HashMap::new(), &e, None);
        assert_eq!(r.home_relay, "vps2");
        assert_eq!(r.paths["home"].via, "vps2");
        let st = HashMap::from([(
            "phone".to_string(),
            Status { node_id: "phone".into(), home_relay: r.home_relay.clone(), ..Default::default() },
        )]);
        let h = run("home", &ns, &probes(&[("1.1.1.1:51820", ok(5)), ("2.2.2.2:51820", ok(50))]), &st, &e, None);
        assert_eq!(h.home_relay, "vps1");
        assert_eq!(h.paths["phone"].via, "vps2", "asymmetric");
        let p = &h.paths["vps2"];
        assert!(p.direct() && p.endpoint == "2.2.2.2:51820");
    }

    #[test]
    fn relay_talks_direct_to_everyone() {
        let ns = nodes();
        let e = HashMap::new();
        let r = run("vps1", &ns, &HashMap::new(), &HashMap::new(), &e, None);
        for id in ["phone", "home", "vps2"] {
            assert!(r.paths[id].direct(), "relay->{id}");
        }
        assert!(r.home_relay.is_empty());
    }

    #[test]
    fn home_relay_hysteresis() {
        let ns = nodes();
        let e = HashMap::new();
        let prev = Result { home_relay: "vps1".into(), ..Default::default() };
        let r = run("phone", &ns, &probes(&[("1.1.1.1:51820", ok(30)), ("2.2.2.2:51820", ok(26))]), &HashMap::new(), &e, Some(&prev));
        assert_eq!(r.home_relay, "vps1", "flapped");
        let r = run("phone", &ns, &probes(&[("1.1.1.1:51820", ok(60)), ("2.2.2.2:51820", ok(15))]), &HashMap::new(), &e, Some(&prev));
        assert_eq!(r.home_relay, "vps2", "did not switch");
        let dead = Probe { last_ok: NOW - 60 * SEC, rtt: 0 };
        let r = run("phone", &ns, &probes(&[("1.1.1.1:51820", dead), ("2.2.2.2:51820", ok(90))]), &HashMap::new(), &e, Some(&prev));
        assert_eq!(r.home_relay, "vps2", "did not fail over");
    }

    #[test]
    fn static_device_routed_via_its_relay() {
        let mut all = nodes();
        let mut st = node("laptop", "static", false, &[]);
        st.via_relay = "vps1".into();
        all.push(st);
        let (e, s, p) = (HashMap::new(), HashMap::new(), HashMap::new());
        assert_eq!(run("home", &all, &p, &s, &e, None).paths["laptop"].via, "vps1");
        assert!(run("vps1", &all, &p, &s, &e, None).paths["laptop"].direct());
        assert_eq!(run("vps2", &all, &p, &s, &e, None).paths["laptop"].via, "vps1");
    }

    #[test]
    fn anchor_symmetric() {
        let ns = nodes();
        for (a, b) in [(0, 1), (1, 2), (2, 3)] {
            assert_eq!(anchor(&ns[a], &ns[b]).id, anchor(&ns[b], &ns[a]).id);
        }
    }
}
