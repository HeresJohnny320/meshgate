//! Link watch (Go: internal/agent/linkwatch.go): leaves a trace in the log
//! when a link to another server drops, comes back or changes path, and
//! when warnings appear or clear.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use super::Agent;
use crate::model::{self, Node};
use crate::pathsel;
use crate::wg::PeerStat;

/// WireGuard renews a session every 2 minutes and drops it after 3.
const LINK_DEAD_AFTER: i64 = 180;

#[derive(Default)]
pub struct LinkWatch {
    down: HashMap<String, Instant>,
    path: HashMap<String, String>,
    warn: HashSet<String>,
    checked: Option<Instant>,
}

/// Go's Duration.Round(time.Second).String().
pub fn dur(secs: i64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h{m}m{s}s")
    } else if m > 0 {
        format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

/// Whether a direct link is dead, and why.
pub fn link_state(st: &PeerStat, probes_ok: bool, now: i64, running: i64) -> (String, bool) {
    if running < LINK_DEAD_AFTER {
        return (String::new(), false); // give the first handshake time
    }
    let hs = st.last_handshake.0;
    if hs != 0 && now - hs <= LINK_DEAD_AFTER {
        return (String::new(), false);
    }
    let mut msg = "no WireGuard handshake".to_string();
    if hs == 0 {
        msg.push_str(" since meshgate started");
    } else {
        let (_, _, _, h, m, s, _) = crate::logx::local(hs);
        msg.push_str(&format!(" since {h:02}:{m:02}:{s:02} ({} ago)", dur(now - hs)));
    }
    if !st.endpoint.is_empty() {
        msg.push_str(&format!(", endpoint {}", st.endpoint));
    }
    if probes_ok {
        msg.push_str("; its meshgate still answers probes, so the tunnel itself is broken (interface, keys or port)");
    } else {
        msg.push_str("; it does not answer probes either (offline, or the path to it is blocked)");
    }
    (msg, true)
}

impl Agent {
    /// Runs at the end of every reconcile.
    pub(super) fn watch_links(&self, nodes: &[Node], res: &pathsel::Result, warn: &[String]) {
        let mut lw = self.links.lock().unwrap();
        let cur: HashSet<String> = warn.iter().cloned().collect();
        for w in warn {
            if !lw.warn.contains(w) {
                logf!("warning: {w}");
            }
        }
        for w in lw.warn.iter() {
            if !cur.contains(w) {
                logf!("resolved: {w}");
            }
        }
        lw.warn = cur;
        // Handshakes change slowly; every 15 seconds is plenty.
        if lw.checked.is_some_and(|t| t.elapsed() < Duration::from_secs(15)) {
            return;
        }
        lw.checked = Some(Instant::now());
        let names: HashMap<&str, &str> = nodes.iter().map(|n| (n.id.as_str(), n.name.as_str())).collect();
        let me = nodes.iter().find(|n| n.id == self.cfg.node_id).cloned().unwrap_or_default();
        let stats = self.wg.stats();
        let now = crate::util::now_unix();
        let running = self.started.elapsed().as_secs() as i64;
        for n in nodes {
            if n.id == self.cfg.node_id || n.kind != model::NODE_SERVER {
                continue; // phones come and go; only server links are watched
            }
            let Some(p) = res.paths.get(&n.id) else { continue };
            let path = if p.direct() { "direct".to_string() } else { format!("via {}", names.get(p.via.as_str()).copied().unwrap_or("")) };
            if let Some(old) = lw.path.get(&n.id)
                && *old != path
            {
                logf!("path to {}: {old} -> {path}", n.name);
            }
            lw.path.insert(n.id.clone(), path);
            if !p.direct() {
                lw.down.remove(&n.id); // no tunnel of our own to it
                continue;
            }
            let up = res.up.as_ref().is_some_and(|u| u.get(&n.id).copied().unwrap_or(false));
            let (msg, dead) = link_state(&stats.get(&n.public_key).cloned().unwrap_or_default(), up, now, running);
            match (dead, lw.down.get(&n.id).copied()) {
                (true, None) => {
                    lw.down.insert(n.id.clone(), Instant::now());
                    logf!("link to {} DOWN: {msg}", n.name);
                    self.beep_for(&me, true);
                }
                (false, Some(since)) => {
                    lw.down.remove(&n.id);
                    logf!("link to {} UP again after {}", n.name, dur(since.elapsed().as_secs_f64().round() as i64));
                    self.beep_for(&me, false);
                }
                _ => {}
            }
        }
    }

    /// Names this node's WireGuard interface instance for the probes' boot
    /// ID; it changes only when the interface (and its sessions) is new.
    pub(super) fn tunnel_id(&self, created: bool) -> String {
        let path = std::path::Path::new(&self.cfg.data_dir).join("tunnel-id");
        if !created
            && let Ok(s) = std::fs::read_to_string(&path)
            && !s.trim().is_empty()
        {
            return s.trim().to_string();
        }
        let id = crate::probe::new_boot_id();
        let _ = crate::config::write_private(&path, format!("{id}\n").as_bytes());
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_states() {
        let now = 1_000_000;
        let fresh = PeerStat { last_handshake: (now - 60, 0), ..Default::default() };
        assert!(!link_state(&fresh, false, now, 3600).1);
        let old = PeerStat { last_handshake: (now - 400, 0), endpoint: "1.2.3.4:51820".into(), ..Default::default() };
        let (msg, dead) = link_state(&old, true, now, 3600);
        assert!(dead && msg.contains("(6m40s ago)") && msg.contains("endpoint 1.2.3.4:51820") && msg.contains("tunnel itself is broken"));
        assert!(!link_state(&PeerStat::default(), false, now, 60).1, "grace period after start");
        let (msg, dead) = link_state(&PeerStat::default(), false, now, 3600);
        assert!(dead && msg.contains("since meshgate started") && msg.contains("does not answer probes"));
        assert_eq!(dur(3725), "1h2m5s");
    }
}
