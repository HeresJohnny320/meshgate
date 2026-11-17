//! Keeps the host's own firewall (ufw or firewalld) open for what a Linux
//! server needs from outside (Go: internal/hostfw). meshgate only ever
//! deletes rules it added itself (listed in hostfw.json); a rule the admin
//! already had is left alone.

use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::fw::Plan;
use crate::gojson::{nullable, zero};

pub const UFW: &str = "ufw";
pub const FIREWALLD: &str = "firewalld";

/// One opening in the host firewall.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Rule {
    pub proto: String,
    pub lo: i64,
    pub hi: i64,
    /// A forward's target after DNAT ("" = served by this host).
    pub to: String,
    pub to_lo: i64,
    pub to_hi: i64,
    pub note: String,
}

/// The rules a node's firewall plan needs.
pub fn wanted(p: &Plan) -> Vec<Rule> {
    let mut out: Vec<Rule> = p
        .host_open
        .iter()
        .map(|h| Rule { proto: h.proto.clone(), lo: h.port, hi: h.port, note: h.note.clone(), ..Default::default() })
        .collect();
    for d in &p.dnat {
        let (to_lo, to_hi) = if d.dst_port == 0 { (d.lo, d.hi) } else { (d.dst_port, d.dst_port) };
        for proto in &d.protos {
            out.push(Rule {
                proto: proto.clone(),
                lo: d.lo,
                hi: d.hi,
                to: d.dst.clone(),
                to_lo,
                to_hi,
                note: format!("forward {}", d.name),
            });
        }
    }
    out
}

/// A rule as one backend spells it (hostfw.json).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Entry {
    pub key: String,
    #[serde(deserialize_with = "nullable")]
    pub args: Vec<String>,
    pub note: String,
    #[serde(skip_serializing_if = "zero")]
    pub theirs: bool,
}

fn ports(lo: i64, hi: i64, sep: &str) -> String {
    if hi > lo { format!("{lo}{sep}{hi}") } else { lo.to_string() }
}

/// Keeps a comment safe as one command-line argument for ufw.
fn sanitize(s: &str) -> String {
    let mut s: String = s.chars().map(|r| if r < ' ' || r == '\'' || r == '"' || r == '\\' { ' ' } else { r }).collect();
    if s.len() > 60 {
        let mut cut = 60;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    format!("meshgate: {s}")
}

/// Turns rules into one backend's entries, without duplicates.
fn spell(backend: &str, rules: &[Rule]) -> Vec<Entry> {
    let mut seen = HashSet::new();
    let mut out = vec![];
    for r in rules {
        let mut e = Entry::default();
        match backend {
            UFW => {
                e.args = if r.to.is_empty() {
                    ["allow", "proto", &r.proto, "to", "any", "port", &ports(r.lo, r.hi, ":")].map(String::from).to_vec()
                } else {
                    ["route", "allow", "proto", &r.proto, "to", &r.to, "port", &ports(r.to_lo, r.to_hi, ":")].map(String::from).to_vec()
                };
                e.key = e.args.join(" ");
            }
            FIREWALLD => {
                e.key = format!("{}/{}", ports(r.lo, r.hi, "-"), r.proto);
                e.args = vec![e.key.clone()];
            }
            _ => continue,
        }
        e.note = sanitize(&r.note);
        if seen.insert(e.key.clone()) {
            out.push(e);
        }
    }
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

/// What meshgate added, kept so it can be removed again.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct State {
    backend: String,
    #[serde(deserialize_with = "nullable")]
    rules: Vec<Entry>,
}

fn load(path: &Path) -> State {
    std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save(path: &Path, st: &State) -> Result<(), String> {
    if st.rules.is_empty() {
        return match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
            _ => Ok(()),
        };
    }
    crate::config::write_private(path, &crate::gojson::marshal_indent(st, "  ")).map_err(|e| e.to_string())
}

/// Applies entries with one backend; add reports Ok(true) when the rule
/// was already there (the admin's own).
trait Runner {
    fn add(&mut self, e: &Entry) -> Result<bool, String>;
    fn del(&mut self, e: &Entry) -> Result<(), String>;
}

/// Brings the host firewall from st to want and returns the new state.
fn reconcile(mut st: State, backend: &str, want: Vec<Entry>, cur: &mut dyn Runner, old: Option<&mut dyn Runner>) -> (State, Vec<String>) {
    let mut errs = vec![];
    if !st.backend.is_empty() && st.backend != backend {
        if let Some(old) = old {
            for e in st.rules.iter().filter(|e| !e.theirs) {
                if let Err(err) = old.del(e) {
                    errs.push(err);
                }
            }
        }
        st = State::default();
    }
    let wanted: HashSet<&str> = want.iter().map(|e| e.key.as_str()).collect();
    let mut next = State { backend: backend.into(), rules: vec![] };
    let mut have = HashSet::new();
    for e in st.rules {
        if wanted.contains(e.key.as_str()) {
            have.insert(e.key.clone());
            next.rules.push(e);
            continue;
        }
        if !e.theirs
            && let Err(err) = cur.del(&e)
        {
            errs.push(err);
            next.rules.push(e); // try again next time
        }
    }
    for mut e in want {
        if have.contains(&e.key) {
            continue;
        }
        match cur.add(&e) {
            Err(err) => errs.push(err),
            Ok(existed) => {
                e.theirs = existed;
                next.rules.push(e);
            }
        }
    }
    next.rules.sort_by(|a, b| a.key.cmp(&b.key));
    if next.rules.is_empty() {
        next.backend.clear();
    }
    (next, errs)
}

struct Nop;
impl Runner for Nop {
    fn add(&mut self, _: &Entry) -> Result<bool, String> {
        Ok(false)
    }
    fn del(&mut self, _: &Entry) -> Result<(), String> {
        Ok(())
    }
}

struct Ufw;
impl Runner for Ufw {
    fn add(&mut self, e: &Entry) -> Result<bool, String> {
        let mut a: Vec<&str> = e.args.iter().map(String::as_str).collect();
        a.extend(["comment", &e.note]);
        let o = crate::util::run("ufw", &a, None);
        if !o.ok {
            return Err(format!("ufw {}: {}: {}", e.key, o.err, o.out.trim()));
        }
        // "Skipping adding existing rule" for every family = the admin's own.
        Ok(!o.out.contains("Rule added"))
    }

    fn del(&mut self, e: &Entry) -> Result<(), String> {
        let mut a: Vec<&str> = if e.args.first().map(String::as_str) == Some("route") {
            let mut v = vec!["route", "delete"];
            v.extend(e.args[1..].iter().map(String::as_str));
            v
        } else {
            let mut v = vec!["delete"];
            v.extend(e.args.iter().map(String::as_str));
            v
        };
        a.extend(["comment", &e.note]);
        let o = crate::util::run("ufw", &a, None);
        if !o.ok && !o.out.contains("non-existent") {
            return Err(format!("ufw delete {}: {}: {}", e.key, o.err, o.out.trim()));
        }
        Ok(())
    }
}

struct Firewalld;
impl Runner for Firewalld {
    fn add(&mut self, e: &Entry) -> Result<bool, String> {
        let port = &e.args[0];
        if crate::util::run("firewall-cmd", &["-q", "--permanent", &format!("--query-port={port}")], None).ok {
            return Ok(true);
        }
        for perm in [true, false] {
            let arg = format!("--add-port={port}");
            let a: Vec<&str> = if perm { vec!["-q", "--permanent", &arg] } else { vec!["-q", &arg] };
            let o = crate::util::run("firewall-cmd", &a, None);
            if !o.ok {
                return Err(format!("firewall-cmd --add-port={port}: {}: {}", o.err, o.out.trim()));
            }
        }
        Ok(false)
    }

    fn del(&mut self, e: &Entry) -> Result<(), String> {
        let port = &e.args[0];
        let mut errs = vec![];
        for perm in [true, false] {
            let arg = format!("--remove-port={port}");
            let a: Vec<&str> = if perm { vec!["-q", "--permanent", &arg] } else { vec!["-q", &arg] };
            let o = crate::util::run("firewall-cmd", &a, None);
            if !o.ok && !o.out.contains("NOT_ENABLED") {
                errs.push(o.out.trim().to_string());
            }
        }
        if errs.is_empty() { Ok(()) } else { Err(format!("firewall-cmd --remove-port={port}: {}", errs.join("; "))) }
    }
}

/// The active host firewall: ufw, firewalld or "" (none). Linux only.
pub fn detect() -> String {
    if !cfg!(target_os = "linux") {
        return String::new();
    }
    if crate::util::look_path("firewall-cmd") && crate::util::run("firewall-cmd", &["--state"], None).ok {
        return FIREWALLD.into();
    }
    if crate::util::look_path("ufw") && crate::util::output("ufw", &["status"]).is_some_and(|o| o.contains("Status: active")) {
        return UFW.into();
    }
    String::new()
}

fn runner_for(backend: &str) -> Option<Box<dyn Runner>> {
    match backend {
        UFW if crate::util::look_path("ufw") => Some(Box::new(Ufw)),
        FIREWALLD if crate::util::look_path("firewall-cmd") => Some(Box::new(Firewalld)),
        _ => None,
    }
}

/// Makes the active host firewall hold exactly rules (plus whatever the
/// admin added); off removes everything meshgate added. Returns the backend.
pub fn sync(state_path: &Path, rules: &[Rule], off: bool) -> Result<String, String> {
    if !cfg!(target_os = "linux") {
        return Ok(String::new());
    }
    let st = load(state_path);
    let mut backend = if off { String::new() } else { detect() };
    let mut want = vec![];
    let mut cur = runner_for(&backend);
    if cur.is_none() {
        backend.clear();
        cur = Some(Box::new(Nop));
    } else {
        want = spell(&backend, rules);
    }
    let mut old = runner_for(&st.backend);
    let mut cur = cur.unwrap();
    let old_ref: Option<&mut dyn Runner> = match old.as_mut() {
        Some(b) => Some(&mut **b),
        None => None,
    };
    let (next, mut errs) = reconcile(st, &backend, want, &mut *cur, old_ref);
    if let Err(e) = save(state_path, &next) {
        errs.push(e);
    }
    if errs.is_empty() { Ok(backend) } else { Err(errs.join("; ")) }
}

/// Deletes every rule meshgate added (meshgate leave).
pub fn remove_all(state_path: &Path) {
    let _ = sync(state_path, &[], true);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fw::{Dnat, HostPort};

    #[test]
    fn wanted_and_spell() {
        let p = Plan {
            host_open: vec![
                HostPort { proto: "udp".into(), port: 51820, note: "wireguard".into() },
                HostPort { proto: "tcp".into(), port: 443, note: "https routes".into() },
            ],
            dnat: vec![
                Dnat {
                    name: "minecraft".into(),
                    protos: vec!["tcp".into()],
                    lo: 25565,
                    hi: 25565,
                    dst: "192.168.1.50".into(),
                    dst_port: 25566,
                    ..Default::default()
                },
                Dnat {
                    name: "valheim".into(),
                    protos: vec!["udp".into()],
                    lo: 2456,
                    hi: 2458,
                    dst: "100.88.0.5".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let rules = wanted(&p);
        let ufw: Vec<String> = spell(UFW, &rules).into_iter().map(|e| e.key).collect();
        assert_eq!(
            ufw,
            [
                "allow proto tcp to any port 443",
                "allow proto udp to any port 51820",
                "route allow proto tcp to 192.168.1.50 port 25566",
                "route allow proto udp to 100.88.0.5 port 2456:2458"
            ]
        );
        let fwd: Vec<String> = spell(FIREWALLD, &rules).into_iter().map(|e| e.key).collect();
        assert_eq!(fwd, ["2456-2458/udp", "25565/tcp", "443/tcp", "51820/udp"]);
    }

    #[test]
    fn sanitize_comment() {
        assert_eq!(sanitize("it's \"x\"\\"), "meshgate: it s  x  ");
    }

    #[derive(Default)]
    struct Fake {
        existing: HashSet<String>,
        added: Vec<String>,
        gone: Vec<String>,
    }
    impl Runner for Fake {
        fn add(&mut self, e: &Entry) -> Result<bool, String> {
            if self.existing.contains(&e.key) {
                return Ok(true);
            }
            self.added.push(e.key.clone());
            Ok(false)
        }
        fn del(&mut self, e: &Entry) -> Result<(), String> {
            self.gone.push(e.key.clone());
            Ok(())
        }
    }

    #[test]
    fn reconcile_rules() {
        let mc = Rule {
            proto: "tcp".into(),
            lo: 25565,
            hi: 25565,
            to: "192.168.1.50".into(),
            to_lo: 25565,
            to_hi: 25565,
            note: "forward mc".into(),
        };
        let web = Rule { proto: "tcp".into(), lo: 443, hi: 443, note: "https routes".into(), ..Default::default() };

        let mut f = Fake { existing: HashSet::from(["allow proto tcp to any port 443".to_string()]), ..Default::default() };
        let (st, errs) = reconcile(State::default(), UFW, spell(UFW, &[mc.clone(), web.clone()]), &mut f, None);
        assert!(errs.is_empty());
        assert_eq!(f.added, ["route allow proto tcp to 192.168.1.50 port 25565"]);

        let mut f = Fake::default();
        let mut g = Fake::default();
        let (st, _) = reconcile(st, UFW, vec![], &mut f, Some(&mut g));
        assert_eq!(f.gone, ["route allow proto tcp to 192.168.1.50 port 25565"]);
        assert!(st.rules.is_empty() && st.backend.is_empty());

        let (mut old, mut cur) = (Fake::default(), Fake::default());
        let (st, _) = reconcile(State::default(), UFW, spell(UFW, std::slice::from_ref(&web)), &mut old, None);
        let (st, _) = reconcile(st, FIREWALLD, spell(FIREWALLD, std::slice::from_ref(&web)), &mut cur, Some(&mut old));
        assert_eq!(old.gone, ["allow proto tcp to any port 443"]);
        assert_eq!(cur.added, ["443/tcp"]);
        assert_eq!(st.backend, FIREWALLD);
        assert_eq!(st.rules.iter().map(|e| e.key.as_str()).collect::<Vec<_>>(), ["443/tcp"]);

        let mut f = Fake::default();
        reconcile(st, FIREWALLD, spell(FIREWALLD, &[web]), &mut f, None);
        assert!(f.added.is_empty() && f.gone.is_empty());
    }
}
