//! Loading rules into meshgate's pf anchors (FreeBSD/pfSense).

use std::collections::HashMap;

use super::{Plan, pf_anchors, render_pf};
use crate::util::run;

const PF_SEP: &str = "#--meshgate-anchor--\n";

/// Whether we run on pfSense.
pub fn is_pfsense() -> bool {
    std::fs::read_to_string("/etc/platform").is_ok_and(|s| s.to_lowercase().contains("pfsense"))
}

/// The rules to load on this OS.
pub fn render(p: &Plan) -> String {
    let (n, r, f) = render_pf(p);
    format!("{n}{PF_SEP}{r}{PF_SEP}{f}")
}

/// Applies rendered rules into meshgate's pf anchors.
pub fn load(rendered: &str) -> Result<(), String> {
    let parts: Vec<&str> = rendered.splitn(3, PF_SEP).collect();
    if parts.len() != 3 {
        return Err("pf: bad rendered rules".into());
    }
    let (n, r, f) = (parts[0], parts[1], parts[2]);
    check_pf()?;
    let (nat, rdr, filter) = pf_anchors();
    if rdr == nat {
        // One anchor may hold both; nat must come first.
        pfctl(&format!("{n}{r}"), &["-a", &nat, "-f", "-"])?;
        return pfctl(f, &["-a", &filter, "-f", "-"]);
    }
    pfctl(n, &["-a", &nat, "-f", "-"])?;
    pfctl(r, &["-a", &rdr, "-f", "-"])?;
    pfctl(f, &["-a", &filter, "-f", "-"])
}

/// Flushes meshgate's anchors.
pub fn remove() -> Result<(), String> {
    let (nat, rdr, filter) = pf_anchors();
    let errs: Vec<String> = [&nat, &rdr, &filter].iter().filter_map(|a| pfctl("", &["-a", a, "-F", "all"]).err()).collect();
    if errs.is_empty() { Ok(()) } else { Err(errs.join("\n")) }
}

fn pfctl(stdin: &str, args: &[&str]) -> Result<(), String> {
    let o = run("pfctl", args, Some(stdin));
    if o.ok { Ok(()) } else { Err(format!("pfctl {}: {}: {}", args.join(" "), o.err, o.out.trim())) }
}

/// pf must be on and the main ruleset must evaluate our anchors.
fn check_pf() -> Result<(), String> {
    let info = run("pfctl", &["-s", "info"], None).out;
    if !info.contains("Status: Enabled") {
        return Err("pf is disabled; enable it with `pfctl -e` (always on with pfSense)".into());
    }
    let rules = run("pfctl", &["-s", "rules"], None).out;
    let nat_out = run("pfctl", &["-s", "nat"], None).out;
    let (nat, rdr, filter) = pf_anchors();
    let mut missing = vec![];
    for (kind, name) in [("nat-anchor", &nat), ("rdr-anchor", &rdr)] {
        let line = format!("{kind} \"{}/*\"", parent(name));
        if !nat_out.contains(&line) {
            missing.push(line);
        }
    }
    let fp = parent(&filter);
    if !rules.contains(&format!("\"{fp}/*\"")) {
        missing.push(format!("anchor \"{fp}/*\""));
    }
    if !missing.is_empty() {
        return Err(format!("pf main ruleset does not reference meshgate's anchors; add to /etc/pf.conf: {}", missing.join("; ")));
    }
    Ok(())
}

fn parent(anchor: &str) -> &str {
    anchor.split_once('/').map(|(a, _)| a).unwrap_or(anchor)
}

/// The interface of the IPv4 default route.
pub fn detect_wan() -> String {
    let o = run("route", &["-n", "get", "-inet", "default"], None);
    if !o.ok {
        return String::new();
    }
    for l in o.out.lines() {
        if let Some((k, v)) = l.trim().split_once(':') {
            if k == "interface" {
                return v.trim().to_string();
            }
        }
    }
    String::new()
}

/// Not implemented with pf (traffic stats come from Linux edges).
pub fn read_counters() -> Option<HashMap<String, [u64; 2]>> {
    None
}

pub fn sync_iptables(_rules: &[Vec<String>]) -> Result<(), String> {
    Ok(())
}

pub fn remove_iptables() {}
