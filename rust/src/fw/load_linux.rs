//! Loading rules on Linux: nftables table `inet meshgate` and the iptables
//! MESHGATE chain.

use std::collections::HashMap;

use super::{Plan, render_nft};
use crate::util::{look_path, run};

/// The rules to load on this OS.
pub fn render(p: &Plan) -> String {
    render_nft(p)
}

/// Applies rendered rules.
pub fn load(rendered: &str) -> Result<(), String> {
    let o = run("nft", &["-f", "-"], Some(rendered));
    if o.ok { Ok(()) } else { Err(format!("nft: {}: {}", o.err, o.out.trim())) }
}

/// Deletes meshgate's rules.
pub fn remove() -> Result<(), String> {
    remove_iptables();
    load("table inet meshgate\ndelete table inet meshgate\n")
}

/// Only needed for pf.
pub fn detect_wan() -> String {
    String::new()
}

pub fn is_pfsense() -> bool {
    false
}

/// meshgate's nft counters (name -> packets, bytes). They restart from
/// zero whenever the table is reloaded.
pub fn read_counters() -> Option<HashMap<String, [u64; 2]>> {
    let out = crate::util::output("nft", &["-j", "list", "counters", "table", "inet", "meshgate"])?;
    #[derive(serde::Deserialize)]
    struct Counter {
        #[serde(default)]
        name: String,
        #[serde(default)]
        packets: u64,
        #[serde(default)]
        bytes: u64,
    }
    #[derive(serde::Deserialize)]
    struct Item {
        counter: Option<Counter>,
    }
    #[derive(serde::Deserialize)]
    struct Doc {
        #[serde(default)]
        nftables: Vec<Item>,
    }
    let doc: Doc = serde_json::from_str(&out).ok()?;
    Some(doc.nftables.into_iter().filter_map(|i| i.counter).map(|c| (c.name, [c.packets, c.bytes])).collect())
}

fn ipt(args: &[&str]) -> Result<(), String> {
    let mut a = vec!["-w", "5"];
    a.extend_from_slice(args);
    let o = run("iptables", &a, None);
    if o.ok { Ok(()) } else { Err(format!("iptables {}: {}: {}", args.join(" "), o.err, o.out.trim())) }
}

/// Makes the MESHGATE chain hold exactly `rules` and keeps it at the top of
/// iptables' FORWARD chain (ufw and Docker set FORWARD's policy to DROP).
pub fn sync_iptables(rules: &[Vec<String>]) -> Result<(), String> {
    if !look_path("iptables") {
        return Ok(()); // no iptables: nothing can block us there
    }
    let _ = ipt(&["-N", "MESHGATE"]); // fails harmlessly when it exists
    ipt(&["-F", "MESHGATE"])?;
    for r in rules {
        let mut a = vec!["-A", "MESHGATE"];
        a.extend(r.iter().map(String::as_str));
        ipt(&a)?;
    }
    if ipt(&["-C", "FORWARD", "-j", "MESHGATE"]).is_err() {
        return ipt(&["-I", "FORWARD", "1", "-j", "MESHGATE"]);
    }
    Ok(())
}

/// Deletes the MESHGATE chain.
pub fn remove_iptables() {
    if !look_path("iptables") {
        return;
    }
    while run("iptables", &["-w", "5", "-D", "FORWARD", "-j", "MESHGATE"], None).ok {}
    run("iptables", &["-w", "5", "-F", "MESHGATE"], None);
    run("iptables", &["-w", "5", "-X", "MESHGATE"], None);
}
