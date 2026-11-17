//! The TUI's share of the web UI's Traffic, Tools, Logs and Settings tabs
//! (Go: internal/tui/extra.go and logs.go).

use std::collections::{BTreeMap, HashMap};

use serde::Deserialize;

use super::form::{Action, Form, opt};
use super::view::{human_bits, human_bytes, marker};
use super::*;
use crate::events::Entry;
use crate::traffic::Rate;

// ---------------------------------------------------------- TRAFFIC: live

/// One line of the live view.
#[derive(Clone, Debug, Default)]
pub struct LiveRow {
    pub header: String,
    pub label: String,
    pub detail: String,
    pub rate: Rate,
    pub monitor: String,
    pub text: String,
}

fn add(t: &mut Rate, r: &Rate) {
    t.in_ += r.in_;
    t.out += r.out;
    t.in_rate += r.in_rate;
    t.out_rate += r.out_rate;
}

pub fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() > n { s.chars().take(n - 1).collect::<String>() + "…" } else { s.into() }
}

/// "tcp 192.168.1.51:25566", "any 10.0.0.0/24", "udp port 19132".
fn monitor_match(m: &Monitor) -> String {
    let proto = super::view::proto_label(&m.proto);
    if m.ip.is_empty() {
        return format!("{proto} port {}", m.ports);
    }
    if !m.ports.is_empty() {
        return format!("{proto} {}:{}", m.ip, m.ports);
    }
    format!("{proto} {}", m.ip)
}

impl Model {
    /// Every server's report summed like the web UI's Traffic tab.
    pub fn live_rows(&self) -> Vec<LiveRow> {
        let s = st();
        let (mut fwd, mut routes, mut mons): (HashMap<String, Rate>, HashMap<String, crate::traffic::Route>, HashMap<String, Rate>) =
            Default::default();
        let mut rules: HashMap<String, u64> = HashMap::new();
        let mut recent = vec![];
        let mut links: BTreeMap<String, (String, String, Rate)> = BTreeMap::new();
        for t in &self.traffic {
            for (id, r) in &t.forwards {
                add(fwd.entry(id.clone()).or_default(), r);
            }
            for (id, r) in &t.monitors {
                add(mons.entry(id.clone()).or_default(), r);
            }
            for (id, r) in &t.routes {
                let v = routes.entry(id.clone()).or_default();
                add(&mut v.rate, &r.rate);
                v.requests += r.requests;
                v.errors += r.errors;
            }
            for (id, n) in &t.acls {
                *rules.entry(id.clone()).or_default() += n;
            }
            // A link between two servers is measured at both ends: keep one.
            for (peer, r) in &t.peers {
                let (a, b) = if t.node > *peer { (peer.clone(), t.node.clone()) } else { (t.node.clone(), peer.clone()) };
                let k = format!("{a}|{b}");
                if links.get(&k).is_none_or(|l| r.in_ + r.out > l.2.in_ + l.2.out) {
                    links.insert(k, (t.node.clone(), peer.clone(), *r));
                }
            }
            recent.extend(t.recent.iter().cloned());
        }
        let mut rows =
            vec![LiveRow { header: "MONITORS  (A add, E edit, D remove; they only count, never route)".into(), ..Default::default() }];
        for it in &self.v.monitors {
            let m = &it.value;
            rows.push(LiveRow {
                label: label_or(&m.name),
                detail: format!("{} on {}", monitor_match(m), self.name(&m.node)),
                rate: mons.get(&m.id).copied().unwrap_or_default(),
                monitor: m.id.clone(),
                ..Default::default()
            });
        }
        if self.v.monitors.is_empty() {
            rows.push(LiveRow {
                text: s.muted.render("    none yet: press A to measure an IP and/or port (e.g. a proxy's backend)"),
                ..Default::default()
            });
        }
        // By target IP: forwards and HTTPS routes to the same machine add up.
        let (mut by_ip, mut uses): (HashMap<String, Rate>, HashMap<String, Vec<String>>) = Default::default();
        let mut ips: Vec<String> = vec![];
        let mut add_ip = |ip: String, use_: String, r: Rate| {
            if !by_ip.contains_key(&ip) {
                ips.push(ip.clone());
            }
            add(by_ip.entry(ip.clone()).or_default(), &r);
            uses.entry(ip).or_default().push(use_);
        };
        for it in &self.v.forwards {
            let f = &it.value;
            add_ip(
                self.addr_of(&f.target_node, &f.target_ip),
                format!("{} ({} {})", label_or(&f.name), f.proto, f.listen_port),
                fwd.get(&f.id).copied().unwrap_or_default(),
            );
        }
        for it in &self.v.routes {
            add_ip(
                self.addr_of(&it.value.target_node, &it.value.target_ip),
                it.value.hostname.clone(),
                routes.get(&it.value.id).map(|r| r.rate).unwrap_or_default(),
            );
        }
        if !ips.is_empty() {
            let speed = |ip: &String| by_ip[ip].in_rate + by_ip[ip].out_rate;
            ips.sort_by(|a, b| speed(b).partial_cmp(&speed(a)).unwrap_or(std::cmp::Ordering::Equal).then_with(|| a.cmp(b)));
            rows.push(LiveRow { header: "BY TARGET IP  (port forwards and HTTPS routes)".into(), ..Default::default() });
            for ip in &ips {
                rows.push(LiveRow { label: ip.clone(), detail: uses[ip].join(", "), rate: by_ip[ip], ..Default::default() });
            }
        }
        if !self.v.forwards.is_empty() {
            rows.push(LiveRow { header: "PORT FORWARDS".into(), ..Default::default() });
            for it in &self.v.forwards {
                let f = &it.value;
                rows.push(LiveRow {
                    label: label_or(&f.name),
                    detail: format!("{} :{} -> {}:{}", f.proto, f.listen_port, self.addr_of(&f.target_node, &f.target_ip), f.target_port),
                    rate: fwd.get(&f.id).copied().unwrap_or_default(),
                    ..Default::default()
                });
            }
        }
        if !self.v.routes.is_empty() {
            rows.push(LiveRow { header: "HTTPS ROUTES".into(), ..Default::default() });
            for it in &self.v.routes {
                let r = routes.get(&it.value.id).copied().unwrap_or_default();
                rows.push(LiveRow {
                    label: it.value.hostname.clone(),
                    detail: format!("{} requests, {} errors", r.requests, r.errors),
                    rate: r.rate,
                    ..Default::default()
                });
            }
        }
        if !links.is_empty() {
            rows.push(LiveRow { header: "DEVICES  (WireGuard traffic per link)".into(), ..Default::default() });
            let mut keys: Vec<&String> = links.keys().collect();
            let sp = |k: &String| links[k].2.in_rate + links[k].2.out_rate;
            keys.sort_by(|a, b| sp(b).partial_cmp(&sp(a)).unwrap_or(std::cmp::Ordering::Equal).then_with(|| a.cmp(b)));
            for k in keys {
                let (by, peer, r) = &links[k];
                let r = Rate { in_: r.out, out: r.in_, in_rate: r.out_rate, out_rate: r.in_rate };
                rows.push(LiveRow {
                    label: self.name(peer),
                    detail: format!("{} <-> {}", self.name(peer), self.name(by)),
                    rate: r,
                    ..Default::default()
                });
            }
        }
        if !self.v.acls.is_empty() {
            rows.push(LiveRow { header: "ACCESS RULES  (connections allowed)".into(), ..Default::default() });
            for it in &self.v.acls {
                let n = rules.get(&it.value.id).copied().unwrap_or(0);
                rows.push(LiveRow {
                    text: format!("    {:<27} {}", trunc(&label_or(&it.value.name), 27), s.value.render(&n.to_string())),
                    ..Default::default()
                });
            }
        }
        if !recent.is_empty() {
            recent.sort_by_key(|r| std::cmp::Reverse(r.time));
            rows.push(LiveRow { header: "RECENT HTTPS REQUESTS".into(), ..Default::default() });
            for q in recent.iter().take(30) {
                let (_, _, _, h, mi, sec, _) = crate::logx::local(q.time);
                rows.push(LiveRow {
                    text: format!(
                        "    {h:02}:{mi:02}:{sec:02}  {:<15} {:>3}  {} {}{}  {} {}ms",
                        q.client,
                        q.status,
                        q.method,
                        q.host,
                        q.path,
                        human_bytes(q.bytes as f64),
                        q.ms
                    ),
                    ..Default::default()
                });
            }
        }
        rows
    }

    /// Name, what it is, speeds and total.
    pub fn live_line(&self, r: &LiveRow, sel: bool) -> String {
        let s = st();
        let mk = marker(sel);
        if !r.header.is_empty() {
            return mk + &s.section.render(&r.header);
        }
        if !r.text.is_empty() {
            return mk + &r.text;
        }
        format!(
            "{mk}{:<22} {}{}{}{}{}{}{}",
            trunc(&r.label, 22),
            s.muted.render(&format!("{:<34}", trunc(&r.detail, 34))),
            s.label.render(" IN "),
            s.value.render(&format!("{:<10}", human_bits(r.rate.in_rate))),
            s.label.render(" OUT "),
            s.value.render(&format!("{:<10}", human_bits(r.rate.out_rate))),
            s.label.render(" TOTAL "),
            s.address.render(&human_bytes((r.rate.in_ + r.rate.out) as f64))
        )
    }

    pub fn selected_monitor(&self) -> Option<Item<Monitor>> {
        if self.tab != TAB_TRAFFIC || self.history {
            return None;
        }
        let rows = self.live_rows();
        let id = rows.get(self.sel).map(|r| r.monitor.clone()).filter(|m| !m.is_empty())?;
        self.v.monitors.iter().find(|m| m.value.id == id).cloned()
    }

    pub fn monitor_form(&mut self, it: Option<Item<Monitor>>) {
        let (m, title) = match &it {
            Some(it) => (it.value.clone(), format!("Edit monitor {}", it.value.name)),
            None => (Monitor { proto: "tcp".into(), node: self.v.self_id.clone(), ..Default::default() }, "New monitor".into()),
        };
        self.form = Some(
            Form::new(&title, Action::Monitor(it.map(|i| i.value)))
                .text("name", "Name", &m.name, "survival server")
                .choice("node", "Measured on", self.server_options(), &m.node)
                .text("ip", "IP or subnet (empty = any)", &m.ip, "192.168.1.51")
                .text("ports", "Ports (empty = all)", &m.ports, "25565 or 25565-25570")
                .choice(
                    "proto",
                    "Protocol",
                    vec![opt("tcp", "tcp"), opt("udp", "udp"), opt("tcp+udp", "both"), opt("any (IP only)", "any")],
                    &m.proto,
                ),
        );
    }

    /// Writes the shown period of every series to a CSV file.
    pub fn export_history(&mut self) {
        let Some(h) = &self.hist else {
            self.message = "No history loaded yet.".into();
            return;
        };
        let now = crate::util::now_unix();
        let (y, mo, d, hh, mi, ..) = crate::logx::local(now);
        let name = format!("meshgate-traffic-{}-{y:04}-{mo:02}-{d:02}-{hh:02}{mi:02}.csv", self.hist_range);
        let path = std::env::current_dir().map(|d| d.join(&name)).unwrap_or_else(|_| name.clone().into());
        let cols = ["kind", "name", "hostname", "proto", "port", "target_ip", "target_port", "target_node", "node", "peer"];
        let mut out = String::new();
        let mut row = |fields: Vec<String>| {
            let f: Vec<String> =
                fields
                    .into_iter()
                    .map(|v| {
                        if v.contains([',', '"', '\n', '\r']) || v.starts_with(' ') { format!("\"{}\"", v.replace('"', "\"\"")) } else { v }
                    })
                    .collect();
            out.push_str(&f.join(","));
            out.push('\n');
        };
        let mut head: Vec<String> = ["time", "unix", "series"].iter().map(|s| s.to_string()).collect();
        head.extend(cols.iter().map(|s| s.to_string()));
        head.extend(["bytes_in", "bytes_out", "peak_in_bps", "peak_out_bps"].iter().map(|s| s.to_string()));
        row(head);
        for (k, buckets) in &h.series {
            let label: Vec<String> = cols.iter().map(|c| h.labels.get(k).and_then(|l| l.get(*c)).cloned().unwrap_or_default()).collect();
            for b in buckets {
                let t = b[0] as i64;
                let (y, mo, d, hh, mi, ..) = crate::logx::local(t);
                let mut r = vec![format!("{y:04}-{mo:02}-{d:02} {hh:02}:{mi:02}"), t.to_string(), k.clone()];
                r.extend(label.iter().cloned());
                r.extend([
                    (b[1] as i64).to_string(),
                    (b[2] as i64).to_string(),
                    ((b[3] * 8.0) as i64).to_string(),
                    ((b[4] * 8.0) as i64).to_string(),
                ]);
                row(r);
            }
        }
        self.message = match std::fs::write(&path, out) {
            Ok(()) => format!("Saved {}", path.display()),
            Err(e) => format!("Error: {e}"),
        };
    }

    /// Whether a node can update to the latest release.
    pub fn outdated(&self, n: &Node) -> bool {
        let st = self.v.statuses.get(&n.id).cloned().unwrap_or_default();
        !self.v.runtime.latest.is_empty()
            && crate::update::newer(&st.version, &self.v.runtime.latest)
            && n.kind != model::NODE_STATIC
            && st.os != "android"
            && st.os != "ios"
    }

    /// Updates every node behind the latest release, this one last.
    pub async fn update_all(&mut self) {
        let mut ids: Vec<String> = self
            .v
            .nodes
            .iter()
            .filter(|it| self.outdated(&it.value) && it.value.id != self.v.self_id)
            .map(|it| it.value.id.clone())
            .collect();
        ids.extend(
            self.v.nodes.iter().filter(|it| self.outdated(&it.value) && it.value.id == self.v.self_id).map(|it| it.value.id.clone()),
        );
        if ids.is_empty() {
            self.message = "Every node runs the latest release.".into();
            return;
        }
        let mut msgs = vec![];
        for id in ids {
            let m = self.post_message("update", serde_json::json!({"node": id})).await;
            msgs.push(match m.strip_prefix("Error: ") {
                Some(e) => format!("{}: {e}", self.name(&id)),
                None => m,
            });
        }
        self.message = msgs.join("  ");
    }

    /// LAN/VLAN subnets a node reports and does not share yet.
    pub fn detected_subnets(&self, n: &Node) -> Vec<String> {
        let mut have: std::collections::HashSet<String> = n.routes.iter().cloned().collect();
        let mut out = vec![];
        for l in self.v.statuses.get(&n.id).map(|s| s.lans.clone()).unwrap_or_default() {
            let bridge = ["docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "lxc"].iter().any(|p| l.iface.starts_with(p));
            if bridge || !have.insert(l.cidr.clone()) {
                continue;
            }
            out.push(l.cidr);
        }
        out
    }

    // ---------------------------------------------------------- TOOLS

    pub fn tool_rows(&self) -> Vec<ToolRow> {
        let check = |kind: &str, target: &str, port: i64| diag::Check { kind: kind.into(), target: target.into(), port };
        let mut rows = vec![
            ToolRow { header: format!("RUN A CHECK  (from {}; ENTER to run)", self.self_node_name()), ..Default::default() },
            ToolRow { label: "Custom check: type any target".into(), check: check("ping", "", 0), ..Default::default() },
            ToolRow { label: "My public IP (what websites see)".into(), check: check("myip", "", 0), ..Default::default() },
        ];
        let by_id: HashMap<&str, &Node> = self.v.nodes.iter().map(|n| (n.value.id.as_str(), &n.value)).collect();
        let (mut mesh, mut public) = (vec![], vec![]);
        for it in &self.v.nodes {
            let n = &it.value;
            if !n.mesh_ip.is_empty() {
                mesh.push(ToolRow {
                    label: format!("{} — {}", n.name, n.mesh_ip),
                    check: check("ping", &n.mesh_ip, 0),
                    ..Default::default()
                });
            }
            let p = public_host(n);
            if n.kind == model::NODE_SERVER && !p.is_empty() {
                public.push(ToolRow { label: format!("{} public — {p}", n.name), check: check("ping", &p, 0), ..Default::default() });
            }
        }
        let l4 = |p: &str| if p == model::PROTO_UDP { "udp" } else { "tcp" };
        let (mut outside, mut target, mut sites) = (vec![], vec![], vec![]);
        for it in &self.v.forwards {
            let f = &it.value;
            let p = by_id.get(f.edge_node.as_str()).map(|n| public_host(n)).unwrap_or_default();
            if !p.is_empty() {
                outside.push(ToolRow {
                    label: format!("{} — {p}:{}/{}", label_or(&f.name), f.listen_port, f.proto),
                    check: check(l4(&f.proto), &p, f.listen_port),
                    ..Default::default()
                });
            }
            let ip = self.addr_of(&f.target_node, &f.target_ip);
            if !ip.is_empty() {
                target.push(ToolRow {
                    label: format!("{} target — {ip}:{}", label_or(&f.name), f.target_port),
                    check: check(l4(&f.proto), &ip, f.target_port),
                    ..Default::default()
                });
            }
        }
        for it in &self.v.routes {
            sites.push(ToolRow {
                label: it.value.hostname.clone(),
                check: check("http", &format!("https://{}/", it.value.hostname), 0),
                ..Default::default()
            });
        }
        for (title, picks) in [
            ("MESH DEVICES", mesh),
            ("PUBLIC ADDRESSES", public),
            ("PORT FORWARDS (FROM OUTSIDE)", outside),
            ("PORT FORWARDS (TARGET)", target),
            ("HTTPS SITES", sites),
        ] {
            if !picks.is_empty() {
                rows.push(ToolRow { header: title.into(), ..Default::default() });
                rows.extend(picks);
            }
        }
        let test: Vec<String> = self
            .v
            .nodes
            .iter()
            .filter(|it| it.value.test_port > 0)
            .map(|it| format!("{} -> {}:{}", it.value.name, it.value.mesh_ip, it.value.test_port))
            .collect();
        rows.push(ToolRow { header: "TEST SERVICE  (Nodes > edit > test service port)".into(), ..Default::default() });
        rows.push(ToolRow {
            label: if test.is_empty() { "off on every node".into() } else { format!("on now: {}", test.join(", ")) },
            ..Default::default()
        });
        rows
    }

    fn self_node_name(&self) -> String {
        self.v.self_node().map(|n| n.name.clone()).unwrap_or_default()
    }

    pub fn tool_line(&self, r: &ToolRow, sel: bool) -> String {
        let s = st();
        let mk = marker(sel);
        if !r.header.is_empty() {
            return mk + &s.section.render(&r.header);
        }
        if r.check.kind.is_empty() {
            return mk + &s.muted.render(&format!("    {}", r.label));
        }
        format!("{mk}    {}{}", s.value.render(&r.label), s.muted.render(&format!("  ({})", r.check.kind)))
    }

    pub fn diag_form(&mut self, c: diag::Check) {
        if c.kind.is_empty() {
            return; // a header or info line
        }
        let kinds = vec![
            opt("ping", "ping"),
            opt("my public IP", "myip"),
            opt("traceroute", "trace"),
            opt("TCP port open?", "tcp"),
            opt("UDP answer (test service)", "udp"),
            opt("HTTP / HTTPS page", "http"),
        ];
        let port = if c.port > 0 { c.port.to_string() } else { String::new() };
        self.form = Some(
            Form::new(&format!("Run a check from {}", self.self_node_name()), Action::Diag)
                .choice("kind", "Check", kinds, &c.kind)
                .text("target", "Target (not for my public IP)", &c.target, "100.88.x.y, 192.168.1.20, example.com or https://…")
                .text("port", "Port (tcp/udp)", &port, "8099"),
        );
    }

    // ---------------------------------------------------------- SETTINGS

    pub fn setting_rows(&self) -> Vec<SettingRow> {
        let netw = &self.v.network;
        let log_server = if netw.log_server.is_empty() { "automatic (first VPS relay)".to_string() } else { self.name(&netw.log_server) };
        let mut rows = vec![
            SettingRow { label: "Let's Encrypt email".into(), value: super::view::dash(&netw.acme_email), open: Setting::Settings },
            SettingRow {
                label: "Log server (history and logs)".into(),
                value: format!("{log_server}, kept {} days", netw.history_days()),
                open: Setting::History,
            },
            SettingRow { label: "Web UI admin login".into(), value: "change the username or password".into(), open: Setting::Admin },
        ];
        for it in &self.v.nodes {
            let n = &it.value;
            let fp = if n.id == self.v.self_id { self.v.runtime.web_cert_fp.clone() } else { n.web_fp.clone() };
            if n.webui && n.web_tls && !fp.is_empty() {
                rows.push(SettingRow {
                    label: format!("Web UI certificate: {}", n.name),
                    value: fp.clone(),
                    open: Setting::Fp(n.name.clone(), fp),
                });
            }
        }
        let ca = self.v.runtime.web_ca_fp.clone();
        if !ca.is_empty() {
            rows.push(SettingRow { label: "Web UI CA (this server)".into(), value: ca.clone(), open: Setting::Ca(ca) });
        }
        rows.push(SettingRow { label: "Theme (this terminal)".into(), value: self.theme.clone(), open: Setting::Theme });
        rows
    }

    pub fn open_setting(&mut self, s: Setting) {
        match s {
            Setting::Settings => self.settings_form(),
            Setting::History => self.history_form(),
            Setting::Admin => self.admin_form(),
            Setting::Fp(name, fp) => {
                self.note =
                    format!("Web UI certificate of {name} (SHA-256). Compare it with what the browser shows before accepting:\n\n  {fp}");
            }
            Setting::Ca(ca) => {
                self.note = format!(
                    "Install this server's CA once per device and the browser stops warning.\nFingerprint (SHA-256):\n\n  {ca}\n\nRun `meshgate webui ca` on this server for the file and install steps per system."
                );
            }
            Setting::Theme => self.cycle_theme(false),
        }
    }

    pub fn setting_line(&self, r: &SettingRow, sel: bool) -> String {
        let s = st();
        format!("{}{} {}", marker(sel), s.label.render(&format!("{:<32}", trunc(&r.label, 32))), s.value.render(&r.value))
    }

    fn history_form(&mut self) {
        let mut servers = vec![opt("automatic (first VPS relay)", "")];
        servers.extend(self.server_options());
        let days = if self.v.network.log_days > 0 { self.v.network.log_days.to_string() } else { String::new() };
        self.form = Some(
            Form::new("Log server (traffic history and logs)", Action::History)
                .choice("server", "Log server", servers, &self.v.network.log_server)
                .text("days", "Keep for (days)", &days, "365"),
        );
    }

    fn admin_form(&mut self) {
        self.form = Some(
            Form::new("Web UI admin login", Action::Admin)
                .text("user", "Username", "", "admin")
                .password("pass", "New password (8+ characters)"),
        );
    }

    // ---------------------------------------------------------- history rows

    /// Every forward, site and monitor (also deleted ones the log server
    /// still has), then per target IP, port, node and device link.
    pub fn hist_rows(&self) -> Vec<HistRow> {
        let empty = BTreeMap::new();
        let labels = self.hist.as_ref().map(|h| &h.labels).unwrap_or(&empty);
        let keys: Vec<String> = self.hist.as_ref().map(|h| h.series.keys().cloned().collect()).unwrap_or_default();
        let mut rows: Vec<HistRow> = vec![];
        let mut seen = std::collections::HashSet::new();
        let add = |rows: &mut Vec<HistRow>, seen: &mut std::collections::HashSet<String>, label: String, keys: Vec<String>| {
            for k in &keys {
                seen.insert(k.clone());
            }
            rows.push(HistRow { label, keys });
        };
        for it in &self.v.forwards {
            let f = &it.value;
            add(&mut rows, &mut seen, format!("{} ({} {})", label_or(&f.name), f.proto, f.listen_port), vec![format!("f:{}", f.id)]);
        }
        for it in &self.v.routes {
            add(&mut rows, &mut seen, format!("https://{}", it.value.hostname), vec![format!("r:{}", it.value.id)]);
            add(&mut rows, &mut seen, format!("http://{}", it.value.hostname), vec![format!("h:{}", it.value.id)]);
        }
        for it in &self.v.monitors {
            add(&mut rows, &mut seen, format!("monitor {}", label_or(&it.value.name)), vec![format!("m:{}", it.value.id)]);
        }
        let lab = |k: &str, f: &str| labels.get(k).and_then(|l| l.get(f)).cloned().unwrap_or_default();
        for k in &keys {
            if seen.contains(k) || k.starts_with("d:") {
                continue;
            }
            if k.starts_with("f:") {
                add(
                    &mut rows,
                    &mut seen,
                    format!("{} ({} {}, deleted)", label_or(&lab(k, "name")), lab(k, "proto"), lab(k, "port")),
                    vec![k.clone()],
                );
            } else if !lab(k, "hostname").is_empty() {
                add(&mut rows, &mut seen, format!("{}://{} (deleted)", lab(k, "kind"), lab(k, "hostname")), vec![k.clone()]);
            } else if k.starts_with("m:") {
                add(&mut rows, &mut seen, format!("monitor {} (deleted)", label_or(&lab(k, "name"))), vec![k.clone()]);
            }
        }
        let mut ips: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for k in &keys {
            let ip = lab(k, "target_ip");
            if !ip.is_empty() && !k.starts_with("d:") && !k.starts_with("m:") {
                ips.entry(ip).or_default().push(k.clone());
            }
        }
        for (ip, ks) in ips {
            rows.push(HistRow { label: format!("target {ip}"), keys: ks });
        }
        let mut ports: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for k in &keys {
            let p = lab(k, "port");
            if !p.is_empty() && (k.starts_with("f:") || k.starts_with("r:") || k.starts_with("h:")) {
                ports.entry(p).or_default().push(k.clone());
            }
        }
        let mut plist: Vec<(String, Vec<String>)> = ports.into_iter().collect();
        plist.sort_by_key(|(p, _)| atoi(p.split('-').next().unwrap_or("")));
        for (p, ks) in plist {
            rows.push(HistRow { label: format!("port {p}"), keys: ks });
        }
        let mut by_node: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut link_keys = vec![];
        for k in &keys {
            if let Some(rest) = k.strip_prefix("d:") {
                let by = rest.split_once('@').map(|(_, b)| b.to_string()).unwrap_or_default();
                by_node.entry(by).or_default().push(k.clone());
                link_keys.push(k.clone());
            }
        }
        let mut nodes: Vec<(String, Vec<String>)> = by_node.into_iter().collect();
        nodes.sort_by_key(|(id, _)| self.name(id));
        for (id, ks) in nodes {
            rows.push(HistRow { label: format!("node {} (all links)", self.name(&id)), keys: ks });
        }
        for k in link_keys {
            let rest = &k[2..];
            let (peer, by) = rest.split_once('@').unwrap_or((rest, ""));
            rows.push(HistRow { label: format!("{} <-> {}", self.name(peer), self.name(by)), keys: vec![k.clone()] });
        }
        rows
    }

    // ---------------------------------------------------------- LOGS

    /// The query the web UI sends too (same order).
    pub fn logs_query(&self) -> String {
        let since = match LOG_SPANS[self.log_span].1 {
            0 => String::new(),
            s => (crate::util::now_unix() - s).to_string(),
        };
        format!(
            "events?since={since}&node={}&q={}&important={}&limit=500",
            crate::http::url_encode(&self.log_node),
            crate::http::url_encode(&self.log_text),
            if self.log_imp { "1" } else { "0" }
        )
    }

    pub fn log_rows(&self) -> Vec<LogRow> {
        let Some(r) = &self.logs else { return vec![] };
        let ram: std::collections::HashSet<(i64, String, String)> =
            r.pending.iter().map(|e| (e.t, e.node.clone(), e.text.clone())).collect();
        if !r.error.is_empty() {
            return r.recent.iter().map(|e| LogRow { e: e.clone(), ram: ram.contains(&(e.t, e.node.clone(), e.text.clone())) }).collect();
        }
        r.pending
            .iter()
            .map(|e| LogRow { e: e.clone(), ram: true })
            .chain(r.entries.iter().map(|e| LogRow { e: e.clone(), ram: false }))
            .collect()
    }

    pub fn log_line(&self, r: &LogRow, sel: bool, w: usize) -> String {
        let s = st();
        let (_, mo, d, h, mi, sec, _) = crate::logx::local(r.e.t);
        let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
        let when = if crate::util::now_unix() - r.e.t > 20 * 3600 {
            format!("{} {d:02} {h:02}:{mi:02}", months[(mo as usize).clamp(1, 12) - 1])
        } else {
            format!("{h:02}:{mi:02}:{sec:02}")
        };
        let tag = if r.ram { s.warn.render("RAM ") } else { "    ".into() };
        let style = if r.e.text.contains(" DOWN") {
            s.err
        } else if crate::events::important(&r.e.text) {
            s.focused
        } else {
            s.value
        };
        let room = w.saturating_sub(40).max(10);
        format!(
            "{}{}{tag}{}{}",
            marker(sel),
            s.muted.render(&format!("{when:<12} ")),
            s.selected.render(&format!("{:<14} ", trunc(&self.name(&r.e.node), 14))),
            style.render(&trunc(&r.e.text, room))
        )
    }

    pub fn logs_hint(&self) -> String {
        let mut filter = LOG_SPANS[self.log_span].0.to_string();
        if self.log_imp {
            filter.push_str(", important only");
        }
        if !self.log_node.is_empty() {
            filter.push_str(&format!(", node {}", self.name(&self.log_node)));
        }
        if !self.log_text.is_empty() {
            filter.push_str(&format!(", \"{}\"", self.log_text));
        }
        match &self.logs {
            None => filter,
            Some(l) if !l.error.is_empty() => format!("{}; showing this node's RAM ({filter})", l.error),
            Some(l) => {
                let held = if l.pending.is_empty() { String::new() } else { format!("; {} line(s) waiting in RAM here", l.pending.len()) };
                format!("stored on {}{held} ({filter})", l.server)
            }
        }
    }

    /// Steps the node filter through all servers.
    pub fn cycle_log_node(&mut self) {
        let mut ids: Vec<String> = if self.log_file { vec![] } else { vec![String::new()] };
        ids.extend(self.v.nodes.iter().filter(|it| it.value.kind == model::NODE_SERVER).map(|it| it.value.id.clone()));
        if let Some(i) = ids.iter().position(|id| *id == self.log_node) {
            self.log_node = ids[(i + 1) % ids.len()].clone();
            return;
        }
        self.log_node = if self.log_file { ids.first().cloned().unwrap_or_default() } else { String::new() };
    }

    pub fn log_search_form(&mut self) {
        self.form = Some(Form::new("Search the log", Action::LogSearch).text(
            "q",
            "Text (empty = everything)",
            &self.log_text,
            "DOWN, pfsense, TLS…",
        ));
    }

    fn file_node(&self) -> String {
        if self.log_node.is_empty() { self.v.self_id.clone() } else { self.log_node.clone() }
    }

    pub fn raw_query(&self) -> String {
        format!("rawlog?node={}&n=1000", crate::http::url_encode(&self.file_node()))
    }

    /// Newest first, filtered by the search text.
    pub fn raw_rows(&self) -> Vec<String> {
        let Some(r) = &self.raw else { return vec![] };
        let q = self.log_text.to_lowercase();
        r.lines.iter().rev().filter(|l| q.is_empty() || l.to_lowercase().contains(&q)).cloned().collect()
    }

    pub fn raw_line(&self, l: &str, sel: bool, w: usize) -> String {
        let s = st();
        let style = if l.contains(" DOWN") || l.contains("panic") || l.contains("Main process exited") {
            s.err
        } else if crate::events::important(l) {
            s.focused
        } else {
            s.muted
        };
        marker(sel) + &style.render(&trunc(l, w.saturating_sub(4).max(10)))
    }

    pub fn raw_hint(&self) -> String {
        let name = self.name(&self.file_node());
        match &self.raw {
            None => format!("full log file of {name}"),
            Some(r) if !r.error.is_empty() => r.error.clone(),
            Some(r) => {
                let mut h = format!("full log file of {name} ({}), newest first, last {} lines", r.source, r.lines.len());
                if !self.log_text.is_empty() {
                    h.push_str(&format!(", matching \"{}\"", self.log_text));
                }
                h
            }
        }
    }
}

pub fn diag_text(r: Result<diag::Outcome, String>) -> String {
    let s = st();
    match r {
        Err(e) => s.err.render(&format!("Check failed: {e}")),
        Ok(o) if o.ok => format!("{}\n\n{}", s.focused.render("OK"), o.output),
        Ok(o) => format!("{}\n\n{}", s.err.render("FAILED"), o.output),
    }
}

/// A server's first endpoint host that is not private, CGNAT or mesh.
fn public_host(n: &Node) -> String {
    for e in &n.endpoints {
        let Ok((host, _)) = crate::netx::split_host_port(e) else { continue };
        if let Some(ip) = crate::netx::parse_addr4(&host) {
            let o = ip.octets();
            if ip.is_private() || (o[0] == 100 && (64..128).contains(&o[1])) {
                continue;
            }
        }
        return host;
    }
    String::new()
}

#[derive(Clone, Debug, Default)]
pub struct ToolRow {
    pub header: String,
    pub label: String,
    pub check: diag::Check,
}

#[derive(Clone, Debug)]
pub enum Setting {
    Settings,
    History,
    Admin,
    Fp(String, String),
    Ca(String),
    Theme,
}

#[derive(Clone, Debug)]
pub struct SettingRow {
    pub label: String,
    pub value: String,
    pub open: Setting,
}

#[derive(Clone, Debug)]
pub struct HistRow {
    pub label: String,
    pub keys: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct LogRow {
    pub e: Entry,
    pub ram: bool,
}

pub const LOG_SPANS: [(&str, i64); 4] = [("last hour", 3600), ("last day", 86400), ("last week", 604800), ("everything kept", 0)];

/// The ops "events" answer.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct LogsResp {
    pub server: String,
    pub error: String,
    #[serde(deserialize_with = "crate::gojson::nullable")]
    pub entries: Vec<Entry>,
    pub node: String,
    #[serde(deserialize_with = "crate::gojson::nullable")]
    pub pending: Vec<Entry>,
    #[serde(deserialize_with = "crate::gojson::nullable")]
    pub recent: Vec<Entry>,
    pub dropped: usize,
}

/// The ops "rawlog" answer: one server's own log, oldest first.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct RawResp {
    pub node: String,
    pub source: String,
    #[serde(deserialize_with = "crate::gojson::nullable")]
    pub lines: Vec<String>,
    pub error: String,
}
