//! Rendering (Go: internal/tui/view.go): a boxed header with live status,
//! one bordered card per item, key badges at the bottom; narrow or short
//! terminals fall back to one-line rows.

use super::style::{flow, help_key, inner_width, line, message, on_off, panel, st, width};
use super::*;

const MAX_CONTENT_WIDTH: usize = 120;
const MIN_BOXED_WIDTH: usize = 50;
const CARD_HEIGHT: usize = 5;

/// The visible slice that keeps sel on screen.
pub fn window(sel: usize, n: usize, cap: usize) -> (usize, usize) {
    if n <= cap {
        return (0, n);
    }
    let start = sel.saturating_sub(cap / 2).min(n - cap);
    (start, start + cap)
}

pub fn dash(s: &str) -> String {
    if s.is_empty() { "-".into() } else { s.into() }
}

fn short(id: &str) -> String {
    id.chars().take(6).collect()
}

fn local_tag(local: bool) -> String {
    if local { format!("  {}", st().warn.render("LOCAL ONLY")) } else { String::new() }
}

pub fn handshake_text(t: (i64, i64)) -> String {
    if t.0 < 946_684_800 {
        return "never".into();
    }
    format!("{} ago", crate::agent::dur(crate::util::now_unix() - t.0))
}

/// A node's LAN policy as a badge.
pub fn policy_text(n: &Node) -> String {
    if n.firewall_managed() {
        st().warn.render("PFSENSE RULES")
    } else if n.restricted() {
        on_off(false, "", "RESTRICTED")
    } else {
        on_off(true, "OPEN", "")
    }
}

pub fn proto_label(p: &str) -> String {
    if p == "both" { "tcp+udp".into() } else { p.into() }
}

pub fn human_bytes(mut n: f64) -> String {
    let u = ["B", "KB", "MB", "GB", "TB"];
    let mut i = 0;
    while n >= 1024.0 && i < u.len() - 1 {
        n /= 1024.0;
        i += 1;
    }
    format!("{n:.1} {}", u[i])
}

pub fn human_bits(bytes_per_sec: f64) -> String {
    let mut b = bytes_per_sec * 8.0;
    let u = ["bps", "kbps", "Mbps", "Gbps"];
    let mut i = 0;
    while b >= 1000.0 && i < u.len() - 1 {
        b /= 1000.0;
        i += 1;
    }
    format!("{b:.1} {}", u[i])
}

pub fn spark(vals: &[f64]) -> String {
    let bars: Vec<char> = "▁▂▃▄▅▆▇█".chars().collect();
    let top = vals.iter().cloned().fold(0.0, f64::max);
    vals.iter().map(|v| if top == 0.0 || *v == 0.0 { ' ' } else { bars[(v / top * 7.999) as usize] }).collect()
}

/// Colours one changelog line: + green, - red, ~ yellow.
fn change_line(l: &str, sel: bool) -> String {
    let s = st();
    let marker = if sel { s.selected.render("> ") } else { "  ".into() };
    if let Some(r) = l.strip_prefix("## ") {
        return marker + &s.section.render(r);
    }
    for (p, style) in [("+ ", s.enabled), ("- ", s.err), ("~ ", s.warn)] {
        if let Some(r) = l.strip_prefix(p) {
            return format!("{marker}{}{r}", style.render(p));
        }
    }
    marker + &s.muted.render(l)
}

pub fn marker(sel: bool) -> String {
    if sel { st().selected.render("> ") } else { "  ".into() }
}

impl Model {
    fn content_width(&self) -> usize {
        if self.width < 1 { 100 } else { self.width.min(MAX_CONTENT_WIDTH) }
    }

    fn height_limit(&self) -> usize {
        if self.height < 1 { 40 } else { self.height }
    }

    pub fn view(&mut self) -> String {
        let w = self.content_width();
        let view = if let Some(f) = &mut self.form {
            f.view(w)
        } else if !self.note.is_empty() {
            [panel(w, st().accent, std::slice::from_ref(&self.note)), flow(w, &[help_key("ANY KEY", "back")])].join("\n")
        } else {
            self.list_view(w)
        };
        style::fit_screen(&view, self.width, self.height)
    }

    fn self_node(&self) -> Node {
        self.v.self_node().cloned().unwrap_or_default()
    }

    fn header(&self, w: usize) -> String {
        let s = st();
        let inner = inner_width(w);
        let brand = flow(inner, &[s.brand.render("MESHGATE"), s.section.render("MESH MANAGER")]);
        let me = self.self_node();
        let mut items = vec![format!("{}{}", s.label.render("MESH "), s.address.render(&self.v.network.cidr))];
        if !me.id.is_empty() {
            items.push(format!(
                "{}{}{}{}",
                s.label.render("NODE "),
                s.selected.render(&me.name),
                s.muted.render(" "),
                s.address.render(&me.mesh_ip)
            ));
        }
        if !self.v.runtime.home_relay.is_empty() {
            items.push(format!("{}{}", s.label.render("RELAY "), s.public.render(&self.name(&self.v.runtime.home_relay))));
        }
        if self.v.runtime.userspace {
            items.push(format!("{}{}", s.label.render("WIREGUARD "), s.warn.render("USERSPACE")));
        }
        let mut web = "OFF".to_string();
        for n in &self.v.nodes {
            if n.value.webui {
                web = n.value.name.clone();
            }
        }
        items.push(format!("{}{}", s.label.render("WEB UI "), on_off(web != "OFF", &web.to_uppercase(), "NONE")));
        if me.kind == model::NODE_SERVER && !me.routes.is_empty() {
            items.push(format!("{}{}", s.label.render("LAN "), policy_text(&me)));
        }
        let tab_line: Vec<String> = TABS
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let label = if i >= 10 { t.to_string() } else { format!("{} {t}", (i + 1) % 10) };
                if i == self.tab { s.key.render(&format!(" {label} ")) } else { s.muted.render(&format!(" {label} ")) }
            })
            .collect();
        panel(w, s.accent, &[brand, flow(inner, &items), flow(inner, &tab_line)])
    }

    fn list_view(&self, w: usize) -> String {
        let s = st();
        let header = self.header(w);
        if let Some(e) = &self.err {
            return [header, message(w.saturating_sub(2).max(1), e), flow(w, &[help_key("R", "retry"), help_key("Q", "quit")])].join("\n");
        }
        let mut warn = vec![];
        for (i, wn) in self.v.runtime.warnings.iter().enumerate() {
            if i == 3 {
                warn.push(line(w, &s.warn.render(&format!("  … {} more warnings", self.v.runtime.warnings.len() - 3))));
                break;
            }
            warn.push(line(w, &s.warn.render(&format!("! {wn}"))));
        }
        let footer = self.footer(w);
        let title = line(w, &format!("{}{}", s.section.render(&format!("{} ", TABS[self.tab])), s.muted.render(&self.tab_hint())));
        let available =
            self.height_limit() as isize - style::height(&header) as isize - style::height(&footer) as isize - warn.len() as isize - 1;
        let avail = available.max(1) as usize;
        let n = self.rows();
        let mut body = vec![];
        let rows_of = |f: &dyn Fn(usize) -> String| {
            let (a, b) = window(self.sel, n, avail);
            (a..b).map(|i| line(w, &f(i))).collect::<Vec<_>>()
        };
        if n == 0 {
            body.push(panel(w, s.quiet, &[s.muted.render(&self.empty_text())]));
        } else if self.tab == TAB_TRAFFIC && !self.history {
            let rows = self.live_rows();
            body = rows_of(&|i| self.live_line(&rows[i], i == self.sel));
        } else if self.tab == TAB_TRAFFIC {
            let rows = self.hist_rows();
            body = rows_of(&|i| self.traffic_line(&rows[i], i == self.sel, w));
        } else if self.tab == TAB_TOOLS {
            let rows = self.tool_rows();
            body = rows_of(&|i| self.tool_line(&rows[i], i == self.sel));
        } else if self.tab == TAB_LOGS && self.log_file {
            let rows = self.raw_rows();
            body = rows_of(&|i| self.raw_line(&rows[i], i == self.sel, w));
        } else if self.tab == TAB_LOGS {
            let rows = self.log_rows();
            body = rows_of(&|i| self.log_line(&rows[i], i == self.sel, w));
        } else if self.tab == TAB_SETTINGS {
            let rows = self.setting_rows();
            body = rows_of(&|i| self.setting_line(&rows[i], i == self.sel));
        } else if self.tab == TAB_CHANGES {
            body = rows_of(&|i| change_line(&self.changes[i], i == self.sel));
        } else if w >= MIN_BOXED_WIDTH && avail >= CARD_HEIGHT * n.min(2) {
            let (a, b) = window(self.sel, n, (avail / CARD_HEIGHT).max(1));
            body = (a..b).map(|i| self.card(i, w)).collect();
        } else {
            let (a, b) = window(self.sel, n, avail);
            body = (a..b).map(|i| self.row(i, w)).collect();
        }
        let mut parts = vec![header];
        parts.extend(warn);
        parts.push(title);
        parts.extend(body);
        parts.push(footer);
        parts.join("\n")
    }

    fn tab_hint(&self) -> String {
        match self.tab {
            TAB_NODES => "devices in the mesh and how this node reaches them".into(),
            TAB_FORWARDS => "public ports on an edge node, sent through the mesh".into(),
            TAB_HTTPS => "websites with automatic certificates".into(),
            TAB_RULES => "what mesh devices may reach on restricted nodes".into(),
            TAB_EXITS => "LAN devices whose internet goes out through an exit node".into(),
            TAB_CHANGES => "what changed in each version (+ added, - removed, ~ changed or fixed)".into(),
            TAB_TRAFFIC if !self.history => "live speeds and totals since each server started   M: history".into(),
            TAB_TRAFFIC => {
                let mut where_ = self.hist.as_ref().map(|h| format!(", stored on {}", h.server)).unwrap_or_default();
                if !self.hist_err.is_empty() {
                    where_ = format!(" ({})", self.hist_err);
                }
                format!("traffic history, last {}{where_}   V: change period   M: live", self.hist_range)
            }
            TAB_TOOLS => "connectivity checks from this node".into(),
            TAB_LOGS if self.log_file => self.raw_hint(),
            TAB_LOGS => self.logs_hint(),
            TAB_SETTINGS => "mesh-wide settings and the web UI's certificates".into(),
            TAB_DEVICES => "join tokens for new servers, phones and PCs".into(),
            _ => String::new(),
        }
    }

    fn empty_text(&self) -> String {
        match self.tab {
            TAB_FORWARDS => "No forwards yet. Press A to add one (e.g. Minecraft: TCP 25565 on your VPS -> your home server).".into(),
            TAB_HTTPS => "No HTTPS routes yet. Press A to publish a website.".into(),
            TAB_RULES => "No access rules. They only matter on nodes whose LAN policy is RESTRICTED (edit the node on tab 1).".into(),
            TAB_EXITS => "No exit routes. Press A to send a LAN device (e.g. 192.168.200.11) out through an exit node.".into(),
            TAB_LOGS if self.log_file => match &self.raw {
                Some(r) if !r.error.is_empty() => r.error.clone(),
                _ => "No lines (yet).".into(),
            },
            TAB_LOGS if self.log_imp => "Nothing important in this period. Press I to see every line, V for a longer period.".into(),
            TAB_LOGS => "No log lines in this period.".into(),
            TAB_DEVICES => "No tokens. Press A to create one, or W for a device using the official WireGuard app.".into(),
            _ => "Nothing here yet.".into(),
        }
    }

    fn footer(&self, w: usize) -> String {
        let s = st();
        let mut keys: Vec<(&str, &str)> = vec![("UP/DOWN", "select"), ("TAB", "section")];
        match self.tab {
            TAB_NODES => {
                keys.extend([("E", "edit"), ("U", "update"), ("CTRL+U", "update all"), ("D", "remove"), ("C", "use all-nodes value")])
            }
            TAB_TRAFFIC if self.history => keys.extend([("V", "period (6h/1d/1w/1m/1y)"), ("O", "save CSV"), ("M", "live")]),
            TAB_TRAFFIC => keys.extend([("A", "add monitor"), ("E", "edit"), ("D", "remove"), ("M", "history")]),
            TAB_TOOLS => keys.push(("ENTER", "run")),
            TAB_LOGS if self.log_file => keys.extend([("ENTER", "full line"), ("F", "node"), ("/", "search"), ("B", "event log")]),
            TAB_LOGS => keys.extend([
                ("ENTER", "full line"),
                ("I", "important/all"),
                ("F", "node"),
                ("V", "period"),
                ("/", "search"),
                ("B", "a node's full log file"),
            ]),
            TAB_SETTINGS => keys.push(("ENTER", "change / show")),
            TAB_FORWARDS | TAB_HTTPS | TAB_RULES | TAB_EXITS => {
                keys.extend([("A", "add"), ("E", "edit"), ("T", "on/off"), ("D", "remove"), ("C", "use all-nodes value")])
            }
            TAB_DEVICES => keys.extend([("A", "new token"), ("W", "WireGuard app"), ("D", "revoke")]),
            _ => {}
        }
        if self.tab == TAB_HTTPS {
            keys.push(("S", "settings"));
        }
        keys.extend([("Y", "theme"), ("Q", "quit")]);
        let items: Vec<String> = keys.iter().map(|(k, d)| help_key(k, d)).collect();
        let mut out = vec![flow(w, &items)];
        let mw = w.saturating_sub(2).max(1);
        if !self.confirm.is_empty() {
            out.push(message(mw, &format!("{}{}", s.focused.render(&self.confirm), s.muted.render("  Y yes  any other key no"))));
        } else if !self.message.is_empty() {
            out.push(message(mw, &self.message));
        }
        out.join("\n")
    }

    fn node_state(&self, n: &Node) -> String {
        let s = st();
        if n.id == self.v.self_id {
            return s.enabled.render("THIS NODE");
        }
        match self.v.runtime.peers.get(&n.id) {
            Some(p) if p.last_handshake.0 >= 946_684_800 => {
                if crate::util::now_unix() - p.last_handshake.0 > 180 {
                    s.warn.render("IDLE")
                } else {
                    s.enabled.render("ONLINE")
                }
            }
            _ if n.kind == model::NODE_STATIC => s.muted.render("VIA RELAY"),
            _ => s.disabled.render("NO HANDSHAKE"),
        }
    }

    pub fn path_text(&self, path: &str) -> String {
        match path.strip_prefix("via ") {
            Some(r) => format!("via {}", self.name(r)),
            None => dash(path),
        }
    }

    pub fn addr_of(&self, node: &str, ip: &str) -> String {
        if !ip.is_empty() {
            return ip.into();
        }
        self.v.nodes.iter().find(|n| n.value.id == node).map(|n| n.value.mesh_ip.clone()).unwrap_or_else(|| "?".into())
    }

    fn acl_target(&self, a: &Acl) -> String {
        if a.to == model::TO_SELF {
            return "this node".into();
        }
        if let Some(l) = self.v.statuses.get(&a.node).and_then(|s| s.lans.iter().find(|l| l.cidr == a.to)) {
            return format!("{} ({})", a.to, l.iface);
        }
        a.to.clone()
    }

    fn roles(&self, n: &Node) -> String {
        let mut r = vec![n.kind.clone()];
        if n.relay {
            r.push("relay".into());
        }
        if n.exit {
            r.push("exit node".into());
        }
        if n.webui {
            r.push("web ui".into());
        }
        let mut may: Vec<String> = vec![];
        for a in &n.exits_allowed {
            if a == "*" {
                may = vec!["any exit".into()];
                break;
            }
            may.push(self.name(a));
        }
        if !may.is_empty() {
            r.push(format!("may use {}", may.join("/")));
        } else if !n.exit_via.is_empty() {
            r.push(format!("exit via {}", self.name(&n.exit_via)));
        }
        format!("[{}]", r.join(", "))
    }

    fn card(&self, i: usize, w: usize) -> String {
        let s = st();
        let inner = inner_width(w);
        let sel = i == self.sel;
        let (mk, border) = if sel { (s.selected.render("> "), s.selected_border) } else { ("  ".to_string(), s.quiet) };
        let name_style = if sel { s.selected } else { s.label };
        let (mut l1, mut l2, mut l3) = (String::new(), String::new(), String::new());
        match self.tab {
            TAB_NODES => {
                let it = &self.v.nodes[i];
                let n = &it.value;
                l1 = format!(
                    "{mk}{}  {}  {}{}",
                    self.node_state(n),
                    name_style.render(&n.name),
                    s.muted.render(&self.roles(n)),
                    local_tag(it.local)
                );
                if let Some(v) = self.v.statuses.get(&n.id).map(|s| s.version.clone()).filter(|v| !v.is_empty()) {
                    l1 += &format!("  {}", s.muted.render(&v));
                }
                if self.outdated(n) {
                    l1 += &format!(" {}", s.warn.render("UPDATE AVAILABLE"));
                }
                let p = self.v.runtime.peers.get(&n.id).cloned().unwrap_or_default();
                let (path, hs) = if n.id == self.v.self_id {
                    ("this node".to_string(), String::new())
                } else {
                    (self.path_text(&p.path), handshake_text(p.last_handshake))
                };
                l2 = format!(
                    "{}{}{}{}",
                    s.label.render("MESH IP "),
                    s.address.render(&n.mesh_ip),
                    s.label.render("   PATH "),
                    s.value.render(&path)
                );
                if !hs.is_empty() {
                    l2 += &format!("{}{}", s.label.render("   HANDSHAKE "), s.value.render(&hs));
                }
                if p.rx_bytes + p.tx_bytes > 0 {
                    l2 += &format!(
                        "{}{}",
                        s.label.render("   RX/TX "),
                        s.value.render(&format!("{} / {}", human_bytes(p.rx_bytes as f64), human_bytes(p.tx_bytes as f64)))
                    );
                }
                let mut ep = p.endpoint.clone();
                if ep.is_empty() && !n.endpoints.is_empty() {
                    ep = n.endpoints.join(" ");
                }
                l3 = format!("{}{}", s.label.render("ENDPOINT "), s.address.render(&dash(&ep)));
                if !n.routes.is_empty() {
                    l3 += &format!("{}{} {}", s.label.render("   SUBNETS "), s.port.render(&n.routes.join(" ")), policy_text(n));
                }
            }
            TAB_FORWARDS => {
                let it = &self.v.forwards[i];
                let f = &it.value;
                l1 = format!(
                    "{mk}{}  {}  {}{}",
                    on_off(f.enabled, "ENABLED", "DISABLED"),
                    s.muted.render(&format!("#{}", short(&f.id))),
                    name_style.render(&label_or(&f.name)),
                    local_tag(it.local)
                );
                let mut public = format!(":{}", f.listen_port);
                if f.listen_end > f.listen_port {
                    public += &format!("-{}", f.listen_end);
                }
                l2 = format!(
                    "{}{}{}{}{} {}:{}",
                    s.label.render("PUBLIC "),
                    s.public.render(&self.name(&f.edge_node)),
                    s.public.render(&public),
                    s.muted.render("   ->   TARGET "),
                    s.selected.render(&self.name(&f.target_node)),
                    s.address.render(&self.addr_of(&f.target_node, &f.target_ip)),
                    s.port.render(&f.target_port.to_string())
                );
                l3 = format!(
                    "{}{}{}{}",
                    s.label.render("PROTOCOL "),
                    s.protocol.render(&f.proto.to_uppercase()),
                    s.label.render("   CLIENT IP "),
                    s.muted.render(if f.preserve_client_ip { "real" } else { "masked" })
                );
                if !f.enabled {
                    l3 += &format!("   {}", s.disabled.render("public port blocked"));
                }
            }
            TAB_HTTPS => {
                let it = &self.v.routes[i];
                let r = &it.value;
                l1 = format!("{mk}{}  {}{}", on_off(r.enabled, "ENABLED", "DISABLED"), name_style.render(&r.hostname), local_tag(it.local));
                let scheme = if r.target_tls { "https" } else { "http" };
                l2 = format!(
                    "{}{}{}{} {}{}:{}",
                    s.label.render("EDGE "),
                    s.public.render(&self.name(&r.edge_node)),
                    s.muted.render("   ->   TARGET "),
                    s.selected.render(&self.name(&r.target_node)),
                    s.muted.render(&format!("{scheme}://")),
                    s.address.render(&self.addr_of(&r.target_node, &r.target_ip)),
                    s.port.render(&r.target_port.to_string())
                );
                let mode = if r.force_https { "HTTPS only (HTTP redirects)" } else { "HTTP and HTTPS" };
                l3 = format!("{}{}", s.label.render("MODE "), s.protocol.render(mode));
                if !r.enabled {
                    l3 += &format!("   {}", s.disabled.render("visitors get 403"));
                }
            }
            TAB_RULES => {
                let it = &self.v.acls[i];
                let a = &it.value;
                l1 = format!(
                    "{mk}{}  {}{}",
                    on_off(a.enabled, "ENABLED", "DISABLED"),
                    name_style.render(&label_or(&a.name)),
                    local_tag(it.local)
                );
                let from = if a.from.is_empty() {
                    "any device".to_string()
                } else {
                    a.from.iter().map(|id| self.name(id)).collect::<Vec<_>>().join(", ")
                };
                l2 = format!(
                    "{}{}{}{}{}{}",
                    s.label.render("FROM "),
                    s.selected.render(&from),
                    s.muted.render("   ->   TO "),
                    s.address.render(&self.acl_target(a)),
                    s.label.render("   ON "),
                    s.public.render(&self.name(&a.node))
                );
                let mut allow = proto_label(&a.proto).to_uppercase();
                if !a.ports.is_empty() {
                    allow += &format!(" {}", a.ports);
                }
                l3 = format!("{}{}", s.label.render("ALLOW "), s.protocol.render(&allow));
                if self.v.nodes.iter().any(|n| n.value.id == a.node && !n.value.restricted()) {
                    l3 += &format!("   {}", s.warn.render("node's LAN policy is OPEN: rule has no effect yet"));
                }
            }
            TAB_EXITS => {
                let it = &self.v.exit_routes[i];
                let r = &it.value;
                l1 = format!(
                    "{mk}{}  {}{}",
                    on_off(r.enabled, "ENABLED", "DISABLED"),
                    name_style.render(&label_or(&r.name)),
                    local_tag(it.local)
                );
                l2 = format!(
                    "{}{}{}{}{}{}",
                    s.label.render("DEVICE "),
                    s.address.render(&r.src),
                    s.label.render("   BEHIND "),
                    s.selected.render(&self.name(&r.router)),
                    s.muted.render("   ->   EXIT "),
                    s.public.render(&self.name(&r.via))
                );
                l3 = if r.exit_only {
                    format!("{}{}", s.label.render("EXIT ONLY "), s.warn.render("no internet if no exit node is reachable"))
                } else {
                    format!("{}{}", s.label.render("FALLBACK "), s.muted.render("normal connection if no exit node is reachable"))
                };
            }
            TAB_DEVICES => {
                let t = &self.v.tokens[i];
                let uses = if t.uses_left < 0 { "unlimited".to_string() } else { t.uses_left.to_string() };
                let exp = if t.expires_at > 0 {
                    let (y, mo, d, h, mi, ..) = crate::logx::local(t.expires_at);
                    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}")
                } else {
                    "never".into()
                };
                l1 = format!(
                    "{mk}{}  {}  {}",
                    on_off(uses != "0", "ACTIVE", "USED UP"),
                    s.muted.render(&format!("#{}", t.id)),
                    name_style.render(&format!("{} TOKEN", t.kind.to_uppercase()))
                );
                l2 = format!(
                    "{}{}{}{}",
                    s.label.render("USES LEFT "),
                    s.port.render(&uses),
                    s.label.render("   EXPIRES "),
                    s.value.render(&exp)
                );
                l3 = format!("{}{}", s.label.render("NOTE "), s.value.render(&dash(&t.note)));
            }
            _ => {}
        }
        panel(w, border, &[line(inner, &l1), line(inner, &l2), line(inner, &l3)])
    }

    /// The one-line fallback for narrow or short terminals.
    fn row(&self, i: usize, w: usize) -> String {
        let s = st();
        let mk = marker(i == self.sel);
        let text = match self.tab {
            TAB_NODES => {
                let n = &self.v.nodes[i].value;
                let path = self.v.runtime.peers.get(&n.id).map(|p| p.path.clone()).unwrap_or_default();
                format!(
                    "{} {} {} {}",
                    self.node_state(n),
                    s.selected.render(&n.name),
                    s.address.render(&n.mesh_ip),
                    s.muted.render(&self.path_text(&path))
                )
            }
            TAB_FORWARDS => {
                let f = &self.v.forwards[i].value;
                format!(
                    "{} {}{}{}:{} {} {}",
                    on_off(f.enabled, "ON ", "OFF"),
                    s.public.render(&format!(":{}", f.listen_port)),
                    s.muted.render("->"),
                    s.address.render(&self.name(&f.target_node)),
                    s.port.render(&f.target_port.to_string()),
                    s.protocol.render(&f.proto.to_uppercase()),
                    label_or(&f.name)
                )
            }
            TAB_HTTPS => {
                let r = &self.v.routes[i].value;
                format!(
                    "{} {}{}{}:{}",
                    on_off(r.enabled, "ON ", "OFF"),
                    s.selected.render(&r.hostname),
                    s.muted.render(" -> "),
                    s.address.render(&self.name(&r.target_node)),
                    s.port.render(&r.target_port.to_string())
                )
            }
            TAB_RULES => {
                let a = &self.v.acls[i].value;
                format!(
                    "{} {}{}{} {}",
                    on_off(a.enabled, "ON ", "OFF"),
                    label_or(&a.name),
                    s.muted.render(" -> "),
                    s.address.render(&self.acl_target(a)),
                    s.protocol.render(&format!("{} {}", proto_label(&a.proto), a.ports))
                )
            }
            TAB_EXITS => {
                let r = &self.v.exit_routes[i].value;
                format!(
                    "{} {}{}{}{}{}",
                    on_off(r.enabled, "ON ", "OFF"),
                    label_or(&r.name),
                    s.muted.render(" "),
                    s.address.render(&r.src),
                    s.muted.render(" -> "),
                    s.public.render(&self.name(&r.via))
                )
            }
            TAB_DEVICES => {
                let t = &self.v.tokens[i];
                format!("{} {} {}", s.muted.render(&format!("#{}", t.id)), t.kind, t.note)
            }
            _ => String::new(),
        };
        line(w, &(mk + &text))
    }

    /// Name, a sparkline of the period, the total and the peak speed.
    fn traffic_line(&self, r: &extra::HistRow, sel: bool, w: usize) -> String {
        let cols = w.saturating_sub(62).clamp(8, 48);
        let mut vals = vec![0f64; cols];
        let (mut total, mut peak) = (0f64, 0f64);
        if let Some(h) = &self.hist {
            let (from, to) = (h.from as f64, h.to as f64);
            for k in &r.keys {
                for b in h.series.get(k).into_iter().flatten() {
                    total += b[1] + b[2];
                    peak = peak.max(b[3].max(b[4]));
                    if to > from {
                        let c = (((b[0] - from) / (to - from)) * cols as f64).max(0.0) as usize;
                        vals[c.min(cols - 1)] += b[1] + b[2];
                    }
                }
            }
        }
        let mut label = r.label.clone();
        if label.chars().count() > 26 {
            label = label.chars().take(25).collect::<String>() + "…";
        }
        format!("{}{label:<27} {}  {:>9}  peak {}", marker(sel), st().address.render(&spark(&vals)), human_bytes(total), human_bits(peak))
    }
}

#[allow(dead_code)]
fn _w(s: &str) -> usize {
    width(s)
}
