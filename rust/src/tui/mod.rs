//! The terminal UI (Go: internal/tui). It talks to the local agent, so it
//! works on any node even when the web UI host is offline. Every edit asks
//! whether to apply it to all nodes or only this one.

mod extra;
mod form;
mod style;
mod view;

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

use crate::diag;
use crate::localapi::Client;
use crate::model::{self, Acl, ExitRoute, Forward, HttpRoute, LanExit, Monitor, Node};
use crate::ops::{Item, View};
use form::{Action, Form, Opt, Outcome, opt};
use style::{apply_theme, next_theme, save_theme, st};

pub const TABS: [&str; 11] = ["NODES", "FORWARDS", "HTTPS", "RULES", "EXITS", "DEVICES", "TRAFFIC", "TOOLS", "LOGS", "SETTINGS", "CHANGES"];
const TAB_NODES: usize = 0;
const TAB_FORWARDS: usize = 1;
const TAB_HTTPS: usize = 2;
const TAB_RULES: usize = 3;
const TAB_EXITS: usize = 4;
const TAB_DEVICES: usize = 5;
const TAB_TRAFFIC: usize = 6;
const TAB_TOOLS: usize = 7;
const TAB_LOGS: usize = 8;
const TAB_SETTINGS: usize = 9;
const TAB_CHANGES: usize = 10;

/// The changelog shown on the CHANGES tab.
fn change_lines() -> Vec<String> {
    crate::changelog::TEXT.lines().filter(|l| !l.trim().is_empty() && !l.starts_with("# ")).map(String::from).collect()
}

/// The log server's answer for one range (ops "history").
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct HistResp {
    pub from: i64,
    pub to: i64,
    pub step: i64,
    pub server: String,
    #[serde(deserialize_with = "crate::gojson::nullable")]
    pub series: BTreeMap<String, Vec<[f64; 5]>>,
    #[serde(deserialize_with = "crate::gojson::nullable")]
    pub labels: BTreeMap<String, BTreeMap<String, String>>,
}

const HIST_RANGES: [&str; 5] = ["6h", "1d", "1w", "1m", "1y"];

/// What a background load brings back.
enum Msg {
    Key(String),
    Paste(String),
    Resize(usize, usize),
    Loaded(Box<Loaded>),
    Diag(Result<diag::Outcome, String>),
    Tick,
}

#[derive(Default)]
struct Loaded {
    v: View,
    err: Option<String>,
    hist: Option<HistResp>,
    hist_err: String,
    traffic: Option<Vec<crate::traffic::Node>>,
    logs: Option<extra::LogsResp>,
    raw: Option<extra::RawResp>,
}

pub struct Model {
    api: std::sync::Arc<Client>,
    pub v: View,
    err: Option<String>,
    pub tab: usize,
    pub sel: usize,
    form: Option<Form>,
    note: String,
    message: String,
    confirm: String,
    theme: String,
    width: usize,
    height: usize,
    hist: Option<HistResp>,
    hist_err: String,
    hist_range: String,
    history: bool,
    traffic: Vec<crate::traffic::Node>,
    diag_req: Option<diag::Check>,
    logs: Option<extra::LogsResp>,
    log_imp: bool,
    log_node: String,
    log_text: String,
    log_span: usize,
    log_file: bool,
    raw: Option<extra::RawResp>,
    changes: Vec<String>,
    quit: bool,
    tx: Option<tokio::sync::mpsc::UnboundedSender<Msg>>,
}

/// Starts the TUI.
pub async fn run(socket: &str) -> Result<(), String> {
    use crossterm::{cursor, event, execute, terminal};
    let t = style::load_theme();
    apply_theme(t);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut m = Model::new(Client::new(socket), t.name);
    m.tx = Some(tx.clone());
    terminal::enable_raw_mode().map_err(|e| e.to_string())?;
    let mut out = std::io::stdout();
    let _ = execute!(out, terminal::EnterAlternateScreen, cursor::Hide, event::EnableBracketedPaste);
    let restore = || {
        let mut out = std::io::stdout();
        let _ = execute!(out, event::DisableBracketedPaste, cursor::Show, terminal::LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    };
    if let Ok((w, h)) = terminal::size() {
        m.width = w as usize;
        m.height = h as usize;
    }
    // Keys come from a thread; loads and ticks from tasks.
    let ktx = tx.clone();
    std::thread::spawn(move || {
        while let Ok(ev) = event::read() {
            let msg = match ev {
                event::Event::Key(k) if k.kind != event::KeyEventKind::Release => key_name(&k).map(Msg::Key),
                event::Event::Paste(s) => Some(Msg::Paste(s)),
                event::Event::Resize(w, h) => Some(Msg::Resize(w as usize, h as usize)),
                _ => None,
            };
            if let Some(msg) = msg
                && ktx.send(msg).is_err()
            {
                return;
            }
        }
    });
    let ttx = tx.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(3)).await;
            if ttx.send(Msg::Tick).is_err() {
                return;
            }
        }
    });
    m.load();
    let mut last = String::new();
    loop {
        let frame = m.view();
        if frame != last {
            let mut out = std::io::stdout();
            let body = frame.replace('\n', "\x1b[K\r\n");
            let _ = write!(out, "\x1b[H{body}\x1b[K\x1b[J");
            let _ = out.flush();
            last = frame;
        }
        let Some(msg) = rx.recv().await else { break };
        m.update(msg).await;
        if m.quit {
            break;
        }
    }
    restore();
    Ok(())
}

/// bubbletea's key names.
fn key_name(k: &crossterm::event::KeyEvent) -> Option<String> {
    use crossterm::event::{KeyCode, KeyModifiers};
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    let name = match k.code {
        KeyCode::Char(c) if ctrl => format!("ctrl+{}", c.to_ascii_lowercase()),
        KeyCode::Char(c) => c.to_string(),
        KeyCode::Tab => "tab".into(),
        KeyCode::BackTab => "shift+tab".into(),
        KeyCode::Enter => "enter".into(),
        KeyCode::Esc => "esc".into(),
        KeyCode::Backspace => "backspace".into(),
        KeyCode::Delete => "delete".into(),
        KeyCode::Up => "up".into(),
        KeyCode::Down => "down".into(),
        KeyCode::Left => "left".into(),
        KeyCode::Right => "right".into(),
        KeyCode::Home => "home".into(),
        KeyCode::End => "end".into(),
        KeyCode::PageUp => "pgup".into(),
        KeyCode::PageDown => "pgdown".into(),
        _ => return None,
    };
    Some(name)
}

fn atoi(s: &str) -> i64 {
    crate::gojson::atoi(s.trim()).unwrap_or(0)
}

/// Splits on commas and spaces.
fn lines(s: &str) -> Vec<String> {
    s.split([',', ' ']).filter(|p| !p.is_empty()).map(String::from).collect()
}

fn scope_options(me: &str) -> Vec<Opt> {
    vec![opt("all nodes", "cluster"), opt(&format!("only this node ({me})"), "local")]
}

fn scope_of(local: bool) -> &'static str {
    if local { "local" } else { "cluster" }
}

fn itoa0(n: i64) -> String {
    if n == 0 { String::new() } else { n.to_string() }
}

pub fn label_or(name: &str) -> String {
    if name.is_empty() { "(unnamed)".into() } else { name.into() }
}

impl Model {
    pub fn new(api: Client, theme: &str) -> Model {
        Model {
            api: std::sync::Arc::new(api),
            v: View::default(),
            err: None,
            tab: 0,
            sel: 0,
            form: None,
            note: String::new(),
            message: String::new(),
            confirm: String::new(),
            theme: theme.into(),
            width: 0,
            height: 0,
            hist: None,
            hist_err: String::new(),
            hist_range: "1d".into(),
            history: false,
            traffic: vec![],
            diag_req: None,
            logs: None,
            log_imp: false,
            log_node: String::new(),
            log_text: String::new(),
            log_span: 1,
            log_file: false,
            raw: None,
            changes: change_lines(),
            quit: false,
            tx: None,
        }
    }

    /// Starts loading the view (and the tab's extra data) in the background.
    fn load(&self) {
        let Some(tx) = self.tx.clone() else { return };
        let api = self.api.clone();
        let (tab, rng, hist, log_q, file, raw_q) =
            (self.tab, self.hist_range.clone(), self.history, self.logs_query(), self.log_file, self.raw_query());
        tokio::spawn(async move {
            let mut l = Loaded::default();
            match api.get::<View>("view").await {
                Ok(v) => l.v = v,
                Err(e) => l.err = Some(e),
            }
            if l.err.is_none() {
                if tab == TAB_LOGS && file {
                    l.raw = Some(api.get(&raw_q).await.unwrap_or_else(|e| extra::RawResp { error: e, ..Default::default() }));
                }
                if tab == TAB_LOGS && !file {
                    l.logs = Some(api.get(&log_q).await.unwrap_or_else(|e| extra::LogsResp { error: e, ..Default::default() }));
                }
                if tab == TAB_TRAFFIC && !hist {
                    l.traffic = Some(api.get("traffic").await.unwrap_or_default());
                }
                if tab == TAB_TRAFFIC && hist {
                    match api.get::<HistResp>(&format!("history?range={rng}")).await {
                        Ok(h) => l.hist = Some(h),
                        Err(e) => l.hist_err = e,
                    }
                }
            }
            let _ = tx.send(Msg::Loaded(Box::new(l)));
        });
    }

    async fn update(&mut self, msg: Msg) {
        match msg {
            Msg::Resize(w, h) => {
                self.width = w;
                self.height = h;
            }
            Msg::Loaded(l) => {
                let l = *l;
                self.v = l.v;
                self.err = l.err;
                if l.hist.is_some() || !l.hist_err.is_empty() {
                    self.hist = l.hist;
                    self.hist_err = l.hist_err;
                }
                if let Some(t) = l.traffic {
                    self.traffic = t;
                }
                if l.logs.is_some() {
                    self.logs = l.logs;
                }
                if l.raw.is_some() {
                    self.raw = l.raw;
                }
                let n = self.rows();
                if self.sel >= n {
                    self.sel = n.saturating_sub(1);
                }
            }
            Msg::Tick => {
                self.load();
            }
            Msg::Diag(r) => {
                self.note = extra::diag_text(r);
            }
            Msg::Paste(s) => {
                if let Some(f) = &mut self.form {
                    f.paste(&s);
                }
            }
            Msg::Key(k) => self.key(&k).await,
        }
    }

    async fn key(&mut self, k: &str) {
        if let Some(f) = &mut self.form {
            match f.update(k) {
                Outcome::Stay => {}
                Outcome::Cancel => {
                    self.form = None;
                    self.load();
                }
                Outcome::Submit(vals) => {
                    let action = f.action.clone();
                    match self.submit(action, vals).await {
                        Err(e) => {
                            if let Some(f) = &mut self.form {
                                f.err = e;
                            }
                        }
                        Ok(()) => {
                            self.form = None;
                            if let Some(c) = self.diag_req.take() {
                                self.note = format!("Running {} {}…\n\n(the result replaces this when it is done)", c.kind, c.target);
                                self.run_diag(c);
                            }
                            self.load();
                        }
                    }
                }
            }
            return;
        }
        if !self.note.is_empty() {
            self.note.clear();
            return;
        }
        let key = k.to_lowercase();
        if !self.confirm.is_empty() {
            self.confirm.clear();
            if key == "y" {
                self.delete_item().await;
                self.load();
                return;
            }
            self.message = "Nothing removed.".into();
            return;
        }
        self.message.clear();
        let reload_tab = |m: &Model| m.tab == TAB_TRAFFIC || m.tab == TAB_LOGS;
        match key.as_str() {
            "q" | "ctrl+c" => self.quit = true,
            "tab" | "right" | "l" => {
                self.tab = (self.tab + 1) % TABS.len();
                self.sel = 0;
                if reload_tab(self) {
                    self.load();
                }
            }
            "shift+tab" | "left" | "h" => {
                self.tab = (self.tab + TABS.len() - 1) % TABS.len();
                self.sel = 0;
                if reload_tab(self) {
                    self.load();
                }
            }
            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "0" => {
                let d = key.as_bytes()[0] - b'0';
                self.tab = (d as usize + 9) % 10;
                self.sel = 0;
                if reload_tab(self) {
                    self.load();
                }
            }
            "up" | "k" => self.sel = self.sel.saturating_sub(1),
            "down" | "j" => {
                if self.sel + 1 < self.rows() {
                    self.sel += 1;
                }
            }
            "home" | "g" => self.sel = 0,
            "end" => self.sel = self.rows().saturating_sub(1),
            "r" => self.load(),
            "a" | "n" => self.new_item(),
            "e" | "enter" => self.edit_item(),
            "t" | " " => {
                self.toggle_item().await;
                self.load();
            }
            "b" if self.tab == TAB_LOGS => {
                self.log_file = !self.log_file;
                self.sel = 0;
                self.raw = None;
                self.load();
            }
            "i" if self.tab == TAB_LOGS => {
                self.log_imp = !self.log_imp;
                self.sel = 0;
                self.load();
            }
            "f" if self.tab == TAB_LOGS => {
                self.cycle_log_node();
                self.sel = 0;
                self.load();
            }
            "/" if self.tab == TAB_LOGS => self.log_search_form(),
            "m" if self.tab == TAB_TRAFFIC => {
                self.history = !self.history;
                self.sel = 0;
                self.load();
            }
            "o" if self.tab == TAB_TRAFFIC && self.history => self.export_history(),
            "ctrl+u" if self.tab == TAB_NODES => self.update_all().await,
            "v" if self.tab == TAB_LOGS => {
                self.log_span = (self.log_span + 1) % extra::LOG_SPANS.len();
                self.sel = 0;
                self.load();
            }
            "v" if self.tab == TAB_TRAFFIC && self.history => {
                let i = HIST_RANGES.iter().position(|r| *r == self.hist_range).unwrap_or(0);
                self.hist_range = HIST_RANGES[(i + 1) % HIST_RANGES.len()].into();
                self.hist = None;
                self.load();
            }
            "u" if self.tab == TAB_NODES && self.rows() > 0 => {
                let id = self.v.nodes[self.sel].value.id.clone();
                self.message = self.post_message("update", json!({"node": id})).await;
            }
            "d" | "delete" | "x" => {
                let label = self.selected_label();
                if !label.is_empty() {
                    self.confirm = format!("Remove {label}?");
                }
            }
            "c" => {
                self.clear_local().await;
                self.load();
            }
            "w" => self.static_form(),
            "s" => self.settings_form(),
            "y" => self.cycle_theme(true),
            _ => {}
        }
    }

    fn cycle_theme(&mut self, say: bool) {
        let t = next_theme(&self.theme);
        apply_theme(t);
        self.theme = t.name.into();
        save_theme(t.name);
        if say {
            self.message = format!("Theme: {} (saved)", t.label);
        }
    }

    async fn post_message(&self, op: &str, body: serde_json::Value) -> String {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Out {
            message: String,
        }
        match self.api.post::<Out, _>(op, &body).await {
            Ok(o) => o.message,
            Err(e) => format!("Error: {e}"),
        }
    }

    /// Names the selected item for the remove prompt.
    fn selected_label(&mut self) -> String {
        if self.rows() == 0 {
            return String::new();
        }
        let i = self.sel;
        match self.tab {
            TAB_NODES => {
                if self.v.nodes[i].value.id == self.v.self_id {
                    self.message = "This is the node you are on; run `meshgate leave` here to remove it.".into();
                    return String::new();
                }
                format!("node {}", self.v.nodes[i].value.name)
            }
            TAB_FORWARDS => format!("forward {}", label_or(&self.v.forwards[i].value.name)),
            TAB_HTTPS => format!("HTTPS route {}", self.v.routes[i].value.hostname),
            TAB_RULES => format!("rule {}", label_or(&self.v.acls[i].value.name)),
            TAB_EXITS => format!("exit route {}", label_or(&self.v.exit_routes[i].value.name)),
            TAB_DEVICES => format!("token {}", self.v.tokens[i].id),
            TAB_TRAFFIC => self.selected_monitor().map(|m| format!("monitor {}", label_or(&m.value.name))).unwrap_or_default(),
            _ => String::new(),
        }
    }

    /// Switches the selected forward, route, rule or exit route.
    async fn toggle_item(&mut self) {
        if self.rows() == 0 {
            return;
        }
        let i = self.sel;
        let (kind, id, on, what) = match self.tab {
            TAB_FORWARDS => {
                let f = &self.v.forwards[i].value;
                (model::KIND_FORWARD, f.id.clone(), f.enabled, format!("Forward {}", label_or(&f.name)))
            }
            TAB_HTTPS => {
                let r = &self.v.routes[i].value;
                (model::KIND_ROUTE, r.id.clone(), r.enabled, format!("Route {}", r.hostname))
            }
            TAB_RULES => {
                let a = &self.v.acls[i].value;
                (model::KIND_ACL, a.id.clone(), a.enabled, format!("Rule {}", label_or(&a.name)))
            }
            TAB_EXITS => {
                let r = &self.v.exit_routes[i].value;
                (model::KIND_EXIT_ROUTE, r.id.clone(), r.enabled, format!("Exit route {}", label_or(&r.name)))
            }
            _ => return,
        };
        if let Err(e) = self.api.post_ok("toggle", &json!({"kind": kind, "id": id, "enabled": !on})).await {
            self.message = format!("Error: {e}");
            return;
        }
        self.message = if on {
            let mut s = format!("{what} disabled.");
            if kind == model::KIND_FORWARD {
                s.push_str(" Its public port is now blocked.");
            }
            s
        } else {
            format!("{what} enabled.")
        };
    }

    pub fn rows(&self) -> usize {
        match self.tab {
            TAB_NODES => self.v.nodes.len(),
            TAB_FORWARDS => self.v.forwards.len(),
            TAB_HTTPS => self.v.routes.len(),
            TAB_RULES => self.v.acls.len(),
            TAB_EXITS => self.v.exit_routes.len(),
            TAB_CHANGES => self.changes.len(),
            TAB_TRAFFIC if !self.history => self.live_rows().len(),
            TAB_TRAFFIC => self.hist_rows().len(),
            TAB_TOOLS => self.tool_rows().len(),
            TAB_LOGS if self.log_file => self.raw_rows().len(),
            TAB_LOGS => self.log_rows().len(),
            TAB_SETTINGS => self.setting_rows().len(),
            TAB_DEVICES => self.v.tokens.len(),
            _ => 0,
        }
    }

    pub fn name(&self, id: &str) -> String {
        self.v.nodes.iter().find(|n| n.value.id == id).map(|n| n.value.name.clone()).unwrap_or_else(|| id.to_string())
    }

    fn server_options(&self) -> Vec<Opt> {
        self.v.nodes.iter().filter(|n| n.value.kind == model::NODE_SERVER).map(|n| opt(&n.value.name, &n.value.id)).collect()
    }

    fn relay_options(&self) -> Vec<Opt> {
        self.v.nodes.iter().filter(|n| n.value.relay && !n.value.endpoints.is_empty()).map(|n| opt(&n.value.name, &n.value.id)).collect()
    }

    /// Exit nodes a device can send its internet traffic through.
    fn exit_options(&self, me: &str) -> Vec<Opt> {
        let mut o = vec![opt("its own connection", "")];
        for n in &self.v.nodes {
            if n.value.exit && n.value.id != me {
                o.push(opt(&format!("through {}", n.value.name), &n.value.id));
            }
        }
        o
    }

    fn me_name(&self) -> String {
        self.name(&self.v.self_id)
    }

    // ---------------------------------------------------------- actions

    fn new_item(&mut self) {
        match self.tab {
            TAB_FORWARDS => self.forward_form(None),
            TAB_HTTPS => self.route_form(None),
            TAB_RULES => self.acl_form(None),
            TAB_EXITS => self.exit_route_form(None),
            TAB_DEVICES => self.token_form(),
            TAB_TRAFFIC if !self.history => self.monitor_form(None),
            _ => {}
        }
    }

    fn edit_item(&mut self) {
        if self.rows() == 0 {
            return;
        }
        let i = self.sel;
        match self.tab {
            TAB_NODES => self.node_form(self.v.nodes[i].clone()),
            TAB_FORWARDS => self.forward_form(Some(self.v.forwards[i].clone())),
            TAB_HTTPS => self.route_form(Some(self.v.routes[i].clone())),
            TAB_RULES => self.acl_form(Some(self.v.acls[i].clone())),
            TAB_EXITS => self.exit_route_form(Some(self.v.exit_routes[i].clone())),
            TAB_TRAFFIC => {
                if let Some(it) = self.selected_monitor() {
                    self.monitor_form(Some(it));
                }
            }
            TAB_TOOLS => {
                let c = self.tool_rows()[i].check.clone();
                self.diag_form(c);
            }
            TAB_SETTINGS => {
                let what = self.setting_rows()[i].open.clone();
                self.open_setting(what);
            }
            TAB_LOGS => {
                if self.log_file {
                    self.note = self.raw_rows()[i].clone();
                    return;
                }
                let r = self.log_rows()[i].clone();
                let where_ = if r.ram { "in this node's RAM, not delivered yet" } else { "on the log server" };
                let (y, mo, d, h, mi, s, _) = crate::logx::local(r.e.t);
                self.note = format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}  {}  ({where_})\n\n{}", self.name(&r.e.node), r.e.text);
            }
            _ => {}
        }
    }

    async fn delete_item(&mut self) {
        if self.rows() == 0 {
            return;
        }
        let i = self.sel;
        let (kind, id) = match self.tab {
            TAB_NODES => (model::KIND_NODE, self.v.nodes[i].value.id.clone()),
            TAB_FORWARDS => (model::KIND_FORWARD, self.v.forwards[i].value.id.clone()),
            TAB_HTTPS => (model::KIND_ROUTE, self.v.routes[i].value.id.clone()),
            TAB_RULES => (model::KIND_ACL, self.v.acls[i].value.id.clone()),
            TAB_EXITS => (model::KIND_EXIT_ROUTE, self.v.exit_routes[i].value.id.clone()),
            TAB_DEVICES => (model::KIND_TOKEN, self.v.tokens[i].id.clone()),
            TAB_TRAFFIC => match self.selected_monitor() {
                Some(it) => (model::KIND_MONITOR, it.value.id),
                None => return,
            },
            _ => return,
        };
        self.message = match self.api.post_ok("delete", &json!({"kind": kind, "id": id, "scope": "cluster"})).await {
            Ok(()) => "Removed.".into(),
            Err(e) => format!("Error: {e}"),
        };
    }

    async fn clear_local(&mut self) {
        if self.rows() == 0 {
            return;
        }
        let i = self.sel;
        let (kind, id) = match self.tab {
            TAB_NODES => (model::KIND_NODE, self.v.nodes[i].value.id.clone()),
            TAB_FORWARDS => (model::KIND_FORWARD, self.v.forwards[i].value.id.clone()),
            TAB_HTTPS => (model::KIND_ROUTE, self.v.routes[i].value.id.clone()),
            TAB_RULES => (model::KIND_ACL, self.v.acls[i].value.id.clone()),
            TAB_EXITS => (model::KIND_EXIT_ROUTE, self.v.exit_routes[i].value.id.clone()),
            _ => return,
        };
        self.message = match self.api.post_ok("clear-local", &json!({"kind": kind, "id": id})).await {
            Ok(()) => "Local override removed; the all-nodes value applies again.".into(),
            Err(e) => format!("Error: {e}"),
        };
    }

    fn run_diag(&self, c: diag::Check) {
        let (Some(tx), api) = (self.tx.clone(), self.api.clone()) else { return };
        tokio::spawn(async move {
            let r = api.post::<diag::Outcome, _>("diag", &c).await;
            let _ = tx.send(Msg::Diag(r));
        });
    }

    // ---------------------------------------------------------- forms

    fn forward_form(&mut self, it: Option<Item<Forward>>) {
        let (f, local, title) = match &it {
            Some(it) => (it.value.clone(), it.local, format!("Edit forward {}", it.value.name)),
            None => (Forward { proto: model::PROTO_TCP.into(), enabled: true, ..Default::default() }, false, "New port forward".into()),
        };
        let servers = self.server_options();
        let end = if f.listen_end > 0 { f.listen_end.to_string() } else { String::new() };
        self.form = Some(
            Form::new(&title, Action::Forward(it.map(|i| i.value)))
                .text("name", "Name", &f.name, "minecraft")
                .choice("proto", "Protocol", vec![opt("tcp", "tcp"), opt("udp", "udp"), opt("tcp+udp", "both")], &f.proto)
                .choice("edge", "Edge node (public)", servers.clone(), &f.edge_node)
                .text("listen", "Public port", &itoa0(f.listen_port), "25565")
                .text("end", "…to port (range, optional)", &end, "")
                .choice("target", "Target node", servers, &f.target_node)
                .text("target_port", "Target port", &itoa0(f.target_port), "25565")
                .text("target_ip", "Target LAN IP (optional)", &f.target_ip, "empty = target node itself")
                .toggle("preserve", "Show players' real IPs", f.preserve_client_ip)
                .toggle("enabled", "Enabled", f.enabled)
                .choice("scope", "Apply to", scope_options(&self.me_name()), scope_of(local)),
        );
    }

    fn route_form(&mut self, it: Option<Item<HttpRoute>>) {
        let (r, local, title) = match &it {
            Some(it) => (it.value.clone(), it.local, format!("Edit route {}", it.value.hostname)),
            None => (HttpRoute { force_https: true, enabled: true, ..Default::default() }, false, "New HTTPS route".into()),
        };
        let servers = self.server_options();
        self.form = Some(
            Form::new(&title, Action::Route(it.map(|i| i.value)))
                .text("host", "Hostname", &r.hostname, "app.example.com")
                .choice("edge", "Edge node (public)", servers.clone(), &r.edge_node)
                .choice("target", "Target node", servers, &r.target_node)
                .text("target_ip", "Target LAN IP (optional)", &r.target_ip, "")
                .text("port", "Target port", &itoa0(r.target_port), "8080")
                .toggle("tls", "Backend uses HTTPS", r.target_tls)
                .toggle("force", "Redirect HTTP to HTTPS", r.force_https)
                .toggle("enabled", "Enabled", r.enabled)
                .choice("scope", "Apply to", scope_options(&self.me_name()), scope_of(local)),
        );
    }

    fn node_form(&mut self, it: Item<Node>) {
        let n = it.value.clone();
        let detected = self.detected_subnets(&n);
        let mut f = Form::new(&format!("Edit node {}", n.name), Action::Node(Box::new(n.clone()), detected.clone()))
            .text("name", "Name", &n.name, "");
        match n.kind.as_str() {
            model::NODE_SERVER => {
                f = f.text("endpoints", "Endpoints (host:port, comma)", &n.endpoints.join(", "), "1.2.3.4:51820, 192.168.1.10:51820").text(
                    "routes",
                    "Shared subnets (comma)",
                    &n.routes.join(", "),
                    "192.168.1.0/24",
                );
                if !detected.is_empty() {
                    f = f.toggle("detect", &format!("Also share detected: {}", detected.join(", ")), false);
                }
                let lan_exit_srcs = n.lan_exits.iter().map(|e| e.src.clone()).collect::<Vec<_>>().join(", ");
                let lan_exit_via = n.lan_exits.first().map(|e| e.via.clone()).unwrap_or_default();
                f = f
                    .toggle("relay", "Relay (public endpoint)", n.relay)
                    .toggle("exit", "Exit node (devices may use it for internet)", n.exit)
                    .text("test_port", "Test service port (empty = off)", &itoa0(n.test_port), "8099")
                    .toggle("app_admin", "Phone app may manage through this node", !n.app_admin_off)
                    .toggle("beep", "Beep when a server link drops/returns", !n.beep_off)
                    .toggle("iptables", "Add iptables allow rules (ufw/Docker)", !n.iptables_off)
                    .toggle("host_firewall", "Open ports in ufw/firewalld automatically", !n.host_firewall_off)
                    .text("lan_exit_src", "LAN devices via exit (IPs/subnets, comma)", &lan_exit_srcs, "192.168.1.205, 192.168.20.0/24")
                    .choice("lan_exit_via", "...through exit node", exit_choices(self.exit_options(&n.id)[1..].to_vec()), &lan_exit_via)
                    .toggle("exit_only", "...exit only (block if no exit reachable)", n.exit_only)
                    .choice(
                        "policy",
                        "LAN policy",
                        vec![
                            opt("open: any mesh device", model::POLICY_OPEN),
                            opt("restricted: rules only", model::POLICY_RESTRICTED),
                            opt("firewall: pfSense rules decide", model::POLICY_FIREWALL),
                        ],
                        if n.restricted() || n.firewall_managed() { &n.lan_policy } else { model::POLICY_OPEN },
                    );
            }
            model::NODE_STATIC => f = f.choice("via", "Connects through relay", self.relay_options(), &n.via_relay),
            model::NODE_CLIENT => {
                f = f
                    .text("exits_allowed", "May use exits (names, comma; * = any)", &self.exit_names(&n.exits_allowed), "vps, vps2")
                    .choice("exit_via", "Default internet away from home", self.exit_options(&n.id), &n.exit_via)
                    .toggle("exit_only", "Exit only (block if no exit reachable)", n.exit_only);
            }
            _ => {}
        }
        self.form = Some(f.choice("scope", "Apply to", scope_options(&self.me_name()), scope_of(it.local)));
    }

    fn exit_route_form(&mut self, it: Option<Item<ExitRoute>>) {
        let (r, local, title) = match &it {
            Some(it) => (it.value.clone(), it.local, format!("Edit exit route {}", it.value.name)),
            None => (ExitRoute { enabled: true, ..Default::default() }, false, "New exit route".into()),
        };
        let mut routers = vec![opt("automatic (from the IP)", "")];
        for n in &self.v.nodes {
            if n.value.kind == model::NODE_SERVER && !n.value.routes.is_empty() {
                routers.push(opt(&n.value.name, &n.value.id));
            }
        }
        self.form = Some(
            Form::new(&title, Action::ExitRoute(it.map(|i| i.value)))
                .text("name", "Name", &r.name, "gaming-vm")
                .text("src", "Device IP or subnet", &r.src, "192.168.200.11")
                .choice("via", "Exit node", exit_choices(self.exit_options("")[1..].to_vec()), &r.via)
                .choice("router", "Router", routers, &r.router)
                .toggle("exit_only", "Exit only (no internet if no exit reachable)", r.exit_only)
                .toggle("enabled", "Enabled", r.enabled)
                .choice("scope", "Apply to", scope_options(&self.me_name()), scope_of(local)),
        );
    }

    fn acl_form(&mut self, it: Option<Item<Acl>>) {
        let (a, local, title) = match &it {
            Some(it) => (it.value.clone(), it.local, format!("Edit rule {}", it.value.name)),
            None => (
                Acl { proto: "tcp".into(), enabled: true, to: model::TO_SELF.into(), ..Default::default() },
                false,
                "New access rule".into(),
            ),
        };
        let from: Vec<String> = a.from.iter().map(|id| self.name(id)).collect();
        let mut hint = "self, 192.168.20.15 or 192.168.20.0/24".to_string();
        if !a.node.is_empty() {
            let l = self.lans(&a.node);
            if !l.is_empty() {
                hint = format!("self or {l}");
            }
        }
        self.form = Some(
            Form::new(&title, Action::Acl(it.map(|i| i.value)))
                .text("name", "Name", &a.name, "laptop to NAS")
                .choice("node", "Enforced on", self.server_options(), &a.node)
                .text("from", "From devices (empty = any)", &from.join(", "), "laptop, phone")
                .text("to", "To", &a.to, &hint)
                .choice(
                    "proto",
                    "Protocol",
                    vec![opt("tcp", "tcp"), opt("udp", "udp"), opt("tcp+udp", "both"), opt("icmp", "icmp"), opt("any", "any")],
                    &a.proto,
                )
                .text("ports", "Ports (empty = all)", &a.ports, "443 or 80,443 or 8000-8100")
                .toggle("enabled", "Enabled", a.enabled)
                .choice("scope", "Apply to", scope_options(&self.me_name()), scope_of(local)),
        );
    }

    fn id_by_name(&self, name: &str) -> Option<String> {
        self.v.nodes.iter().find(|n| n.value.name.to_lowercase() == name.to_lowercase()).map(|n| n.value.id.clone())
    }

    /// A node's local networks ("192.168.20.0/24 (igb1.20)").
    fn lans(&self, node: &str) -> String {
        self.v
            .statuses
            .get(node)
            .map(|s| s.lans.iter().map(|l| format!("{} ({})", l.cidr, l.iface)).collect::<Vec<_>>().join(", "))
            .unwrap_or_default()
    }

    fn token_form(&mut self) {
        self.form = Some(
            Form::new("Create join token", Action::Token)
                .choice("kind", "Device type", vec![opt("phone / laptop", "client"), opt("server", "server")], "client")
                .text("uses", "Uses (-1 = unlimited)", "1", "")
                .text("ttl", "Valid for hours (0 = forever)", "24", "")
                .text("note", "Note", "", "e.g. Alex's phone"),
        );
    }

    fn static_form(&mut self) {
        self.form = Some(Form::new("Device using the official WireGuard app", Action::Static).text("name", "Name", "", "laptop").choice(
            "relay",
            "Relay",
            self.relay_options(),
            "",
        ));
    }

    fn settings_form(&mut self) {
        self.form = Some(Form::new("Network settings", Action::Settings).text(
            "email",
            "Let's Encrypt email (optional)",
            &self.v.network.acme_email,
            "you@example.com",
        ));
    }

    fn exit_names(&self, ids: &[String]) -> String {
        if ids.iter().any(|i| i == "*") {
            return "*".into();
        }
        ids.iter().map(|id| self.name(id)).collect::<Vec<_>>().join(", ")
    }

    /// Runs a form's action with its values.
    async fn submit(&mut self, action: Action, v: HashMap<String, String>) -> Result<(), String> {
        let g = |k: &str| v.get(k).cloned().unwrap_or_default();
        let b = |k: &str| g(k) == "true";
        let api = self.api.clone();
        match action {
            Action::Forward(f) => {
                let f = f.unwrap_or_default();
                let nf = Forward {
                    id: f.id,
                    name: g("name"),
                    proto: g("proto"),
                    edge_node: g("edge"),
                    listen_port: atoi(&g("listen")),
                    listen_end: atoi(&g("end")),
                    target_node: g("target"),
                    target_ip: g("target_ip"),
                    target_port: atoi(&g("target_port")),
                    preserve_client_ip: b("preserve"),
                    enabled: b("enabled"),
                };
                api.post_ok("forward", &json!({"forward": nf, "scope": g("scope")})).await
            }
            Action::Route(r) => {
                let r = r.unwrap_or_default();
                let nr = HttpRoute {
                    id: r.id,
                    hostname: g("host"),
                    edge_node: g("edge"),
                    target_node: g("target"),
                    target_ip: g("target_ip"),
                    target_port: atoi(&g("port")),
                    target_tls: b("tls"),
                    force_https: b("force"),
                    enabled: b("enabled"),
                };
                api.post_ok("route", &json!({"route": nr, "scope": g("scope")})).await
            }
            Action::Node(n, detected) => {
                let mut patch = serde_json::Map::new();
                patch.insert("name".into(), json!(g("name")));
                match n.kind.as_str() {
                    model::NODE_STATIC => {
                        patch.insert("via_relay".into(), json!(g("via")));
                    }
                    model::NODE_CLIENT => {
                        patch.insert("exit_via".into(), json!(g("exit_via")));
                        patch.insert("exit_only".into(), json!(b("exit_only")));
                        let mut allowed: Vec<String> = vec![];
                        for name in lines(&g("exits_allowed")) {
                            if name == "*" || name == "any" {
                                allowed = vec!["*".into()];
                                break;
                            }
                            allowed.extend(
                                self.v
                                    .nodes
                                    .iter()
                                    .filter(|it| it.value.name.to_lowercase() == name.to_lowercase())
                                    .map(|it| it.value.id.clone()),
                            );
                        }
                        patch.insert("exits_allowed".into(), if allowed.is_empty() { serde_json::Value::Null } else { json!(allowed) });
                    }
                    model::NODE_SERVER => {
                        patch.insert("endpoints".into(), json!(lines(&g("endpoints"))));
                        let mut routes = lines(&g("routes"));
                        if b("detect") {
                            for r in detected {
                                if !routes.contains(&r) {
                                    routes.push(r);
                                }
                            }
                        }
                        patch.insert("routes".into(), json!(routes));
                        patch.insert("relay".into(), json!(b("relay")));
                        patch.insert("exit".into(), json!(b("exit")));
                        patch.insert("test_port".into(), json!(atoi(&g("test_port"))));
                        patch.insert("app_admin".into(), json!(b("app_admin")));
                        patch.insert("beep".into(), json!(b("beep")));
                        patch.insert("iptables".into(), json!(b("iptables")));
                        patch.insert("host_firewall".into(), json!(b("host_firewall")));
                        let le: Vec<LanExit> =
                            lines(&g("lan_exit_src")).into_iter().map(|src| LanExit { src, via: g("lan_exit_via") }).collect();
                        patch.insert("lan_exits".into(), if le.is_empty() { serde_json::Value::Null } else { json!(le) });
                        patch.insert("exit_only".into(), json!(b("exit_only")));
                        patch.insert("lan_policy".into(), json!(g("policy")));
                    }
                    _ => {}
                }
                // Go leaves nil slices out of the patch ("omitempty" pointers to
                // nil slices are still sent as null, which clears them).
                api.post_ok("node", &json!({"id": n.id, "patch": patch, "scope": g("scope")})).await
            }
            Action::ExitRoute(r) => {
                let r = r.unwrap_or_default();
                let nr = ExitRoute {
                    id: r.id,
                    name: g("name"),
                    src: g("src"),
                    router: g("router"),
                    via: g("via"),
                    exit_only: b("exit_only"),
                    enabled: b("enabled"),
                };
                api.post_ok("exitroute", &json!({"exit_route": nr, "scope": g("scope")})).await
            }
            Action::Acl(a) => {
                let a = a.unwrap_or_default();
                let mut na = Acl {
                    id: a.id,
                    name: g("name"),
                    node: g("node"),
                    to: g("to"),
                    proto: g("proto"),
                    ports: g("ports"),
                    enabled: b("enabled"),
                    from: vec![],
                };
                for name in lines(&g("from")) {
                    let id = self.id_by_name(&name).ok_or_else(|| format!("no device named {name:?}"))?;
                    na.from.push(id);
                }
                api.post_ok("acl", &json!({"acl": na, "scope": g("scope")})).await
            }
            Action::Token => {
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct Out {
                    token: String,
                }
                let out: Out = api
                    .post("token", &json!({"kind": g("kind"), "uses": atoi(&g("uses")), "ttl_hours": atoi(&g("ttl")), "note": g("note")}))
                    .await?;
                let (linux, pfsense, windows) = crate::join::install_commands(&out.token);
                self.note = if g("kind") == "server" {
                    format!(
                        "Linux server (shell):\n  {linux}\n\npfSense (Diagnostics > Command Prompt > Execute Shell Command):\n  {pfsense}\n\nWindows (PowerShell as Administrator):\n  {windows}\n"
                    )
                } else {
                    let q = crate::cli::qr_small(&out.token, qrcode::EcLevel::L).unwrap_or_default();
                    format!(
                        "Phone: scan with the meshgate app.\nLinux laptop:  {linux} --kind client\nWindows PC (PowerShell as Administrator):  {windows} --kind client\n\n{q}"
                    )
                };
                Ok(())
            }
            Action::Static => {
                let out: crate::ops::StaticDevice = api.post("static-device", &json!({"name": g("name"), "relay": g("relay")})).await?;
                let q = crate::cli::qr_small(&out.config, qrcode::EcLevel::L).unwrap_or_default();
                self.note = format!("Scan with the WireGuard app (private key shown only once):\n\n{q}\n{}", out.config);
                Ok(())
            }
            Action::Settings => api.post_ok("network", &json!({"acme_email": g("email")})).await,
            Action::Monitor(mo) => {
                let mo = mo.unwrap_or_default();
                let nm = Monitor { id: mo.id, name: g("name"), node: g("node"), ip: g("ip"), ports: g("ports"), proto: g("proto") };
                api.post_ok("monitor", &json!({"monitor": nm, "scope": "cluster"})).await
            }
            Action::Diag => {
                self.diag_req = Some(diag::Check { kind: g("kind"), target: g("target"), port: atoi(&g("port")) });
                Ok(())
            }
            Action::History => api.post_ok("history-settings", &json!({"log_server": g("server"), "log_days": atoi(&g("days"))})).await,
            Action::Admin => api.post_ok("admin", &json!({"username": g("user"), "password": g("pass")})).await,
            Action::LogSearch => {
                self.log_text = g("q");
                self.sel = 0;
                Ok(())
            }
        }
    }
}

fn exit_choices(o: Vec<Opt>) -> Vec<Opt> {
    if o.is_empty() { vec![opt("(no exit node yet)", "")] } else { o }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::PeerRuntime;

    pub fn model_for_shot() -> Model {
        model()
    }

    fn model() -> Model {
        let mut m = Model::new(Client::new("/nonexistent"), "classic");
        m.v = View {
            self_id: "a".into(),
            network: model::Network { cidr: "100.88.0.0/16".into(), ..Default::default() },
            nodes: vec![
                Item {
                    value: Node {
                        id: "a".into(),
                        name: "vps".into(),
                        kind: "server".into(),
                        relay: true,
                        mesh_ip: "100.88.0.1".into(),
                        endpoints: vec!["1.2.3.4:51820".into()],
                        ..Default::default()
                    },
                    local: false,
                },
                Item {
                    value: Node {
                        id: "b".into(),
                        name: "home".into(),
                        kind: "server".into(),
                        mesh_ip: "100.88.0.2".into(),
                        ..Default::default()
                    },
                    local: true,
                },
            ],
            forwards: vec![Item {
                value: Forward {
                    id: "f".into(),
                    name: "minecraft".into(),
                    proto: "tcp".into(),
                    edge_node: "a".into(),
                    listen_port: 25565,
                    target_node: "b".into(),
                    target_port: 25565,
                    enabled: true,
                    ..Default::default()
                },
                local: false,
            }],
            runtime: crate::ops::Runtime {
                peers: BTreeMap::from([(
                    "b".into(),
                    PeerRuntime { path: "direct".into(), last_handshake: (crate::util::now_unix(), 0), ..Default::default() },
                )]),
                ..Default::default()
            },
            ..Default::default()
        };
        m
    }

    #[tokio::test]
    async fn views_render() {
        let mut m = model();
        for tab in 0..TABS.len() {
            m.tab = tab;
            assert!(m.view().contains("MESHGATE"), "tab {tab} did not render");
        }
        m.tab = 1;
        m.forward_form(Some(m.v.forwards[0].clone()));
        let v = m.view();
        assert!(v.contains("Apply to") && v.contains("EDIT FORWARD"), "form missing scope choice");
        for k in ["tab", "tab", "right", "down", " ", "shift+tab", "esc"] {
            m.key(k).await;
        }
        assert!(m.form.is_none(), "esc did not close the form");
        // Narrow and short terminals still render.
        m.width = 40;
        m.height = 12;
        m.tab = 0;
        assert!(m.view().lines().count() <= 12);
    }
}

#[cfg(test)]
mod shot {
    #[tokio::test]
    async fn print_screens() {
        if std::env::var_os("TUI_SHOT").is_none() {
            return;
        }
        let mut m = super::tests::model_for_shot();
        m.width = 100;
        m.height = 30;
        for tab in [0, 1] {
            m.tab = tab;
            let v = m.view();
            let mut plain = String::new();
            let mut esc = false;
            for c in v.chars() {
                if c == '\x1b' {
                    esc = true;
                } else if esc {
                    if c.is_ascii_alphabetic() {
                        esc = false;
                    }
                } else {
                    plain.push(c);
                }
            }
            println!("{plain}\n----");
        }
    }
}
