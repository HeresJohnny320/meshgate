//! Styles, themes and layout helpers (the Go TUI's lipgloss look):
//! ANSI-aware width, truncation, wrapping, rounded panels.

use std::sync::RwLock;

use unicode_width::UnicodeWidthChar;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Style {
    pub fg: Option<(u8, u8, u8)>,
    pub bg: Option<(u8, u8, u8)>,
    pub bold: bool,
    pub underline: bool,
    pub reverse: bool,
    pub pad: usize,
}

fn truecolor() -> bool {
    static T: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *T.get_or_init(|| matches!(std::env::var("COLORTERM").as_deref(), Ok("truecolor") | Ok("24bit")) || cfg!(windows))
}

/// The nearest xterm-256 color (termenv's mapping).
fn ansi256(r: u8, g: u8, b: u8) -> u8 {
    let q = |v: u8| -> u8 {
        if v < 48 {
            0
        } else if v < 115 {
            1
        } else {
            (v - 35) / 40
        }
    };
    let (qr, qg, qb) = (q(r), q(g), q(b));
    let lv = [0u8, 95, 135, 175, 215, 255];
    let (cr, cg, cb) = (lv[qr as usize], lv[qg as usize], lv[qb as usize]);
    let avg = (r as u32 + g as u32 + b as u32) / 3;
    let gi = if avg > 238 { 23 } else { avg.saturating_sub(3) / 10 };
    let gv = (8 + 10 * gi) as u8;
    let dist = |x: u8, y: u8, z: u8| {
        let (dr, dg, db) = (r as i32 - x as i32, g as i32 - y as i32, b as i32 - z as i32);
        dr * dr + dg * dg + db * db
    };
    if dist(cr, cg, cb) <= dist(gv, gv, gv) { 16 + 36 * qr + 6 * qg + qb } else { 232 + gi as u8 }
}

fn color_code(c: (u8, u8, u8), bg: bool) -> String {
    let base = if bg { 48 } else { 38 };
    if truecolor() { format!("{base};2;{};{};{}", c.0, c.1, c.2) } else { format!("{base};5;{}", ansi256(c.0, c.1, c.2)) }
}

impl Style {
    pub fn fg(hex: &str, bold: bool) -> Style {
        Style { fg: parse_hex(hex), bold, ..Default::default() }
    }

    fn codes(&self) -> String {
        let mut c = vec![];
        if self.bold {
            c.push("1".to_string());
        }
        if self.underline {
            c.push("4".to_string());
        }
        if self.reverse {
            c.push("7".to_string());
        }
        if let Some(f) = self.fg {
            c.push(color_code(f, false));
        }
        if let Some(b) = self.bg {
            c.push(color_code(b, true));
        }
        c.join(";")
    }

    /// Styles every line of s (with the horizontal padding inside).
    pub fn render(&self, s: &str) -> String {
        let codes = self.codes();
        let pad = " ".repeat(self.pad);
        s.split('\n')
            .map(|l| {
                let body = format!("{pad}{l}{pad}");
                if codes.is_empty() || body.is_empty() { body } else { format!("\x1b[{codes}m{body}\x1b[0m") }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn parse_hex(h: &str) -> Option<(u8, u8, u8)> {
    let h = h.strip_prefix('#')?;
    if h.len() != 6 {
        return None;
    }
    Some((u8::from_str_radix(&h[0..2], 16).ok()?, u8::from_str_radix(&h[2..4], 16).ok()?, u8::from_str_radix(&h[4..6], 16).ok()?))
}

/// Every style of the current theme.
#[derive(Clone, Debug, Default)]
pub struct Styles {
    pub brand: Style,
    pub section: Style,
    pub muted: Style,
    pub label: Style,
    pub selected: Style,
    pub public: Style,
    pub address: Style,
    pub port: Style,
    pub protocol: Style,
    pub enabled: Style,
    pub disabled: Style,
    pub key: Style,
    pub message: Style,
    pub message_border: Option<(u8, u8, u8)>,
    pub value: Style,
    pub focused: Style,
    pub warn: Style,
    pub err: Style,
    pub accent: Option<(u8, u8, u8)>,
    pub quiet: Option<(u8, u8, u8)>,
    pub selected_border: Option<(u8, u8, u8)>,
}

pub struct Theme {
    pub name: &'static str,
    pub label: &'static str,
    plain: bool,
    c: [&'static str; 25],
}

// brandFG brandBG section muted label selected public address port protocol
// enabled disabled keyFG keyBG message messageBorder accent quiet
// selectedBorder value focused warn err
pub const THEMES: [Theme; 5] = [
    Theme {
        name: "classic",
        label: "Classic",
        plain: false,
        c: [
            "#F2F7F3", "#176B4B", "#75D6A3", "#8B9A91", "#96A79C", "#F5F8F5", "#E5B85C", "#61C7D4", "#81D69F", "#C5A7EF", "#66D494",
            "#D9A36A", "#12241A", "#80D6A5", "#F0D28A", "#D9A64F", "#3B7557", "#394940", "#58B981", "#DDE7DF", "#F2C96D", "#F0D28A",
            "#F07A6A", "", "",
        ],
    },
    Theme {
        name: "readable",
        label: "Readable",
        plain: false,
        c: [
            "#000000", "#FFD75F", "#FFFFFF", "#D0D0D0", "#E4E4E4", "#FFFFFF", "#FFD75F", "#5FD7FF", "#87FF87", "#FF87FF", "#5FFF5F",
            "#FF8700", "#000000", "#FFFFFF", "#FFFFFF", "#FFD75F", "#FFFFFF", "#8A8A8A", "#FFD75F", "#FFFFFF", "#FFD75F", "#FFD75F",
            "#FF5F5F", "", "",
        ],
    },
    Theme {
        name: "light",
        label: "Light terminal",
        plain: false,
        c: [
            "#FFFFFF", "#176B4B", "#0E5A3A", "#4E5D55", "#3D4A43", "#000000", "#8A5A00", "#005F87", "#1F6B3A", "#6B2FA0", "#1E7A44",
            "#A0461C", "#FFFFFF", "#176B4B", "#5A3C00", "#B07A1A", "#176B4B", "#9AA59E", "#0E5A3A", "#1A1A1A", "#8A3C00", "#8A5A00",
            "#B0281A", "", "",
        ],
    },
    Theme {
        name: "ocean",
        label: "Ocean",
        plain: false,
        c: [
            "#F4F8FC", "#1F5F99", "#7FB8F0", "#8C9BAD", "#9FB0C4", "#F4F8FC", "#F0C674", "#7FDBEB", "#8FE3B8", "#C9A7F5", "#6FD0A0",
            "#E8A06A", "#0B1B2B", "#7FB8F0", "#F0D28A", "#7FB8F0", "#2A5D8F", "#2C3E50", "#7FB8F0", "#DCE6F0", "#F0C674", "#F0D28A",
            "#F07A6A", "", "",
        ],
    },
    Theme { name: "plain", label: "Plain (no colors)", plain: true, c: [""; 25] },
];

pub fn find_theme(name: &str) -> &'static Theme {
    THEMES.iter().find(|t| t.name == name).unwrap_or(&THEMES[0])
}

pub fn next_theme(name: &str) -> &'static Theme {
    let i = THEMES.iter().position(|t| t.name == name).map(|i| (i + 1) % THEMES.len()).unwrap_or(0);
    &THEMES[i]
}

static CURRENT: RwLock<Option<Styles>> = RwLock::new(None);

pub fn apply_theme(t: &Theme) {
    let col = |i: usize| if t.plain { None } else { parse_hex(t.c[i]) };
    let text = |i: usize, bold: bool| Style { fg: col(i), bold, ..Default::default() };
    let mut s = Styles {
        brand: Style { fg: col(0), bg: col(1), bold: true, pad: 1, ..Default::default() },
        key: Style { fg: col(12), bg: col(13), bold: true, ..Default::default() },
        section: text(2, true),
        muted: text(3, false),
        label: text(4, false),
        selected: text(5, true),
        public: text(6, true),
        address: text(7, true),
        port: text(8, true),
        protocol: text(9, true),
        enabled: text(10, true),
        disabled: text(11, true),
        warn: text(21, false),
        err: text(22, true),
        message: text(14, false),
        message_border: col(15),
        value: text(19, false),
        focused: text(20, true),
        accent: col(16),
        quiet: col(17),
        selected_border: col(18),
    };
    if t.plain {
        s.brand.reverse = true;
        s.key.reverse = true;
        s.disabled.underline = true;
        s.focused.underline = true;
    }
    *CURRENT.write().unwrap() = Some(s);
}

/// The current styles.
pub fn st() -> Styles {
    if CURRENT.read().unwrap().is_none() {
        apply_theme(&THEMES[0]);
    }
    CURRENT.read().unwrap().clone().unwrap()
}

fn theme_file() -> Option<std::path::PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("AppData").map(std::path::PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(std::path::PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| std::path::Path::new(&h).join(".config")))
    }?;
    Some(base.join("meshgate").join("tui-theme"))
}

pub fn load_theme() -> &'static Theme {
    theme_file().and_then(|f| std::fs::read_to_string(f).ok()).map(|s| find_theme(s.trim())).unwrap_or(&THEMES[0])
}

pub fn save_theme(name: &str) {
    if let Some(f) = theme_file() {
        if let Some(d) = f.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let _ = std::fs::write(f, format!("{name}\n"));
    }
}

// ---------------------------------------------------------------- layout

/// Display width, ignoring ANSI escape sequences.
pub fn width(s: &str) -> usize {
    let mut w = 0;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        w += c.width().unwrap_or(0);
    }
    w
}

/// Height in lines.
pub fn height(s: &str) -> usize {
    s.split('\n').count()
}

/// Cuts styled text to at most w columns, ending with tail when cut.
pub fn truncate(s: &str, w: usize, tail: &str) -> String {
    if width(s) <= w {
        return s.to_string();
    }
    let room = w.saturating_sub(width(tail));
    let mut out = String::new();
    let mut used = 0;
    let mut styled = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            out.push(c);
            for c2 in chars.by_ref() {
                out.push(c2);
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
            styled = true;
            continue;
        }
        let cw = c.width().unwrap_or(0);
        if used + cw > room {
            break;
        }
        used += cw;
        out.push(c);
    }
    out.push_str(tail);
    if styled {
        out.push_str("\x1b[0m");
    }
    out
}

/// One line of at most width columns.
pub fn line(w: usize, text: &str) -> String {
    truncate(&text.replace('\n', " "), w, "…")
}

/// Word-wraps styled text to width (long words are broken).
fn ansi_wrap(text: &str, w: usize) -> String {
    let mut out: Vec<String> = vec![];
    for para in text.split('\n') {
        let mut cur = String::new();
        let mut cur_w = 0;
        for (i, word) in para.split(' ').enumerate() {
            let mut word = word.to_string();
            let mut ww = width(&word);
            let sep = if i == 0 { 0 } else { 1 };
            if cur_w + sep + ww <= w {
                if i > 0 {
                    cur.push(' ');
                }
                cur.push_str(&word);
                cur_w += sep + ww;
                continue;
            }
            if cur_w > 0 || i > 0 {
                out.push(std::mem::take(&mut cur));
            }
            while ww > w {
                let head = truncate(&word, w, "");
                let hl = head.trim_end_matches("\x1b[0m").len();
                out.push(head.clone());
                word = word[hl.min(word.len())..].to_string();
                ww = width(&word);
            }
            cur = word;
            cur_w = ww;
        }
        out.push(cur);
    }
    out.join("\n")
}

/// Breaks text to fit width and pads every line to it.
pub fn wrap(w: usize, text: &str) -> String {
    let w = w.max(1);
    ansi_wrap(text, w)
        .split('\n')
        .map(|t| {
            let l = line(w, t.trim_end_matches(' '));
            let pad = w.saturating_sub(width(&l));
            format!("{l}{}", " ".repeat(pad))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn inner_width(w: usize) -> usize {
    if w < 8 { w.max(1) } else { w - 4 }
}

/// A rounded box exactly width columns wide.
pub fn panel(w: usize, color: Option<(u8, u8, u8)>, lines: &[String]) -> String {
    let content = lines.join("\n");
    if w < 8 {
        return wrap(w, &content);
    }
    let b = Style { fg: color, ..Default::default() };
    let inner = inner_width(w);
    let mut out = vec![b.render(&format!("╭{}╮", "─".repeat(w - 2)))];
    for l in wrap(inner, &content).split('\n') {
        out.push(format!("{} {l} {}", b.render("│"), b.render("│")));
    }
    out.push(b.render(&format!("╰{}╯", "─".repeat(w - 2))));
    out.join("\n")
}

/// The message box: a colored left bar, wrapped to width.
pub fn message(w: usize, text: &str) -> String {
    let s = st();
    let bar = Style { fg: s.message_border, ..Default::default() }.render("│");
    let inner = w.saturating_sub(1).max(1);
    wrap(inner, &s.message.render(text)).split('\n').map(|l| format!("{bar} {l}")).collect::<Vec<_>>().join("\n")
}

/// Lays items out left to right, wrapping like words.
pub fn flow(w: usize, items: &[String]) -> String {
    let mut out = vec![];
    let mut cur = String::new();
    for it in items {
        let it = line(w, it);
        if cur.is_empty() {
            cur = it;
        } else if width(&cur) + 2 + width(&it) <= w {
            cur = format!("{cur}  {it}");
        } else {
            out.push(std::mem::replace(&mut cur, it));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out.join("\n")
}

/// Keeps the view inside the terminal, top first.
pub fn fit_screen(view: &str, w: usize, h: usize) -> String {
    let mut ls: Vec<String> = view.split('\n').map(|l| if w > 0 { truncate(l, w, "") } else { l.to_string() }).collect();
    if h > 0 && ls.len() > h {
        ls.truncate(h);
    }
    ls.join("\n")
}

/// "-" for an empty value.
pub fn dash_text(s: &str) -> String {
    if s.is_empty() { "-".into() } else { s.into() }
}

pub fn help_key(k: &str, d: &str) -> String {
    let s = st();
    format!("{} {}", s.key.render(&format!(" {k} ")), s.muted.render(d))
}

pub fn on_off(on: bool, on_text: &str, off_text: &str) -> String {
    let s = st();
    if on { s.enabled.render(on_text) } else { s.disabled.render(off_text) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widths_and_truncation() {
        let s = Style { fg: Some((1, 2, 3)), bold: true, ..Default::default() }.render("héllo");
        assert_eq!(width(&s), 5);
        let t = truncate(&format!("{s} world"), 7, "…");
        assert_eq!(width(&t), 7);
        assert_eq!(wrap(5, "ab cdefghij k"), "ab   \ncdefg\nhij k");
        let p = panel(20, None, &["x".into()]);
        assert!(p.lines().all(|l| width(l) == 20), "{p}");
        assert_eq!(flow(10, &["aaaa".into(), "bbbb".into(), "c".into()]), "aaaa  bbbb\nc");
        assert!(ansi256(0x17, 0x6B, 0x4B) >= 16);
    }
}
