//! A small vertical form (Go: internal/tui/form.go): TAB/SHIFT+TAB or
//! UP/DOWN move, SPACE toggles, LEFT/RIGHT change choices, ENTER on the
//! last field (or CTRL+S) submits, ESC cancels.

use std::collections::HashMap;

use super::style::{dash_text, help_key, inner_width, line, message, panel, st};

#[derive(Clone, Debug)]
pub struct Opt {
    pub label: String,
    pub value: String,
}

pub fn opt(label: &str, value: &str) -> Opt {
    Opt { label: label.into(), value: value.into() }
}

/// A one-line text input (bubbles/textinput).
#[derive(Clone, Debug, Default)]
pub struct Input {
    pub value: Vec<char>,
    pub cursor: usize,
    pub placeholder: String,
    pub password: bool,
    offset: usize,
}

impl Input {
    pub fn text(&self) -> String {
        self.value.iter().collect()
    }

    /// Handles a key; true when it was used.
    pub fn key(&mut self, k: &str) -> bool {
        match k {
            "left" | "ctrl+b" => self.cursor = self.cursor.saturating_sub(1),
            "right" | "ctrl+f" => self.cursor = (self.cursor + 1).min(self.value.len()),
            "home" | "ctrl+a" => self.cursor = 0,
            "end" | "ctrl+e" => self.cursor = self.value.len(),
            "backspace" | "ctrl+h" => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    self.value.remove(self.cursor);
                }
            }
            "delete" | "ctrl+d" => {
                if self.cursor < self.value.len() {
                    self.value.remove(self.cursor);
                }
            }
            "ctrl+u" => {
                self.value.drain(..self.cursor);
                self.cursor = 0;
            }
            "ctrl+k" => self.value.truncate(self.cursor),
            "ctrl+w" => {
                let mut i = self.cursor;
                while i > 0 && self.value[i - 1] == ' ' {
                    i -= 1;
                }
                while i > 0 && self.value[i - 1] != ' ' {
                    i -= 1;
                }
                self.value.drain(i..self.cursor);
                self.cursor = i;
            }
            _ => {
                let mut cs = k.chars();
                match (cs.next(), cs.next()) {
                    (Some(c), None) if !c.is_control() => {
                        if self.value.len() < 512 {
                            self.value.insert(self.cursor, c);
                            self.cursor += 1;
                        }
                    }
                    _ => return false,
                }
            }
        }
        true
    }

    /// Inserts pasted text.
    pub fn paste(&mut self, s: &str) {
        for c in s.chars().filter(|c| !c.is_control()) {
            self.key(&c.to_string());
        }
    }

    /// The focused view: a window of `width` columns around the cursor.
    pub fn view(&mut self, width: usize) -> String {
        let s = st();
        if self.value.is_empty() {
            let ph: String = self.placeholder.chars().take(width.saturating_sub(1)).collect();
            let mut cs = ph.chars();
            let first = cs.next().map(|c| c.to_string()).unwrap_or_else(|| " ".into());
            return format!("\x1b[7m{}\x1b[0m{}", s.muted.render(&first), s.muted.render(cs.as_str()));
        }
        if self.cursor < self.offset {
            self.offset = self.cursor;
        }
        if self.cursor >= self.offset + width {
            self.offset = self.cursor + 1 - width;
        }
        let shown: Vec<char> = if self.password { vec!['•'; self.value.len()] } else { self.value.clone() };
        let end = (self.offset + width).min(shown.len());
        let mut out = String::new();
        for (i, c) in shown[self.offset..end].iter().enumerate() {
            if self.offset + i == self.cursor {
                out.push_str(&format!("\x1b[7m{c}\x1b[0m"));
            } else {
                out.push(*c);
            }
        }
        if self.cursor == shown.len() {
            out.push_str("\x1b[7m \x1b[0m");
        }
        out
    }
}

#[derive(Clone, Debug)]
pub enum Kind {
    Text(Input),
    Bool(bool),
    Choice(Vec<Opt>, usize),
}

#[derive(Clone, Debug)]
pub struct Field {
    pub key: String,
    pub label: String,
    pub kind: Kind,
}

impl Field {
    pub fn value(&self) -> String {
        match &self.kind {
            Kind::Bool(on) => if *on { "true" } else { "false" }.into(),
            Kind::Choice(o, i) => o.get(*i).map(|o| o.value.clone()).unwrap_or_default(),
            Kind::Text(t) => t.text().trim().to_string(),
        }
    }
}

/// What submitting the form does (handled by the model).
#[derive(Clone, Debug)]
pub enum Action {
    Forward(Option<crate::model::Forward>),
    Route(Option<crate::model::HttpRoute>),
    Node(Box<crate::model::Node>, Vec<String>),
    ExitRoute(Option<crate::model::ExitRoute>),
    Acl(Option<crate::model::Acl>),
    Token,
    Static,
    Settings,
    Monitor(Option<crate::model::Monitor>),
    Diag,
    History,
    Admin,
    LogSearch,
}

pub struct Form {
    pub title: String,
    pub fields: Vec<Field>,
    pub focus: usize,
    pub err: String,
    pub action: Action,
}

pub enum Outcome {
    Stay,
    Cancel,
    Submit(HashMap<String, String>),
}

impl Form {
    pub fn new(title: &str, action: Action) -> Form {
        Form { title: title.into(), fields: vec![], focus: 0, err: String::new(), action }
    }

    pub fn text(mut self, key: &str, label: &str, val: &str, placeholder: &str) -> Form {
        let v: Vec<char> = val.chars().collect();
        let input = Input { cursor: v.len(), value: v, placeholder: placeholder.into(), ..Default::default() };
        self.fields.push(Field { key: key.into(), label: label.into(), kind: Kind::Text(input) });
        self
    }

    pub fn password(mut self, key: &str, label: &str) -> Form {
        self = self.text(key, label, "", "");
        if let Some(Field { kind: Kind::Text(t), .. }) = self.fields.last_mut() {
            t.password = true;
        }
        self
    }

    pub fn toggle(mut self, key: &str, label: &str, on: bool) -> Form {
        self.fields.push(Field { key: key.into(), label: label.into(), kind: Kind::Bool(on) });
        self
    }

    pub fn choice(mut self, key: &str, label: &str, opts: Vec<Opt>, current: &str) -> Form {
        let i = opts.iter().rposition(|o| o.value == current).unwrap_or(0);
        self.fields.push(Field { key: key.into(), label: label.into(), kind: Kind::Choice(opts, i) });
        self
    }

    fn set_focus(&mut self, i: isize) {
        let n = self.fields.len() as isize;
        self.focus = if i < 0 {
            (n - 1).max(0) as usize
        } else if i >= n {
            0
        } else {
            i as usize
        };
    }

    pub fn values(&self) -> HashMap<String, String> {
        self.fields.iter().map(|f| (f.key.clone(), f.value())).collect()
    }

    pub fn paste(&mut self, s: &str) {
        if let Some(Field { kind: Kind::Text(t), .. }) = self.fields.get_mut(self.focus) {
            t.paste(s);
        }
    }

    pub fn update(&mut self, k: &str) -> Outcome {
        match k {
            "esc" => return Outcome::Cancel,
            "tab" | "down" => {
                self.set_focus(self.focus as isize + 1);
                return Outcome::Stay;
            }
            "shift+tab" | "up" => {
                self.set_focus(self.focus as isize - 1);
                return Outcome::Stay;
            }
            "ctrl+s" => return Outcome::Submit(self.values()),
            "enter" => {
                if self.focus + 1 == self.fields.len() {
                    return Outcome::Submit(self.values());
                }
                self.set_focus(self.focus as isize + 1);
                return Outcome::Stay;
            }
            _ => {}
        }
        let Some(cur) = self.fields.get_mut(self.focus) else { return Outcome::Stay };
        match &mut cur.kind {
            Kind::Bool(on) => {
                if matches!(k, " " | "left" | "right") {
                    *on = !*on;
                }
            }
            Kind::Choice(o, i) => {
                if !o.is_empty() {
                    match k {
                        "left" | "h" => *i = (*i + o.len() - 1) % o.len(),
                        "right" | "l" | " " => *i = (*i + 1) % o.len(),
                        _ => {}
                    }
                }
            }
            Kind::Text(t) => {
                t.key(k);
            }
        }
        Outcome::Stay
    }

    pub fn view(&mut self, width: usize) -> String {
        let s = st();
        let inner = inner_width(width);
        let mut body = vec![line(inner, &s.brand.render(&self.title.to_uppercase())), String::new()];
        let focus = self.focus;
        for (i, f) in self.fields.iter_mut().enumerate() {
            let (marker, style) = if i == focus { (s.selected.render("> "), s.focused) } else { ("  ".to_string(), s.value) };
            let val = match &mut f.kind {
                Kind::Text(t) => {
                    if i == focus {
                        t.view(inner.saturating_sub(32).max(10))
                    } else if t.password {
                        style.render(&dash_text(&"•".repeat(t.value.len())))
                    } else {
                        style.render(&dash_text(&t.text()))
                    }
                }
                Kind::Bool(on) => style.render(if *on { "[x] yes" } else { "[ ] no" }),
                Kind::Choice(o, idx) => o.get(*idx).map(|o| style.render(&format!("< {} >", o.label))).unwrap_or_default(),
            };
            body.push(line(inner, &format!("{marker}{} {val}", s.label.render(&format!("{:<28}", format!("{}:", f.label))))));
        }
        let mut out = vec![
            panel(width, s.accent, &body),
            super::style::flow(
                width,
                &[
                    help_key("TAB/UP/DOWN", "move"),
                    help_key("SPACE/LEFT/RIGHT", "change"),
                    help_key("ENTER", "next / save on last"),
                    help_key("CTRL+S", "save"),
                    help_key("ESC", "cancel"),
                ],
            ),
        ];
        if !self.err.is_empty() {
            out.push(message(width.saturating_sub(2).max(1), &s.err.render(&self.err)));
        }
        out.join("\n")
    }
}
