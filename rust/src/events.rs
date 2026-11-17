//! The mesh's event log (Go: internal/events). Each node keeps its log
//! lines in RAM until the log server has them; the log server appends them
//! to events-YYYY-MM-DD.jsonl (UTC days) and deletes days beyond retention.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// One log line of one node.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Entry {
    pub t: i64,
    pub node: String,
    pub text: String,
    /// Order in this node's buffer (not serialized).
    #[serde(skip)]
    pub seq: u64,
}

/// The lines worth seeing first: links going down or up, path changes,
/// restarts, warnings and errors.
pub fn important(text: &str) -> bool {
    const WORDS: [&str; 10] =
        ["down", "up again", "path to", "restarted", "recreated", "updated", "warning", "resolved", "error", "failed"];
    let lower = text.to_lowercase();
    let b = lower.as_bytes();
    let word_char = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    for w in WORDS.iter().chain(std::iter::once(&"panic")) {
        let mut from = 0;
        while let Some(i) = lower[from..].find(w) {
            let s = from + i;
            let e = s + w.len();
            let before = s == 0 || !word_char(b[s - 1]);
            let after = e == b.len() || !word_char(b[e]);
            if before && after {
                return true;
            }
            from = s + 1;
        }
    }
    false
}

#[derive(Default)]
struct BufState {
    pending: Vec<Entry>,
    recent: Vec<Entry>,
    dropped: usize,
    partial: Vec<u8>,
    seq: u64,
}

/// Keeps log lines in RAM: undelivered ones (up to max) and the last
/// `recent` for this node's own view.
pub struct Buffer {
    pub node: String,
    pub max: usize,
    pub recent: usize,
    st: Mutex<BufState>,
}

/// What this node holds in RAM, for its own UIs.
#[derive(Clone, Debug, Default, Serialize)]
pub struct State {
    pub pending: Vec<Entry>,
    pub recent: Vec<Entry>,
    pub dropped: usize,
}

/// Strips package log's "2006/01/02 15:04:05 " prefix.
fn strip_log_prefix(line: &str) -> &str {
    let b = line.as_bytes();
    let d = |i: usize| b.get(i).is_some_and(|c| c.is_ascii_digit());
    let ok = b.len() > 19
        && (0..4).all(d)
        && b[4] == b'/'
        && d(5)
        && d(6)
        && b[7] == b'/'
        && d(8)
        && d(9)
        && b[10] == b' '
        && d(11)
        && d(12)
        && b[13] == b':'
        && d(14)
        && d(15)
        && b[16] == b':'
        && d(17)
        && d(18);
    if !ok {
        return line;
    }
    let mut i = 19;
    if b.get(i) == Some(&b'.') && d(i + 1) {
        i += 1;
        while d(i) {
            i += 1;
        }
    }
    if b.get(i) == Some(&b' ') { &line[i + 1..] } else { line }
}

impl Buffer {
    pub fn new(node: &str, max: usize, recent: usize) -> Buffer {
        Buffer { node: node.into(), max, recent, st: Mutex::new(BufState::default()) }
    }

    /// Takes whole lines; a partial line waits for its end.
    pub fn write(&self, p: &[u8]) {
        self.write_at(p, crate::util::now_unix());
    }

    pub fn write_at(&self, p: &[u8], now: i64) {
        let mut st = self.st.lock().unwrap();
        st.partial.extend_from_slice(p);
        while let Some(i) = st.partial.iter().position(|c| *c == b'\n') {
            let raw: Vec<u8> = st.partial.drain(..=i).collect();
            let s = String::from_utf8_lossy(&raw[..raw.len() - 1]).into_owned();
            let line = strip_log_prefix(s.trim_end_matches('\r')).to_string();
            if line.is_empty() {
                continue;
            }
            st.seq += 1;
            let e = Entry { t: now, node: self.node.clone(), text: line, seq: st.seq };
            st.pending.push(e.clone());
            if st.pending.len() > self.max {
                let over = st.pending.len() - self.max;
                st.pending.drain(..over);
                st.dropped += over;
            }
            st.recent.push(e);
            if st.recent.len() > self.recent {
                let over = st.recent.len() - self.recent;
                st.recent.drain(..over);
            }
        }
    }

    /// Up to n of the oldest undelivered lines (a copy).
    pub fn take(&self, n: usize) -> Vec<Entry> {
        let st = self.st.lock().unwrap();
        st.pending[..n.min(st.pending.len())].to_vec()
    }

    /// Drops what take returned once the log server has it.
    pub fn ack(&self, sent: &[Entry]) {
        let Some(last) = sent.last().map(|e| e.seq) else { return };
        let mut st = self.st.lock().unwrap();
        let i = st.pending.iter().take_while(|e| e.seq <= last).count();
        st.pending.drain(..i);
    }

    pub fn snapshot(&self) -> State {
        let st = self.st.lock().unwrap();
        State { pending: st.pending.clone(), recent: st.recent.clone(), dropped: st.dropped }
    }
}

/// A search of the stored lines.
#[derive(Clone, Debug, Default)]
pub struct Query {
    pub since: i64,
    pub until: i64,
    pub node: String,
    pub text: String,
    pub important: bool,
    pub limit: usize,
}

impl Query {
    pub fn matches(&self, e: &Entry) -> bool {
        (self.since == 0 || e.t >= self.since)
            && (self.until == 0 || e.t <= self.until)
            && (self.node.is_empty() || e.node == self.node)
            && (self.text.is_empty() || e.text.to_lowercase().contains(&self.text.to_lowercase()))
            && (!self.important || important(&e.text))
    }
}

/// The log server's files.
pub struct Store {
    pub dir: PathBuf,
    mu: Mutex<()>,
}

pub fn utc_day(t: i64) -> String {
    let (y, m, d, ..) = crate::logx::utc(t);
    format!("{y:04}-{m:02}-{d:02}")
}

fn day_of(name: &str) -> Option<&str> {
    let d = name.strip_prefix("events-")?.strip_suffix(".jsonl")?;
    let b = d.as_bytes();
    (b.len() == 10 && b[4] == b'-' && b[7] == b'-' && b.iter().enumerate().all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit()))
        .then_some(d)
}

impl Store {
    pub fn new(dir: PathBuf) -> Store {
        Store { dir, mu: Mutex::new(()) }
    }

    /// Adds entries to their days' files.
    pub fn append(&self, es: &[Entry]) -> Result<(), String> {
        let _g = self.mu.lock().unwrap();
        crate::config::secure_dir(&self.dir).map_err(|e| e.to_string())?;
        let mut by_day: std::collections::BTreeMap<String, Vec<&Entry>> = Default::default();
        for e in es {
            by_day.entry(utc_day(e.t)).or_default().push(e);
        }
        for (d, list) in by_day {
            let mut o = std::fs::OpenOptions::new();
            o.create(true).append(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
            let f = o.open(self.dir.join(format!("events-{d}.jsonl"))).map_err(|e| e.to_string())?;
            let mut w = std::io::BufWriter::new(f);
            for e in list {
                let mut b = crate::gojson::marshal(e);
                b.push(b'\n');
                w.write_all(&b).map_err(|e| e.to_string())?;
            }
            w.flush().map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Matching lines, newest first.
    pub fn query(&self, q: &Query) -> Result<Vec<Entry>, String> {
        let _g = self.mu.lock().unwrap();
        let limit = if q.limit == 0 { 500 } else { q.limit };
        let mut days: Vec<String> = std::fs::read_dir(&self.dir)
            .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect())
            .unwrap_or_default();
        days.retain(|n| {
            day_of(n).is_some_and(|d| !(q.since > 0 && d < utc_day(q.since).as_str()) && !(q.until > 0 && d > utc_day(q.until).as_str()))
        });
        days.sort_by(|a, b| b.cmp(a));
        let mut out = vec![];
        for name in days {
            let Ok(data) = std::fs::read(self.dir.join(&name)) else { continue };
            let mut day: Vec<Entry> = data
                .split(|c| *c == b'\n')
                .filter(|l| !l.is_empty())
                .filter_map(|l| serde_json::from_slice::<Entry>(l).ok())
                .filter(|e| q.matches(e))
                .collect();
            // Lines can arrive late (held in RAM), so order within the day.
            day.sort_by_key(|e| std::cmp::Reverse(e.t));
            out.extend(day);
            if out.len() >= limit {
                out.truncate(limit);
                return Ok(out);
            }
        }
        Ok(out)
    }

    /// Deletes days older than keep_days.
    pub fn maintain(&self, now: i64, keep_days: i64) {
        let _g = self.mu.lock().unwrap();
        let cut = utc_day(now - keep_days * 86400);
        if let Ok(rd) = std::fs::read_dir(&self.dir) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if day_of(&n).is_some_and(|d| d < cut.as_str()) {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_keeps_lines_until_acked() {
        let b = Buffer::new("n1", 3, 2);
        b.write_at(b"2026/11/16 10:00:00 link to vps DOWN: x\n2026/11/16 10:00:01 hel", 100);
        b.write_at(b"lo\nthree\nfour\n", 101);
        let s = b.snapshot();
        assert_eq!(s.pending.iter().map(|e| e.text.as_str()).collect::<Vec<_>>(), ["hello", "three", "four"]);
        assert_eq!(s.dropped, 1);
        assert_eq!(s.recent.len(), 2);
        let t = b.take(2);
        b.write_at(b"five\n", 102);
        b.ack(&t);
        assert_eq!(b.snapshot().pending.iter().map(|e| e.text.as_str()).collect::<Vec<_>>(), ["four", "five"]);
    }

    #[test]
    fn important_words() {
        assert!(important("link to vps DOWN: no handshake"));
        assert!(important("link to vps UP again after 3m"));
        assert!(important("warning: x"));
        assert!(!important("downloaded the thing"));
        assert!(!important("probe round"));
    }

    #[test]
    fn store_append_query_maintain() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::new(dir.path().join("events"));
        let day = 86400;
        s.append(&[
            Entry { t: 10 * day + 5, node: "a".into(), text: "old".into(), seq: 0 },
            Entry { t: 20 * day + 5, node: "a".into(), text: "link DOWN".into(), seq: 0 },
            Entry { t: 20 * day + 9, node: "b".into(), text: "later".into(), seq: 0 },
        ])
        .unwrap();
        let all = s.query(&Query::default()).unwrap();
        assert_eq!(all.iter().map(|e| e.text.as_str()).collect::<Vec<_>>(), ["later", "link DOWN", "old"]);
        let imp = s.query(&Query { important: true, ..Default::default() }).unwrap();
        assert_eq!(imp.len(), 1);
        let since = s.query(&Query { since: 20 * day, node: "b".into(), ..Default::default() }).unwrap();
        assert_eq!(since.len(), 1);
        s.maintain(25 * day, 7);
        assert_eq!(s.query(&Query::default()).unwrap().len(), 2);
        // Same line format as Go: {"t":...,"node":"...","text":"..."}
        let text = std::fs::read_to_string(dir.path().join("events/events-1970-01-21.jsonl")).unwrap();
        assert!(text.starts_with(r#"{"t":1728005,"node":"a","text":"link DOWN"}"#));
    }
}
