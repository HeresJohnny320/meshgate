//! Traffic history (Go: internal/history). Every server accumulates exact
//! bytes and peak speeds per series in RAM and hands one point per interval
//! to the log server, which appends them to one binary file per UTC day
//! (YYYY-MM-DD.dat, gzipped once past). The file format is shared with Go:
//!
//!   u32le T | u8 key length | key | uvarint bytes in | uvarint bytes out |
//!   f32le peak in | f32le peak out
//!
//! (.bin files are v0.2.17's: four f32 average/peak speeds instead.)

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

/// The resolution of stored points in seconds (MESHGATE_HISTORY_INTERVAL
/// shortens it for tests, e.g. "20s").
pub fn interval() -> i64 {
    static I: OnceLock<i64> = OnceLock::new();
    *I.get_or_init(|| std::env::var("MESHGATE_HISTORY_INTERVAL").ok().and_then(|v| parse_duration(&v)).filter(|d| *d >= 1).unwrap_or(300))
}

/// Go's time.ParseDuration for whole seconds ("20s", "5m", "1h30m").
pub fn parse_duration(s: &str) -> Option<i64> {
    let mut total = 0f64;
    let mut num = String::new();
    let mut chars = s.chars().peekable();
    let mut any = false;
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() || c == '.' {
            num.push(c);
            continue;
        }
        let mut unit = c.to_string();
        if c == 'm' && chars.peek() == Some(&'s') {
            unit.push(chars.next().unwrap());
        }
        let v: f64 = num.parse().ok()?;
        num.clear();
        total += v * match unit.as_str() {
            "h" => 3600.0,
            "m" => 60.0,
            "s" => 1.0,
            "ms" => 0.001,
            _ => return None,
        };
        any = true;
    }
    (any && num.is_empty()).then_some(total as i64)
}

/// One series over one interval.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Point {
    pub t: i64,
    #[serde(rename = "k")]
    pub key: String,
    #[serde(rename = "bi")]
    pub in_: u64,
    #[serde(rename = "bo")]
    pub out: u64,
    #[serde(rename = "pi")]
    pub peak_in: f32,
    #[serde(rename = "po")]
    pub peak_out: f32,
}

impl<'de> Deserialize<'de> for Point {
    /// Also takes points from v0.2.17 servers (average speeds "ai"/"ao").
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Point, D::Error> {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Raw {
            t: i64,
            k: String,
            bi: u64,
            bo: u64,
            pi: f32,
            po: f32,
            ai: f64,
            ao: f64,
        }
        let r = Raw::deserialize(d)?;
        let mut p = Point { t: r.t, key: r.k, in_: r.bi, out: r.bo, peak_in: r.pi, peak_out: r.po };
        if p.in_ == 0 && p.out == 0 && (r.ai > 0.0 || r.ao > 0.0) {
            p.in_ = (r.ai * interval() as f64) as u64;
            p.out = (r.ao * interval() as f64) as u64;
        }
        Ok(p)
    }
}

#[derive(Default)]
struct Acc {
    in_: u64,
    out: u64,
    peak_in: f64,
    peak_out: f64,
}

/// Turns counter readings into points.
/// Per series: what this interval added up, and the last counter readings.
type AccState = (HashMap<String, Acc>, HashMap<String, [u64; 2]>);

#[derive(Default)]
pub struct Accumulator {
    st: Mutex<AccState>,
}

/// What a counter added; a counter that went down was reset.
fn grown(prev: u64, now: u64) -> u64 {
    if now >= prev { now - prev } else { now }
}

impl Accumulator {
    /// Records a series' counters and current speeds.
    pub fn sample(&self, key: &str, total_in: u64, total_out: u64, rate_in: f64, rate_out: f64) {
        let mut g = self.st.lock().unwrap();
        let (m, last) = &mut *g;
        let s = m.entry(key.to_string()).or_default();
        if let Some(prev) = last.get(key) {
            s.in_ += grown(prev[0], total_in);
            s.out += grown(prev[1], total_out);
        }
        last.insert(key.to_string(), [total_in, total_out]);
        s.peak_in = s.peak_in.max(rate_in);
        s.peak_out = s.peak_out.max(rate_out);
    }

    /// The points of the interval starting at t; starts over.
    pub fn flush(&self, t: i64) -> Vec<Point> {
        let mut g = self.st.lock().unwrap();
        let m = std::mem::take(&mut g.0);
        let mut out: Vec<Point> = m
            .into_iter()
            .filter(|(_, s)| !(s.in_ == 0 && s.out == 0 && s.peak_in == 0.0 && s.peak_out == 0.0))
            .map(|(k, s)| Point { t, key: k, in_: s.in_, out: s.out, peak_in: s.peak_in as f32, peak_out: s.peak_out as f32 })
            .collect();
        out.sort_by(|a, b| a.key.cmp(&b.key));
        out
    }
}

/// Describes a series ("kind", "name", "port", ...).
pub type Label = BTreeMap<String, String>;

const LABELS_FILE: &str = "labels.json";

pub struct Store {
    pub dir: PathBuf,
    st: Mutex<Option<BTreeMap<String, Label>>>,
}

fn day(t: i64) -> String {
    crate::events::utc_day(t)
}

fn put_uvarint(w: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        w.push((v as u8) | 0x80);
        v >>= 7;
    }
    w.push(v as u8);
}

fn encode(w: &mut Vec<u8>, p: &Point) {
    w.extend_from_slice(&(p.t as u32).to_le_bytes());
    w.push(p.key.len() as u8);
    w.extend_from_slice(p.key.as_bytes());
    put_uvarint(w, p.in_);
    put_uvarint(w, p.out);
    w.extend_from_slice(&p.peak_in.to_le_bytes());
    w.extend_from_slice(&p.peak_out.to_le_bytes());
}

fn read_n<const N: usize>(r: &mut dyn BufRead) -> Option<[u8; N]> {
    let mut b = [0u8; N];
    r.read_exact(&mut b).ok()?;
    Some(b)
}

fn read_uvarint(r: &mut dyn BufRead) -> Option<u64> {
    let (mut x, mut s) = (0u64, 0u32);
    for i in 0..10 {
        let [b] = read_n::<1>(r)?;
        if b < 0x80 {
            if i == 9 && b > 1 {
                return None;
            }
            return Some(x | (b as u64) << s);
        }
        x |= ((b & 0x7f) as u64) << s;
        s += 7;
    }
    None
}

fn decode_head(r: &mut dyn BufRead) -> Option<Point> {
    let t = u32::from_le_bytes(read_n::<4>(r)?) as i64;
    let [n] = read_n::<1>(r)?;
    let mut key = vec![0u8; n as usize];
    r.read_exact(&mut key).ok()?;
    Some(Point { t, key: String::from_utf8_lossy(&key).into_owned(), ..Default::default() })
}

fn f32le(r: &mut dyn BufRead) -> Option<f32> {
    Some(f32::from_le_bytes(read_n::<4>(r)?))
}

fn decode(r: &mut dyn BufRead) -> Option<Point> {
    let mut p = decode_head(r)?;
    p.in_ = read_uvarint(r)?;
    p.out = read_uvarint(r)?;
    p.peak_in = f32le(r)?;
    p.peak_out = f32le(r)?;
    Some(p)
}

/// A v0.2.17 record (average and peak speeds) as bytes.
fn decode_v1(r: &mut dyn BufRead) -> Option<Point> {
    let mut p = decode_head(r)?;
    let (ai, ao) = (f32le(r)?, f32le(r)?);
    p.in_ = (ai as f64 * interval() as f64) as u64;
    p.out = (ao as f64 * interval() as f64) as u64;
    p.peak_in = f32le(r)?;
    p.peak_out = f32le(r)?;
    Some(p)
}

type Decoder = fn(&mut dyn BufRead) -> Option<Point>;

/// `^[0-9]{4}-[0-9]{2}-[0-9]{2}\.(bin|dat)(\.gz)?$`
fn day_file(name: &str) -> bool {
    let b = name.as_bytes();
    if b.len() < 14 || !(b[4] == b'-' && b[7] == b'-' && b[10] == b'.') {
        return false;
    }
    if !b[..10].iter().enumerate().all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit()) {
        return false;
    }
    matches!(&name[11..], "bin" | "dat" | "bin.gz" | "dat.gz")
}

fn valid_name(name: &str) -> bool {
    name == LABELS_FILE || day_file(name)
}

/// [start, bytes in, bytes out, peak in, peak out]
pub type Bucket = [f64; 5];

/// The ranges the UIs offer: (span, step) in seconds.
pub fn range(name: &str) -> Option<(i64, i64)> {
    Some(match name {
        "6h" => (6 * 3600, 300),
        "1d" => (86400, 900),
        "1w" => (7 * 86400, 7200),
        "1m" => (30 * 86400, 8 * 3600),
        "1y" => (365 * 86400, 86400),
        _ => return None,
    })
}

impl Store {
    pub fn new(dir: PathBuf) -> Store {
        Store { dir, st: Mutex::new(None) }
    }

    fn mkdir(&self) -> Result<(), String> {
        crate::config::secure_dir(&self.dir).map_err(|e| e.to_string())
    }

    /// Adds points to their days' files.
    pub fn append(&self, points: &[Point]) -> Result<(), String> {
        let _g = self.st.lock().unwrap();
        self.append0(points)
    }

    fn append0(&self, points: &[Point]) -> Result<(), String> {
        self.mkdir()?;
        let mut by_day: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for p in points {
            if p.key.is_empty() || p.key.len() > 255 {
                continue;
            }
            encode(by_day.entry(day(p.t)).or_default(), p);
        }
        for (d, b) in by_day {
            let mut o = std::fs::OpenOptions::new();
            o.create(true).append(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
            o.open(self.dir.join(format!("{d}.dat"))).and_then(|mut f| f.write_all(&b)).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Compresses past days and deletes days older than keep_days.
    pub fn maintain(&self, now: i64, keep_days: i64) -> Result<(), String> {
        let _g = self.st.lock().unwrap();
        let today = day(now);
        let oldest = day(now - keep_days * 86400);
        let Ok(rd) = std::fs::read_dir(&self.dir) else { return Ok(()) };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !day_file(&name) {
                continue;
            }
            let d = &name[..10];
            if d < oldest.as_str() {
                let _ = std::fs::remove_file(e.path());
            } else if !name.ends_with(".gz") && d < today.as_str() {
                gzip_file(&e.path())?;
            }
        }
        Ok(())
    }

    /// The stored files (labels first, then days).
    pub fn files(&self) -> Vec<String> {
        let _g = self.st.lock().unwrap();
        let mut names: Vec<String> = std::fs::read_dir(&self.dir)
            .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
            .unwrap_or_default();
        names.sort();
        let mut out: Vec<String> = names.iter().filter(|n| day_file(n)).cloned().collect();
        if names.iter().any(|n| n == LABELS_FILE) {
            out.insert(0, LABELS_FILE.into());
        }
        out
    }

    pub fn export(&self, name: &str) -> Result<Vec<u8>, String> {
        if !valid_name(name) {
            return Err("bad file name".into());
        }
        let _g = self.st.lock().unwrap();
        std::fs::read(self.dir.join(name)).map_err(|e| e.to_string())
    }

    pub fn remove(&self, name: &str) -> Result<(), String> {
        if !valid_name(name) {
            return Err("bad file name".into());
        }
        let mut g = self.st.lock().unwrap();
        if name == LABELS_FILE {
            *g = None;
        }
        std::fs::remove_file(self.dir.join(name)).map_err(|e| e.to_string())
    }

    /// Adds a file from another log server (merged with what is here).
    pub fn import(&self, name: &str, data: &[u8]) -> Result<usize, String> {
        if !valid_name(name) {
            return Err("bad file name".into());
        }
        if name == LABELS_FILE {
            let l: BTreeMap<String, Label> = serde_json::from_slice(data).map_err(|e| e.to_string())?;
            let n = l.len();
            return self.set_labels(l, false).map(|_| n);
        }
        let mut raw: Box<dyn Read> = Box::new(data);
        if name.ends_with(".gz") {
            raw = Box::new(flate2::read::MultiGzDecoder::new(data));
        }
        let dec: Decoder = if name.contains(".bin") { decode_v1 } else { decode };
        let mut br = BufReader::new(raw);
        let mut pts = vec![];
        while let Some(p) = dec(&mut br) {
            pts.push(p);
        }
        let n = pts.len();
        self.append(&pts).map(|_| n)
    }

    fn load_labels(g: &mut Option<BTreeMap<String, Label>>, dir: &std::path::Path) {
        if g.is_none() {
            *g = Some(std::fs::read(dir.join(LABELS_FILE)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default());
        }
    }

    pub fn labels(&self) -> BTreeMap<String, Label> {
        let mut g = self.st.lock().unwrap();
        Self::load_labels(&mut g, &self.dir);
        g.clone().unwrap_or_default()
    }

    /// Records series descriptions. With replace a changed description wins;
    /// otherwise only unknown series are added.
    pub fn set_labels(&self, l: BTreeMap<String, Label>, replace: bool) -> Result<(), String> {
        let mut g = self.st.lock().unwrap();
        Self::load_labels(&mut g, &self.dir);
        let labels = g.as_mut().unwrap();
        let mut changed = false;
        for (k, v) in l {
            if k.is_empty() || k.len() > 255 || v.is_empty() || v.len() > 16 {
                continue;
            }
            if let Some(old) = labels.get(&k)
                && (!replace || *old == v)
            {
                continue;
            }
            labels.insert(k, v);
            changed = true;
        }
        if !changed {
            return Ok(());
        }
        self.mkdir()?;
        let b = crate::gojson::marshal(labels);
        let tmp = self.dir.join(format!("{LABELS_FILE}.tmp"));
        crate::config::write_private(&tmp, &b).map_err(|e| e.to_string())?;
        std::fs::rename(tmp, self.dir.join(LABELS_FILE)).map_err(|e| e.to_string())
    }

    /// The series between from and to, grouped into steps.
    pub fn query(&self, from: i64, to: i64, step: i64) -> Result<BTreeMap<String, Vec<Bucket>>, String> {
        let _g = self.st.lock().unwrap();
        let mut sums: HashMap<String, BTreeMap<i64, Bucket>> = HashMap::new();
        let mut d = from - from.rem_euclid(86400);
        while d <= to {
            for (mut r, dec) in day_readers(&self.dir.join(day(d))) {
                while let Some(p) = dec(&mut *r) {
                    if p.t < from || p.t >= to {
                        continue;
                    }
                    let start = from + (p.t - from) / step * step;
                    let b = sums.entry(p.key).or_default().entry(start).or_insert([start as f64, 0.0, 0.0, 0.0, 0.0]);
                    b[1] += p.in_ as f64;
                    b[2] += p.out as f64;
                    b[3] = b[3].max(p.peak_in as f64);
                    b[4] = b[4].max(p.peak_out as f64);
                }
            }
            d += 86400;
        }
        Ok(sums.into_iter().map(|(k, m)| (k, m.into_values().collect())).collect())
    }
}

/// Every file of a day: compressed and not, current format and v0.2.17's.
fn day_readers(base: &std::path::Path) -> Vec<(Box<dyn BufRead>, Decoder)> {
    let mut out: Vec<(Box<dyn BufRead>, Decoder)> = vec![];
    for (ext, dec) in [(".dat", decode as Decoder), (".bin", decode_v1 as Decoder)] {
        let p = base.as_os_str().to_string_lossy().into_owned() + ext;
        if let Ok(f) = std::fs::File::open(format!("{p}.gz")) {
            out.push((Box::new(BufReader::new(flate2::read::MultiGzDecoder::new(f))), dec));
        }
        if let Ok(f) = std::fs::File::open(&p) {
            out.push((Box::new(BufReader::new(f)), dec));
        }
    }
    out
}

/// Compresses a day into its .gz, after what the .gz already holds (gzip
/// members concatenate).
fn gzip_file(path: &std::path::Path) -> Result<(), String> {
    let input = std::fs::read(path).map_err(|e| e.to_string())?;
    let gz = PathBuf::from(format!("{}.gz", path.display()));
    let old = match std::fs::read(&gz) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => vec![],
        Err(e) => return Err(e.to_string()),
    };
    let mut enc = flate2::write::GzEncoder::new(old, flate2::Compression::best());
    enc.write_all(&input).map_err(|e| e.to_string())?;
    let out = enc.finish().map_err(|e| e.to_string())?;
    let tmp = PathBuf::from(format!("{}.gz.tmp", path.display()));
    crate::config::write_private(&tmp, &out).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &gz).map_err(|e| e.to_string())?;
    std::fs::remove_file(path).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulator_counts_growth_and_resets() {
        let a = Accumulator::default();
        a.sample("f:1", 1000, 50, 10.0, 1.0);
        a.sample("f:1", 3000, 80, 400.0, 2.0);
        a.sample("f:1", 500, 90, 5.0, 3.0); // counter reset
        a.sample("idle", 7, 7, 0.0, 0.0);
        let p = a.flush(600);
        assert_eq!(p.len(), 1);
        assert_eq!((p[0].in_, p[0].out, p[0].peak_in), (2500, 40, 400.0));
        assert!(a.flush(900).is_empty());
    }

    #[test]
    fn store_roundtrip_gzip_import_and_query() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::new(dir.path().join("history"));
        let d0 = 19_000 * 86400;
        let pts = vec![
            Point { t: d0 + 300, key: "f:1".into(), in_: 1 << 40, out: 5, peak_in: 1.5, peak_out: 2.0 },
            Point { t: d0 + 900, key: "f:1".into(), in_: 10, out: 20, peak_in: 9.0, peak_out: 1.0 },
            Point { t: d0 + 86400 + 60, key: "d:a@b".into(), in_: 1, out: 2, peak_in: 0.5, peak_out: 0.5 },
        ];
        s.append(&pts).unwrap();
        s.maintain(d0 + 86400 + 100, 365).unwrap();
        let files = s.files();
        assert!(files.iter().any(|f| f.ends_with(".dat.gz")), "{files:?}");
        let q = s.query(d0, d0 + 2 * 86400, 3600).unwrap();
        let f = &q["f:1"];
        assert_eq!(f.len(), 1);
        assert_eq!(f[0], [d0 as f64, (1u64 << 40) as f64 + 10.0, 25.0, 9.0, 2.0]);
        assert_eq!(q["d:a@b"].len(), 1);

        // Moving the gz to another store keeps every point.
        let s2 = Store::new(dir.path().join("h2"));
        let name = files.iter().find(|f| f.ends_with(".gz")).unwrap();
        assert_eq!(s2.import(name, &s.export(name).unwrap()).unwrap(), 2);
        s.set_labels(BTreeMap::from([("f:1".to_string(), Label::from([("kind".to_string(), "forward".to_string())]))]), true).unwrap();
        assert_eq!(s.labels()["f:1"]["kind"], "forward");
        assert!(s.files()[0] == "labels.json");
    }

    #[test]
    fn point_json_like_go() {
        let p = Point { t: 1, key: "f:x".into(), in_: 2, out: 3, peak_in: 0.5, peak_out: 0.0 };
        assert_eq!(serde_json::to_string(&p).unwrap(), r#"{"t":1,"k":"f:x","bi":2,"bo":3,"pi":0.5,"po":0.0}"#);
        let old: Point = serde_json::from_str(r#"{"t":1,"k":"x","ai":2}"#).unwrap();
        assert_eq!(old.in_, 2 * interval() as u64);
        assert_eq!(parse_duration("20s"), Some(20));
        assert_eq!(parse_duration("1h30m"), Some(5400));
    }
}

#[cfg(test)]
mod golden {
    use super::*;

    /// The Go build's day file decodes to the same points, and encoding
    /// those points gives the same bytes.
    #[test]
    fn same_bytes_as_go() {
        let file = include_bytes!("../testdata/history/2022-01-01.dat");
        let pts: Vec<Point> = serde_json::from_str(include_str!("../testdata/history/points.json")).unwrap();
        let mut r: &[u8] = file;
        let mut got = vec![];
        while let Some(p) = decode(&mut r) {
            got.push(p);
        }
        assert_eq!(got, pts);
        let mut b = vec![];
        for p in &pts {
            encode(&mut b, p);
        }
        assert_eq!(b, file.to_vec());
    }
}
