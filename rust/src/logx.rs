//! Go-style logging (package log): "2006/01/02 15:04:05 message" lines on
//! stderr in local time, copied to an extra sink (the event log buffer).

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

static STD_FLAGS: AtomicBool = AtomicBool::new(false);
type Sink = Arc<dyn Fn(&[u8]) + Send + Sync>;
static SINK: RwLock<Option<Sink>> = RwLock::new(None);

/// log.SetFlags(log.LstdFlags) when true, log.SetFlags(0) when false.
pub fn set_std_flags(on: bool) {
    STD_FLAGS.store(on, Ordering::Relaxed);
}

/// Also send every line to f (log.SetOutput(io.MultiWriter(os.Stderr, f))).
pub fn set_sink(f: Sink) {
    *SINK.write().unwrap() = Some(f);
}

pub fn output(msg: &str) {
    let mut line = String::with_capacity(msg.len() + 21);
    if STD_FLAGS.load(Ordering::Relaxed) {
        line.push_str(&local_stamp(crate::util::now_unix()));
        line.push(' ');
    }
    line.push_str(msg);
    if !line.ends_with('\n') {
        line.push('\n');
    }
    let _ = std::io::stderr().lock().write_all(line.as_bytes());
    if let Some(s) = SINK.read().unwrap().as_ref() {
        s(line.as_bytes());
    }
}

/// "2006/01/02 15:04:05" in local time.
pub fn local_stamp(unix: i64) -> String {
    let t = local(unix);
    format!("{:04}/{:02}/{:02} {:02}:{:02}:{:02}", t.0, t.1, t.2, t.3, t.4, t.5)
}

/// (year, month, day, hour, minute, second, utc offset seconds) in local time.
#[cfg(unix)]
pub fn local(unix: i64) -> (i32, u32, u32, u32, u32, u32, i64) {
    let t = unix as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: localtime_r only writes into tm.
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return utc(unix);
    }
    (tm.tm_year + 1900, tm.tm_mon as u32 + 1, tm.tm_mday as u32, tm.tm_hour as u32, tm.tm_min as u32, tm.tm_sec as u32, tm.tm_gmtoff as i64)
}

#[cfg(not(unix))]
pub fn local(unix: i64) -> (i32, u32, u32, u32, u32, u32, i64) {
    let off = time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| time::UtcOffset::local_offset_at(t).ok())
        .map(|o| o.whole_seconds() as i64)
        .unwrap_or(0);
    let mut t = utc(unix + off);
    t.6 = off;
    t
}

pub fn utc(unix: i64) -> (i32, u32, u32, u32, u32, u32, i64) {
    let d = time::OffsetDateTime::from_unix_timestamp(unix).unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    (d.year(), d.month() as u32, d.day() as u32, d.hour() as u32, d.minute() as u32, d.second() as u32, 0)
}

/// log.Printf.
#[macro_export]
macro_rules! logf {
    ($($t:tt)*) => { $crate::logx::output(&format!($($t)*)) };
}
