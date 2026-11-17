//! Small shared helpers: time, randomness.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

pub fn now_unix() -> i64 {
    now_ms() / 1000
}

/// Fills a buffer from the OS random source.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("os random source");
    b
}

/// A uniformly random number in [0, n).
pub fn random_below(n: u64) -> u64 {
    assert!(n > 0);
    let zone = u64::MAX - (u64::MAX % n);
    loop {
        let v = u64::from_le_bytes(random_bytes::<8>());
        if v < zone {
            return v % n;
        }
    }
}

/// Monotonic nanoseconds, never 0 (0 means "never" in path selection).
pub fn mono_ns() -> i64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    let start = *START.get_or_init(Instant::now);
    // Offset so that "never" (0) is older than any freshness window.
    start.elapsed().as_nanos() as i64 + (1 << 40)
}

/// Output of a finished command (exec.Cmd.CombinedOutput).
pub struct CmdOut {
    pub ok: bool,
    /// Go's error text: "exit status N", "signal: killed" or the spawn error.
    pub err: String,
    pub out: String,
}

/// Runs a program with optional stdin and returns its combined output.
pub fn run(prog: &str, args: &[&str], stdin: Option<&str>) -> CmdOut {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut c = Command::new(prog);
    c.args(args).stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = match c.spawn() {
        Ok(ch) => ch,
        Err(e) => {
            let err = if e.kind() == std::io::ErrorKind::NotFound {
                format!("exec: \"{prog}\": executable file not found in $PATH")
            } else {
                e.to_string()
            };
            return CmdOut { ok: false, err, out: String::new() };
        }
    };
    if let (Some(s), Some(mut w)) = (stdin, child.stdin.take()) {
        let s = s.to_string();
        std::thread::spawn(move || {
            let _ = w.write_all(s.as_bytes());
        });
    }
    let o = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => return CmdOut { ok: false, err: e.to_string(), out: String::new() },
    };
    let mut out = String::from_utf8_lossy(&o.stdout).into_owned();
    out.push_str(&String::from_utf8_lossy(&o.stderr));
    CmdOut { ok: o.status.success(), err: exit_text(&o.status), out }
}

/// Runs a program and returns only its stdout when it succeeds (cmd.Output).
pub fn output(prog: &str, args: &[&str]) -> Option<String> {
    let o =
        std::process::Command::new(prog).args(args).stdin(std::process::Stdio::null()).stderr(std::process::Stdio::null()).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

fn exit_text(st: &std::process::ExitStatus) -> String {
    if let Some(c) = st.code() {
        return format!("exit status {c}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(s) = st.signal() {
            return format!("signal: {}", signal_name(s));
        }
    }
    "exit status unknown".into()
}

#[cfg(unix)]
fn signal_name(s: i32) -> &'static str {
    match s {
        libc::SIGKILL => "killed",
        libc::SIGTERM => "terminated",
        libc::SIGINT => "interrupt",
        libc::SIGSEGV => "segmentation fault",
        libc::SIGABRT => "aborted",
        _ => "signal",
    }
}

/// Whether a program is on PATH (exec.LookPath).
pub fn look_path(prog: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else { return false };
    std::env::split_paths(&path).any(|d| {
        let p = d.join(prog);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(&p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        }
        #[cfg(not(unix))]
        {
            p.is_file() || p.with_extension("exe").is_file()
        }
    })
}

/// Go's time.Time JSON encoding (RFC 3339 with nanoseconds, local zone;
/// the zero time for (0, 0)).
pub fn go_time(sec: i64, nsec: i64) -> String {
    if sec == 0 && nsec == 0 {
        return "0001-01-01T00:00:00Z".into();
    }
    let (y, mo, d, h, mi, s, off) = crate::logx::local(sec);
    let mut out = format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}");
    if nsec > 0 {
        let frac = format!("{nsec:09}");
        out.push('.');
        out.push_str(frac.trim_end_matches('0'));
    }
    if off == 0 {
        out.push('Z');
    } else {
        let sign = if off < 0 { '-' } else { '+' };
        let a = off.abs();
        out.push_str(&format!("{sign}{:02}:{:02}", a / 3600, (a % 3600) / 60));
    }
    out
}

/// Parses Go's time.Time JSON form back to unix seconds and nanoseconds.
pub fn parse_go_time(s: &str) -> Option<(i64, i64)> {
    if s.starts_with("0001-01-01T00:00:00") {
        return Some((0, 0));
    }
    let t = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()?;
    Some((t.unix_timestamp(), t.nanosecond() as i64))
}

pub fn ser_go_time<S: serde::Serializer>(t: &(i64, i64), s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&go_time(t.0, t.1))
}

pub fn de_go_time<'de, D: serde::Deserializer<'de>>(d: D) -> Result<(i64, i64), D::Error> {
    let s: Option<String> = serde::Deserialize::deserialize(d)?;
    Ok(s.and_then(|s| parse_go_time(&s)).unwrap_or((0, 0)))
}
