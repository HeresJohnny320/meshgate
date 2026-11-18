//! Installs new meshgate releases from GitHub (Go: internal/update): find
//! the latest tag, download this platform's file, verify it against the
//! release's SHA256SUMS and swap it in for the running binary. The service
//! manager starts the new version once the old process exits (code 3).

use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use hyper::Method;
use sha2::{Digest, Sha256};

use crate::httpc::{self, Opts};

/// The GitHub repository; MESHGATE_UPDATE_URL overrides it (tests).
pub fn base_url() -> String {
    static B: OnceLock<String> = OnceLock::new();
    B.get_or_init(|| match std::env::var("MESHGATE_UPDATE_URL") {
        Ok(u) if !u.is_empty() => u.trim_end_matches('/').to_string(),
        _ => "https://github.com/heresjohnny320/meshgate".into(),
    })
    .clone()
}

#[cfg(test)]
thread_local! {
    static TEST_BASE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

fn base() -> String {
    #[cfg(test)]
    if let Some(b) = TEST_BASE.with(|b| b.borrow().clone()) {
        return b;
    }
    base_url()
}

/// The newest release tag (e.g. "v0.2.9"), from the redirect of
/// /releases/latest (no API rate limit).
pub async fn latest() -> Result<String, String> {
    let opts = Opts { method: Method::HEAD, timeout: Duration::from_secs(20), follow: false, limit: 1 << 16, ..Default::default() };
    let res = httpc::fetch(&format!("{}/releases/latest", base()), &opts).await?;
    let loc = res.header("location");
    let Some(i) = loc.rfind("/tag/") else {
        return Err(format!("no release found ({})", res.status_line()));
    };
    let tag = &loc[i + 5..];
    if parse(tag).is_none() {
        return Err(format!("unexpected release tag {tag:?}"));
    }
    Ok(tag.to_string())
}

/// Whether latest is newer than current. Development builds never count as
/// older (MESHGATE_UPDATE_DEV=1 allows it, for tests).
pub fn newer(current: &str, latest: &str) -> bool {
    let (c, l) = (parse(current), parse(latest));
    if c.is_none() && l.is_some() && std::env::var("MESHGATE_UPDATE_DEV").as_deref() == Ok("1") {
        return true;
    }
    match (c, l) {
        (Some(c), Some(l)) => l > c,
        _ => false,
    }
}

fn parse(v: &str) -> Option<[i64; 3]> {
    let parts: Vec<&str> = v.strip_prefix('v').unwrap_or(v).split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let mut out = [0i64; 3];
    for (i, p) in parts.iter().enumerate() {
        out[i] = crate::gojson::atoi(p).filter(|n| *n >= 0)?;
    }
    Some(out)
}

/// Go's GOOS/GOARCH names for this build.
pub fn goos() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "freebsd") {
        "freebsd"
    } else if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "unknown"
    }
}

pub fn goarch() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "amd64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "arm") {
        "arm"
    } else if cfg!(target_arch = "x86") {
        "386"
    } else {
        "unknown"
    }
}

/// The release file for this platform.
pub fn asset() -> String {
    if cfg!(windows) { format!("meshgate-windows-{}.zip", goarch()) } else { format!("meshgate-{}-{}", goos(), goarch()) }
}

async fn get(url: &str, limit: usize) -> Result<Vec<u8>, String> {
    let opts = Opts { timeout: Duration::from_secs(300), limit, ..Default::default() };
    let res = httpc::fetch(url, &opts).await?;
    if res.status != hyper::StatusCode::OK {
        return Err(format!("download {url}: {}", res.status_line()));
    }
    Ok(res.body.to_vec())
}

/// Downloads a release file and checks it against SHA256SUMS.
pub async fn fetch(tag: &str, name: &str) -> Result<Vec<u8>, String> {
    let b = format!("{}/releases/download/{tag}/", base());
    let body = get(&format!("{b}{name}"), 512 << 20).await?;
    let sums = get(&format!("{b}SHA256SUMS"), 1 << 20).await.map_err(|e| format!("checksums: {e}"))?;
    let mut want = String::new();
    for l in String::from_utf8_lossy(&sums).lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() == 2 && f[1].trim_start_matches('*') == name {
            want = f[0].to_string();
        }
    }
    if want.is_empty() || want != hex::encode(Sha256::digest(&body)) {
        return Err(format!("checksum mismatch for {name}: refusing to install"));
    }
    Ok(body)
}

/// Replaces the running binary (exe) with release tag.
pub async fn install(tag: &str, exe: &Path) -> Result<(), String> {
    let data = fetch(tag, &asset()).await?;
    let dir = exe.parent().unwrap_or(Path::new("."));
    let files: Vec<(String, Vec<u8>)> = if cfg!(windows) {
        unzip(&data)?
    } else {
        vec![(exe.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "meshgate".into()), data)]
    };
    for (name, b) in files {
        replace(&dir.join(name), &b)?;
    }
    Ok(())
}

/// Writes path atomically. A running file cannot be overwritten on Windows,
/// but it can be renamed away first (kept as .old).
fn replace(path: &Path, b: &[u8]) -> Result<(), String> {
    let tmp = std::path::PathBuf::from(format!("{}.new", path.display()));
    crate::config::write_mode(&tmp, b, 0o755).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
    }
    if cfg!(windows) {
        let old = format!("{}.old", path.display());
        let _ = std::fs::remove_file(&old);
        if let Err(e) = std::fs::rename(path, &old)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.to_string());
        }
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        e.to_string()
    })
}

/// The files of the Windows zip that belong next to meshgate.exe.
fn unzip(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    use std::io::Read;
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(data)).map_err(|e| e.to_string())?;
    let mut out = vec![];
    for i in 0..z.len() {
        let mut f = z.by_index(i).map_err(|e| e.to_string())?;
        let name = Path::new(f.name()).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if !matches!(name.as_str(), "meshgate.exe" | "wintun.dll" | "wireguard.dll") {
            continue;
        }
        let mut b = vec![];
        f.by_ref().take(256 << 20).read_to_end(&mut b).map_err(|e| e.to_string())?;
        out.push((name, b));
    }
    if !out.iter().any(|(n, _)| n == "meshgate.exe") {
        return Err("release zip has no meshgate.exe".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    async fn fake_release(tag: &'static str, files: HashMap<String, Vec<u8>>, tamper: bool) -> String {
        let mut sums = String::new();
        for (name, b) in &files {
            let mut h = Sha256::digest(b).to_vec();
            if tamper {
                h[0] ^= 1;
            }
            sums += &format!("{}  {name}\n", hex::encode(h));
        }
        let files = Arc::new(files);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let h: Arc<dyn crate::http::Handler> = Arc::new(move |r: crate::http::Req, _p: crate::http::Peer| {
            let (files, sums) = (files.clone(), sums.clone());
            async move {
                let path = r.uri().path().to_string();
                if path == "/releases/latest" {
                    let mut res = crate::http::status(hyper::StatusCode::FOUND);
                    res.headers_mut().insert("Location", format!("/releases/tag/{tag}").parse().unwrap());
                    return res;
                }
                let name = path.rsplit('/').next().unwrap_or("");
                if name == "SHA256SUMS" {
                    return crate::http::resp(hyper::StatusCode::OK, "", sums);
                }
                match files.get(name) {
                    Some(b) => crate::http::resp(hyper::StatusCode::OK, "", b.clone()),
                    None => crate::http::not_found(),
                }
            }
        });
        tokio::spawn(crate::http::serve(l, None, h));
        url
    }

    #[test]
    fn newer_versions() {
        for (cur, latest, want) in [
            ("v0.2.3", "v0.2.4", true),
            ("v0.2.9", "v0.2.10", true),
            ("v0.3.0", "v0.2.10", false),
            ("v1.0.0", "v1.0.0", false),
            ("dev", "v9.9.9", false),
            ("67e3410", "v0.2.4", false),
        ] {
            assert_eq!(newer(cur, latest), want, "{cur} {latest}");
        }
    }

    #[tokio::test]
    async fn installs_and_refuses_tampered() {
        // On Windows the release file is a zip with meshgate.exe and wintun.dll.
        let body = if cfg!(windows) {
            use std::io::Write;
            let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            for (name, b) in [("meshgate.exe", "new binary"), ("wintun.dll", "driver")] {
                z.start_file(name, zip::write::SimpleFileOptions::default()).unwrap();
                z.write_all(b.as_bytes()).unwrap();
            }
            z.finish().unwrap().into_inner()
        } else {
            b"new binary".to_vec()
        };
        for tamper in [false, true] {
            let url = fake_release("v0.9.1", HashMap::from([(asset(), body.clone())]), tamper).await;
            TEST_BASE.with(|b| *b.borrow_mut() = Some(url));
            assert_eq!(latest().await.unwrap(), "v0.9.1");
            let dir = tempfile::tempdir().unwrap();
            let exe = dir.path().join(if cfg!(windows) { "meshgate.exe" } else { "meshgate" });
            std::fs::write(&exe, "old binary").unwrap();
            let r = install("v0.9.1", &exe).await;
            let now = std::fs::read_to_string(&exe).unwrap();
            if tamper {
                assert!(r.is_err() && now == "old binary", "installed a tampered download");
            } else {
                assert!(r.is_ok() && now == "new binary", "{r:?}");
            }
        }
    }
}
