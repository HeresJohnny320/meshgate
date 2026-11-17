//! A general HTTP(S) client for URLs: redirects, public CA roots, size
//! limits. Used by the self-update (GitHub), the HTTP check and myip.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hyper::{HeaderMap, Method, StatusCode};

/// A parsed http(s) URL.
#[derive(Clone, Debug, PartialEq)]
pub struct Url {
    pub https: bool,
    pub host: String,
    pub port: u16,
    /// Path with query, starting with "/".
    pub path: String,
}

impl Url {
    pub fn parse(s: &str) -> Option<Url> {
        let (https, rest) = if let Some(r) = s.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = s.strip_prefix("http://") {
            (false, r)
        } else {
            let lower = s.to_ascii_lowercase();
            if lower.starts_with("https://") || lower.starts_with("http://") {
                return Url::parse(&format!("{}{}", &lower[..s.find("://")? + 3], &s[s.find("://")? + 3..]));
            }
            return None;
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..end];
        let mut path = rest[end..].split('#').next().unwrap_or("").to_string();
        if path.is_empty() || path.starts_with('?') {
            path.insert(0, '/');
        }
        let authority = authority.rsplit('@').next()?;
        let (host, port) = if let Some(r) = authority.strip_prefix('[') {
            let i = r.find(']')?;
            let port = r[i + 1..].strip_prefix(':').map(|p| p.parse().ok()).unwrap_or(Some(if https { 443 } else { 80 }))?;
            (r[..i].to_string(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) if !p.is_empty() => (h.to_string(), p.parse().ok()?),
                Some((h, _)) => (h.to_string(), if https { 443 } else { 80 }),
                None => (authority.to_string(), if https { 443 } else { 80 }),
            }
        };
        if host.is_empty() {
            return None;
        }
        Some(Url { https, host, port, path })
    }

    fn default_port(&self) -> bool {
        self.port == if self.https { 443 } else { 80 }
    }

    pub fn host_header(&self) -> String {
        let h = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.default_port() { h } else { format!("{h}:{}", self.port) }
    }

    pub fn addr(&self) -> String {
        crate::netx::join_host_port(&self.host, self.port)
    }

    /// Resolves a Location header against this URL.
    pub fn join(&self, loc: &str) -> Option<Url> {
        if loc.starts_with("http://") || loc.starts_with("https://") {
            return Url::parse(loc);
        }
        if let Some(r) = loc.strip_prefix("//") {
            return Url::parse(&format!("{}://{r}", if self.https { "https" } else { "http" }));
        }
        let mut u = self.clone();
        if loc.starts_with('/') {
            u.path = loc.to_string();
        } else {
            let base = self.path.split('?').next().unwrap_or("/");
            let dir = &base[..base.rfind('/').map(|i| i + 1).unwrap_or(1)];
            u.path = format!("{dir}{loc}");
        }
        Some(u)
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}{}", if self.https { "https" } else { "http" }, self.host_header(), self.path)
    }
}

/// TLS details of an HTTPS answer.
#[derive(Clone, Debug)]
pub struct TlsInfo {
    pub version: String,
    pub peer_cert: Vec<u8>,
}

#[derive(Debug)]
pub struct Response {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub url: Url,
    pub tls: Option<TlsInfo>,
}

impl Response {
    pub fn status_line(&self) -> String {
        format!("{} {}", self.status.as_u16(), self.status.canonical_reason().unwrap_or(""))
    }
    pub fn header(&self, k: &str) -> String {
        self.headers.get(k).and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
    }
}

pub struct Opts {
    pub method: Method,
    pub timeout: Duration,
    pub limit: usize,
    pub follow: bool,
    pub tls: Arc<rustls::ClientConfig>,
}

impl Default for Opts {
    fn default() -> Opts {
        Opts { method: Method::GET, timeout: Duration::from_secs(30), limit: 1 << 20, follow: true, tls: crate::tlsx::public() }
    }
}

/// One request (following up to 10 redirects when opts.follow).
pub async fn fetch(url: &str, opts: &Opts) -> Result<Response, String> {
    let mut u = Url::parse(url).ok_or_else(|| format!("parse \"{url}\": invalid URL"))?;
    let fut = async {
        for _ in 0..10 {
            let r = once(&u, opts).await?;
            if opts.follow
                && r.status.is_redirection()
                && let Some(next) = r.headers.get("location").and_then(|v| v.to_str().ok()).and_then(|l| u.join(l))
            {
                u = next;
                continue;
            }
            return Ok(r);
        }
        Err("stopped after 10 redirects".to_string())
    };
    match tokio::time::timeout(opts.timeout, fut).await {
        Ok(r) => r.map_err(|e| format!("Get \"{url}\": {e}")),
        Err(_) => Err(format!("Get \"{url}\": context deadline exceeded (Client.Timeout exceeded)")),
    }
}

async fn once(u: &Url, opts: &Opts) -> Result<Response, String> {
    let c = crate::http::dial(&u.addr(), opts.timeout).await?;
    let host = u.host_header();
    let hdrs = [("User-Agent", "meshgate"), ("Accept-Encoding", "identity")];
    let (res, tls) = if u.https {
        let name = rustls_pki_types::ServerName::try_from(u.host.clone()).map_err(|e| e.to_string())?;
        let s = tokio_rustls::TlsConnector::from(opts.tls.clone()).connect(name, c).await.map_err(|e| e.to_string())?;
        let info = {
            let (_, conn) = s.get_ref();
            TlsInfo {
                version: match conn.protocol_version() {
                    Some(rustls::ProtocolVersion::TLSv1_3) => "TLS 1.3".into(),
                    Some(rustls::ProtocolVersion::TLSv1_2) => "TLS 1.2".into(),
                    Some(v) => format!("{v:?}"),
                    None => String::new(),
                },
                peer_cert: conn.peer_certificates().and_then(|c| c.first()).map(|c| c.to_vec()).unwrap_or_default(),
            }
        };
        (crate::http::request_on(s, opts.method.clone(), &host, &u.path, &hdrs, Bytes::new(), opts.limit).await?, Some(info))
    } else {
        (crate::http::request_on(c, opts.method.clone(), &host, &u.path, &hdrs, Bytes::new(), opts.limit).await?, None)
    };
    Ok(Response { status: res.status, headers: res.headers, body: res.body, url: u.clone(), tls })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = Url::parse("https://github.com/a/b?x=1").unwrap();
        assert_eq!((u.https, u.host.as_str(), u.port, u.path.as_str()), (true, "github.com", 443, "/a/b?x=1"));
        assert_eq!(u.to_string(), "https://github.com/a/b?x=1");
        let v = Url::parse("http://[::1]:8080").unwrap();
        assert_eq!((v.host.as_str(), v.port, v.path.as_str()), ("::1", 8080, "/"));
        assert_eq!(u.join("/c").unwrap().to_string(), "https://github.com/c");
        assert_eq!(u.join("https://objects.example/z").unwrap().host, "objects.example");
        assert_eq!(u.join("d").unwrap().path, "/a/d");
        assert!(Url::parse("ftp://x").is_none());
    }
}
