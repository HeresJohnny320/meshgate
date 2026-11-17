//! The HTTPS edge (Go: internal/proxy): terminates TLS for configured
//! hostnames with automatic Let's Encrypt certificates (HTTP-01) and
//! reverse-proxies requests through the mesh. Certificates live where the
//! Go build's certmagic kept them, so existing ones are reused.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::StatusCode;
use hyper::body::{Frame, Incoming};
use hyper::header::{HeaderMap, HeaderValue};
use hyper_util::rt::TokioIo;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::http::{self, Body, Peer, Req, Resp};
use crate::traffic::{HostStats, Request};

const RECENT_MAX: usize = 50;
const ISSUER_DIR: &str = "acme-v02.api.letsencrypt.org-directory";

/// A resolved HTTP route.
#[derive(Clone, Debug, PartialEq)]
pub struct Route {
    pub hostname: String,
    /// "http://host:port" or "https://host:port".
    pub target: String,
    pub force_https: bool,
    pub disabled: bool,
}

#[derive(Default)]
struct PState {
    routes: HashMap<String, Route>,
    started: bool,
    managed: HashSet<String>,
    email: String,
}

#[derive(Default)]
struct Stats {
    hosts: HashMap<String, HostStats>,
    recent: VecDeque<Request>,
}

pub struct Proxy {
    pub storage: PathBuf,
    st: Mutex<PState>,
    certs: RwLock<HashMap<String, (Arc<CertifiedKey>, i64)>>,
    challenges: Mutex<HashMap<String, String>>,
    stats: Mutex<Stats>,
    wake: tokio::sync::Notify,
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Proxy")
    }
}

fn acme_url() -> String {
    std::env::var("MESHGATE_ACME_URL").unwrap_or_else(|_| instant_acme::LetsEncrypt::Production.url().to_string())
}

impl Proxy {
    pub fn new(storage: PathBuf) -> Arc<Proxy> {
        Arc::new(Proxy {
            storage,
            st: Mutex::new(PState::default()),
            certs: RwLock::new(HashMap::new()),
            challenges: Mutex::new(HashMap::new()),
            stats: Mutex::new(Stats::default()),
            wake: tokio::sync::Notify::new(),
        })
    }

    /// Per-hostname counters and the most recent requests.
    pub fn stats(&self) -> (HashMap<String, HostStats>, Vec<Request>) {
        let s = self.stats.lock().unwrap();
        (s.hosts.clone(), s.recent.iter().cloned().collect())
    }

    /// Replaces the route set. Listeners start on the first non-empty
    /// update, so nodes without HTTPS routes never bind :80/:443.
    pub async fn update(self: &Arc<Self>, routes: Vec<Route>, email: &str) -> Result<(), String> {
        let start = {
            let mut st = self.st.lock().unwrap();
            if routes.is_empty() && !st.started {
                return Ok(());
            }
            st.routes = routes.into_iter().map(|r| (r.hostname.to_lowercase(), r)).collect();
            st.email = email.to_string();
            !st.started
        };
        if start {
            self.start().await?;
        }
        let mut st = self.st.lock().unwrap();
        let hosts: Vec<String> = st.routes.keys().cloned().collect();
        let mut added = false;
        for h in hosts {
            if st.managed.insert(h.clone()) {
                self.load_cert(&h);
                added = true;
            }
        }
        if added {
            self.wake.notify_one();
        }
        Ok(())
    }

    async fn start(self: &Arc<Self>) -> Result<(), String> {
        let l80 = http::listen(":80").await.map_err(|e| format!("listen :80 (is nginx/apache running?): {e}"))?;
        let l443 = http::listen(":443").await.map_err(|e| format!("listen :443: {e}"))?;
        let me = self.clone();
        let h80: Arc<dyn http::Handler> = Arc::new(move |r: Req, p: Peer| me.clone().serve_http(r, p));
        tokio::spawn(http::serve(l80, None, h80));
        let mut cfg = rustls::ServerConfig::builder_with_provider(crate::tlsx::provider())
            .with_safe_default_protocol_versions()
            .expect("tls versions")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Sni(self.clone())));
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let me = self.clone();
        let h443: Arc<dyn http::Handler> = Arc::new(move |r: Req, p: Peer| me.clone().serve_https(r, p));
        tokio::spawn(http::serve(l443, Some(tokio_rustls::TlsAcceptor::from(Arc::new(cfg))), h443));
        tokio::spawn(self.clone().manage());
        self.st.lock().unwrap().started = true;
        logf!("proxy: listening on :80 and :443");
        Ok(())
    }

    fn host_dir(&self, host: &str) -> PathBuf {
        self.storage.join("certificates").join(ISSUER_DIR).join(host)
    }

    /// Loads a stored certificate (certmagic's layout).
    fn load_cert(&self, host: &str) {
        let d = self.host_dir(host);
        if let Ok(kp) = crate::tlsx::KeyPair::load(&d.join(format!("{host}.crt")), &d.join(format!("{host}.key"))) {
            let exp = x509_parser::parse_x509_certificate(&kp.chain[0]).map(|(_, c)| c.validity().not_after.timestamp()).unwrap_or(0);
            if let Ok(k) = crate::tlsx::provider().key_provider.load_private_key(kp.key) {
                self.certs.write().unwrap().insert(host.into(), (Arc::new(CertifiedKey::new(kp.chain, k)), exp));
            }
        }
    }

    /// Obtains and renews certificates for the managed hostnames.
    async fn manage(self: Arc<Self>) {
        let mut retry: HashMap<String, Instant> = HashMap::new();
        loop {
            let hosts: Vec<String> = {
                let st = self.st.lock().unwrap();
                let mut h: Vec<String> = st.managed.iter().filter(|h| st.routes.contains_key(*h)).cloned().collect();
                h.sort();
                h
            };
            for h in hosts {
                let exp = self.certs.read().unwrap().get(&h).map(|c| c.1).unwrap_or(0);
                if exp > crate::util::now_unix() + 30 * 86400 || retry.get(&h).is_some_and(|t| t.elapsed() < Duration::from_secs(3600)) {
                    continue;
                }
                match self.obtain(&h).await {
                    Ok(()) => {
                        retry.remove(&h);
                        logf!("proxy: certificate for {h} obtained");
                    }
                    Err(e) => {
                        retry.insert(h.clone(), Instant::now());
                        logf!("proxy: certificate for {h}: {e} (retrying in an hour)");
                    }
                }
            }
            let _ = tokio::time::timeout(Duration::from_secs(12 * 3600), self.wake.notified()).await;
        }
    }

    async fn account(&self) -> Result<instant_acme::Account, String> {
        let path = self.storage.join("meshgate-acme-account.json");
        if let Ok(b) = std::fs::read(&path)
            && let Ok(c) = serde_json::from_slice::<instant_acme::AccountCredentials>(&b)
            && let Ok(a) = instant_acme::Account::from_credentials(c).await
        {
            return Ok(a);
        }
        let email = self.st.lock().unwrap().email.clone();
        let contact = format!("mailto:{email}");
        let contacts: Vec<&str> = if email.is_empty() { vec![] } else { vec![contact.as_str()] };
        let na = instant_acme::NewAccount { contact: &contacts, terms_of_service_agreed: true, only_return_existing: false };
        let (a, c) = instant_acme::Account::create(&na, &acme_url(), None).await.map_err(|e| e.to_string())?;
        crate::config::secure_dir(&self.storage).map_err(|e| e.to_string())?;
        crate::config::write_private(&path, &serde_json::to_vec(&c).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        Ok(a)
    }

    /// One HTTP-01 order.
    async fn obtain(&self, host: &str) -> Result<(), String> {
        use instant_acme::{AuthorizationStatus, ChallengeType, Identifier, NewOrder, OrderStatus};
        let account = self.account().await?;
        let ids = [Identifier::Dns(host.to_string())];
        let mut order = account.new_order(&NewOrder { identifiers: &ids }).await.map_err(|e| e.to_string())?;
        let mut tokens = vec![];
        for a in order.authorizations().await.map_err(|e| e.to_string())? {
            if a.status == AuthorizationStatus::Valid {
                continue;
            }
            let ch = a.challenges.iter().find(|c| c.r#type == ChallengeType::Http01).ok_or("no http-01 challenge offered")?;
            let ka = order.key_authorization(ch);
            self.challenges.lock().unwrap().insert(ch.token.clone(), ka.as_str().to_string());
            tokens.push(ch.token.clone());
            order.set_challenge_ready(&ch.url).await.map_err(|e| e.to_string())?;
        }
        let result = async {
            let mut delay = Duration::from_secs(1);
            for _ in 0..20 {
                tokio::time::sleep(delay).await;
                let st = order.refresh().await.map_err(|e| e.to_string())?;
                match st.status {
                    OrderStatus::Ready | OrderStatus::Valid => break,
                    OrderStatus::Invalid => return Err(format!("order invalid: {:?}", st.error)),
                    _ => delay = (delay * 2).min(Duration::from_secs(10)),
                }
            }
            let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
            let mut p = rcgen::CertificateParams::new(vec![host.to_string()]).map_err(|e| e.to_string())?;
            p.distinguished_name = rcgen::DistinguishedName::new();
            let csr = p.serialize_request(&kp).map_err(|e| e.to_string())?;
            if order.state().status == OrderStatus::Ready {
                order.finalize(csr.der()).await.map_err(|e| e.to_string())?;
            }
            let mut chain = None;
            for _ in 0..20 {
                if let Some(c) = order.certificate().await.map_err(|e| e.to_string())? {
                    chain = Some(c);
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            let chain = chain.ok_or("certificate not issued in time")?;
            let d = self.host_dir(host);
            crate::config::secure_dir(&d).map_err(|e| e.to_string())?;
            crate::config::write_private(&d.join(format!("{host}.key")), kp.serialize_pem().as_bytes()).map_err(|e| e.to_string())?;
            crate::config::write_mode(&d.join(format!("{host}.crt")), chain.as_bytes(), 0o600).map_err(|e| e.to_string())?;
            let meta = serde_json::json!({"sans": [host], "issuer_data": {"url": order.url(), "ca": acme_url()}});
            crate::config::write_private(&d.join(format!("{host}.json")), meta.to_string().as_bytes()).map_err(|e| e.to_string())?;
            self.load_cert(host);
            Ok(())
        }
        .await;
        let mut c = self.challenges.lock().unwrap();
        for t in tokens {
            c.remove(&t);
        }
        result
    }

    fn lookup(&self, req: &Req) -> Option<Route> {
        let host = req.headers().get("host").and_then(|v| v.to_str().ok()).or_else(|| req.uri().host()).unwrap_or("").to_lowercase();
        let host = crate::netx::split_host_port(&host).map(|(h, _)| h).unwrap_or(host);
        self.st.lock().unwrap().routes.get(&host).cloned()
    }

    async fn serve_http(self: Arc<Self>, req: Req, peer: Peer) -> Resp {
        if let Some(token) = req.uri().path().strip_prefix("/.well-known/acme-challenge/")
            && let Some(ka) = self.challenges.lock().unwrap().get(token).cloned()
        {
            return http::resp(StatusCode::OK, "text/plain", ka);
        }
        let Some(r) = self.lookup(&req) else { return http::not_found() };
        if !r.force_https && r.disabled {
            return http::error(StatusCode::FORBIDDEN, "This site is disabled.");
        }
        if r.force_https {
            let pq = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
            let to = format!("https://{}{pq}", r.hostname);
            let mut res = http::resp(StatusCode::PERMANENT_REDIRECT, "", Bytes::new());
            if let Ok(v) = HeaderValue::from_str(&to) {
                res.headers_mut().insert("Location", v);
            }
            return res;
        }
        self.counted(req, peer, r).await
    }

    async fn serve_https(self: Arc<Self>, req: Req, peer: Peer) -> Resp {
        let Some(r) = self.lookup(&req) else { return http::not_found() };
        if r.disabled {
            return http::error(StatusCode::FORBIDDEN, "This site is disabled.");
        }
        let hsts = r.force_https;
        let mut res = self.counted(req, peer, r).await;
        if hsts {
            res.headers_mut().insert("Strict-Transport-Security", HeaderValue::from_static("max-age=31536000"));
        }
        res
    }

    /// Proxies one request and records it.
    async fn counted(self: Arc<Self>, req: Req, peer: Peer, r: Route) -> Resp {
        let start = Instant::now();
        let host = r.hostname.to_lowercase();
        let mut path = req.uri().path().to_string();
        if path.len() > 100 {
            let mut cut = 100;
            while !path.is_char_boundary(cut) {
                cut -= 1;
            }
            path.truncate(cut);
            path.push('…');
        }
        let rec = Arc::new(Record {
            proxy: self.clone(),
            host: host.clone(),
            client: peer.addr.map(|a| a.ip().to_string()).unwrap_or_default(),
            method: req.method().to_string(),
            path,
            tls: peer.tls,
            start,
            status: AtomicU64::new(200),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
        });
        match forward(req, peer, &r.target, rec.clone()).await {
            Ok(mut res) => {
                rec.status.store(res.status().as_u16() as u64, Ordering::Relaxed);
                let body = std::mem::replace(res.body_mut(), http::full(Bytes::new()));
                *res.body_mut() = CountBody { inner: body, rec: Some(rec) }.boxed();
                res
            }
            Err(e) => {
                logf!("proxy {} -> {}: {e}", r.hostname, r.target);
                rec.status.store(502, Ordering::Relaxed);
                drop(rec);
                http::error(StatusCode::BAD_GATEWAY, "upstream unavailable")
            }
        }
    }
}

/// One request's numbers, recorded when its response is done.
struct Record {
    proxy: Arc<Proxy>,
    host: String,
    client: String,
    method: String,
    path: String,
    tls: bool,
    start: Instant,
    status: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

impl Drop for Record {
    fn drop(&mut self) {
        let (inn, out, status) =
            (self.bytes_in.load(Ordering::Relaxed), self.bytes_out.load(Ordering::Relaxed), self.status.load(Ordering::Relaxed));
        let mut s = self.proxy.stats.lock().unwrap();
        let h = s.hosts.entry(self.host.clone()).or_default();
        h.requests += 1;
        h.in_ += inn;
        h.out += out;
        if !self.tls {
            h.http_requests += 1;
            h.http_in += inn;
            h.http_out += out;
        }
        if status >= 500 {
            h.errors += 1;
        }
        s.recent.push_back(Request {
            time: crate::util::now_unix() - self.start.elapsed().as_secs() as i64,
            client: self.client.clone(),
            method: self.method.clone(),
            host: self.host.clone(),
            path: std::mem::take(&mut self.path),
            status: status as i64,
            bytes: out,
            ms: self.start.elapsed().as_millis() as i64,
        });
        while s.recent.len() > RECENT_MAX {
            s.recent.pop_front();
        }
    }
}

/// Counts the bytes of a response body; the record is written when the
/// body is finished or dropped.
struct CountBody {
    inner: Body,
    rec: Option<Arc<Record>>,
}

impl hyper::body::Body for CountBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        let r = Pin::new(&mut self.inner).poll_frame(cx);
        match &r {
            Poll::Ready(Some(Ok(f))) => {
                if let (Some(d), Some(rec)) = (f.data_ref(), &self.rec) {
                    rec.bytes_out.fetch_add(d.len() as u64, Ordering::Relaxed);
                }
            }
            Poll::Ready(None) => self.rec = None,
            _ => {}
        }
        r
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// Counts request body bytes on their way to the backend.
struct CountIn {
    inner: Incoming,
    rec: Arc<Record>,
}

impl hyper::body::Body for CountIn {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let r = Pin::new(&mut self.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(f))) = &r
            && let Some(d) = f.data_ref()
        {
            self.rec.bytes_in.fetch_add(d.len() as u64, Ordering::Relaxed);
        }
        r
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

const HOP: [&str; 9] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn strip_hop(h: &mut HeaderMap) {
    let extra: Vec<String> = h
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|s| s.trim().to_lowercase()).collect::<Vec<_>>())
        .collect();
    for k in HOP.iter().map(|s| s.to_string()).chain(extra) {
        h.remove(k.as_str());
    }
}

/// Sends req to target (httputil.ReverseProxy with SetURL + SetXForwarded,
/// the original Host kept), streaming both ways; websocket upgrades pass.
async fn forward(mut req: Req, peer: Peer, target: &str, rec: Arc<Record>) -> Result<Resp, String> {
    let u = crate::httpc::Url::parse(target).ok_or("bad target")?;
    let upgrade = req.headers().get("upgrade").cloned();
    let client_up = upgrade.is_some().then(|| hyper::upgrade::on(&mut req));
    let (mut parts, body) = req.into_parts();
    let in_host = parts.headers.get("host").cloned();
    let prior_xff: Vec<String> =
        parts.headers.get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok().map(String::from)).collect();
    strip_hop(&mut parts.headers);
    for k in ["forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto"] {
        parts.headers.remove(k);
    }
    let client = peer.addr.map(|a| a.ip().to_string()).unwrap_or_default();
    let xff = if prior_xff.is_empty() { client } else { format!("{}, {client}", prior_xff.join(", ")) };
    let h = &mut parts.headers;
    h.insert("x-forwarded-for", HeaderValue::from_str(&xff).map_err(|e| e.to_string())?);
    if let Some(v) = &in_host {
        h.insert("x-forwarded-host", v.clone());
    }
    h.insert("x-forwarded-proto", HeaderValue::from_static(if peer.tls { "https" } else { "http" }));
    if let Some(up) = &upgrade {
        h.insert("connection", HeaderValue::from_static("upgrade"));
        h.insert("upgrade", up.clone());
    }
    let pq = parts.uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
    parts.uri = pq.parse().map_err(|e: hyper::http::uri::InvalidUri| e.to_string())?;
    parts.version = hyper::Version::HTTP_11;
    if !parts.headers.contains_key("host") {
        parts.headers.insert("host", HeaderValue::from_str(&u.host_header()).map_err(|e| e.to_string())?);
    }
    let out = hyper::Request::from_parts(parts, CountIn { inner: body, rec });

    let tcp = http::dial(&u.addr(), Duration::from_secs(30)).await?;
    let mut res = if u.https {
        let name = rustls_pki_types::ServerName::try_from(u.host.clone()).map_err(|e| e.to_string())?;
        let s = tokio_rustls::TlsConnector::from(crate::tlsx::insecure()).connect(name, tcp).await.map_err(|e| e.to_string())?;
        send(s, out).await?
    } else {
        send(tcp, out).await?
    };
    if res.status() == StatusCode::SWITCHING_PROTOCOLS {
        if let Some(cu) = client_up {
            let su = hyper::upgrade::on(&mut res);
            tokio::spawn(async move {
                if let (Ok(c), Ok(s)) = (cu.await, su.await) {
                    let _ = tokio::io::copy_bidirectional(&mut TokioIo::new(c), &mut TokioIo::new(s)).await;
                }
            });
        }
        let (parts, _) = res.into_parts();
        return Ok(hyper::Response::from_parts(parts, http::full(Bytes::new())));
    }
    let (mut parts, body) = res.into_parts();
    strip_hop(&mut parts.headers);
    Ok(hyper::Response::from_parts(parts, body.map_err(std::io::Error::other).boxed()))
}

async fn send<S>(io: S, req: hyper::Request<CountIn>) -> Result<hyper::Response<Incoming>, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await.map_err(|e| e.to_string())?;
    tokio::spawn(conn.with_upgrades());
    tx.send_request(req).await.map_err(|e| e.to_string())
}

/// Picks the certificate by SNI.
#[derive(Debug)]
struct Sni(Arc<Proxy>);

impl ResolvesServerCert for Sni {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name()?.to_lowercase();
        self.0.certs.read().unwrap().get(&name).map(|c| c.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Method;

    /// A backend that echoes what it received.
    async fn backend() -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let h: Arc<dyn http::Handler> = Arc::new(|r: Req, _p: Peer| async move {
            let host = r.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            let xff = r.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            let path = r.uri().to_string();
            let b = http::body(r, 1 << 20).await;
            http::resp(StatusCode::OK, "text/plain", format!("host={host} xff={xff} path={path} body={}", String::from_utf8_lossy(&b)))
        });
        tokio::spawn(http::serve(l, None, h));
        addr
    }

    #[tokio::test]
    async fn proxies_counts_and_disables() {
        let be = backend().await;
        let p = Proxy::new(tempfile::tempdir().unwrap().path().to_path_buf());
        p.st.lock().unwrap().routes.insert(
            "app.example.com".into(),
            Route { hostname: "app.example.com".into(), target: format!("http://{be}"), force_https: false, disabled: false },
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let me = p.clone();
        let h: Arc<dyn http::Handler> = Arc::new(move |r: Req, peer: Peer| me.clone().serve_http(r, peer));
        tokio::spawn(http::serve(l, None, h));
        let r = http::plain(&addr, Method::POST, "/x?y=1", &[("Host", "App.example.com")], "hello".into(), Duration::from_secs(5))
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&r.body).to_string();
        assert_eq!(r.status, 200);
        assert!(
            text.contains("host=App.example.com")
                && text.contains("xff=127.0.0.1")
                && text.contains("path=/x?y=1")
                && text.contains("body=hello"),
            "{text}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (hosts, recent) = p.stats();
        let s = hosts["app.example.com"];
        assert_eq!((s.requests, s.in_, s.http_requests), (1, 5, 1));
        assert_eq!(s.out as usize, text.len());
        assert_eq!(recent[0].path, "/x");
        assert_eq!(
            http::plain(&addr, Method::GET, "/", &[("Host", "other.example.com")], Bytes::new(), Duration::from_secs(5))
                .await
                .unwrap()
                .status,
            404
        );
        p.st.lock().unwrap().routes.get_mut("app.example.com").unwrap().disabled = true;
        assert_eq!(
            http::plain(&addr, Method::GET, "/", &[("Host", "app.example.com")], Bytes::new(), Duration::from_secs(5))
                .await
                .unwrap()
                .status,
            403
        );
        p.st.lock().unwrap().routes.get_mut("app.example.com").unwrap().force_https = true;
        let r =
            http::plain(&addr, Method::GET, "/a?b", &[("Host", "app.example.com")], Bytes::new(), Duration::from_secs(5)).await.unwrap();
        assert_eq!(r.status, 308);
        assert_eq!(r.headers["location"], "https://app.example.com/a?b");
        // Backend down: 502 and counted as an error.
        p.st.lock().unwrap().routes.insert(
            "down.example.com".into(),
            Route { hostname: "down.example.com".into(), target: "http://127.0.0.1:1".into(), force_https: false, disabled: false },
        );
        let r = http::plain(&addr, Method::GET, "/", &[("Host", "down.example.com")], Bytes::new(), Duration::from_secs(5)).await.unwrap();
        assert_eq!(r.status, 502);
        assert_eq!(p.stats().0["down.example.com"].errors, 1);
    }
}
