//! The browser dashboard and the phone app's management API (Go:
//! internal/webui). The dashboard files are the Go build's own
//! (go/internal/webui/static), served as they are.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use hyper::header::HeaderValue;
use hyper::{Method, StatusCode};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::http::{self, Peer, Req, Resp};
use crate::ops::Service;

const COOKIE: &str = "meshgate_session";
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
/// How long an app login lasts.
pub const TOKEN_TTL: i64 = 12 * 3600;

/// The dashboard's files.
pub const STATIC: [(&str, &str, &[u8]); 3] = [
    ("index.html", "text/html; charset=utf-8", include_bytes!("../../go/internal/webui/static/index.html")),
    ("app.js", "text/javascript; charset=utf-8", include_bytes!("../../go/internal/webui/static/app.js")),
    ("app.css", "text/css; charset=utf-8", include_bytes!("../../go/internal/webui/static/app.css")),
];

/// Locks out an address after 5 wrong passwords in 10 minutes.
#[derive(Default)]
pub struct Limiter {
    fails: Mutex<HashMap<String, Vec<Instant>>>,
}

impl Limiter {
    /// Runs ok unless the caller is locked out; Err is the response to send.
    pub fn check(&self, peer: &Peer, ok: impl FnOnce() -> bool) -> Result<(), Box<Resp>> {
        let mut ip = peer.addr.map(|a| a.to_string()).unwrap_or_default();
        if let Some(i) = ip.rfind(':') {
            ip.truncate(i);
        }
        let n = {
            let mut f = self.fails.lock().unwrap();
            let v = f.entry(ip.clone()).or_default();
            v.retain(|t| t.elapsed() < Duration::from_secs(600));
            v.len()
        };
        if n >= 5 {
            return Err(Box::new(http::error(StatusCode::TOO_MANY_REQUESTS, r#"{"error":"too many attempts, wait 10 minutes"}"#)));
        }
        if !ok() {
            self.fails.lock().unwrap().entry(ip).or_default().push(Instant::now());
            return Err(Box::new(http::error(StatusCode::UNAUTHORIZED, r#"{"error":"wrong username or password"}"#)));
        }
        Ok(())
    }
}

/// Login bodies: Go matches JSON keys case-insensitively.
#[derive(Deserialize, Default)]
#[serde(default)]
struct Login {
    #[serde(alias = "Username", alias = "USERNAME")]
    username: String,
    #[serde(alias = "Password", alias = "PASSWORD")]
    password: String,
}

pub struct Ui {
    ops: Arc<Service>,
    sessions: Mutex<HashMap<String, (String, Instant)>>,
    lim: Limiter,
    /// The CA download and the http->https redirect, when served over HTTPS.
    pub cert: Option<Arc<crate::webtls::Cert>>,
}

fn secure(mut r: Resp) -> Resp {
    let h = r.headers_mut();
    h.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    h.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    h.insert("Referrer-Policy", HeaderValue::from_static("no-referrer"));
    h.insert(
        "Content-Security-Policy",
        HeaderValue::from_static("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'"),
    );
    h.insert("Cache-Control", HeaderValue::from_static("no-cache"));
    r
}

fn cookie(req: &Req, name: &str) -> Option<String> {
    for v in req.headers().get_all("cookie") {
        for part in v.to_str().ok()?.split(';') {
            if let Some((k, val)) = part.trim().split_once('=')
                && k == name
            {
                return Some(val.trim_matches('"').to_string());
            }
        }
    }
    None
}

impl Ui {
    pub fn new(ops: Arc<Service>, cert: Option<Arc<crate::webtls::Cert>>) -> Arc<Ui> {
        Arc::new(Ui { ops, sessions: Mutex::new(HashMap::new()), lim: Limiter::default(), cert })
    }

    fn user(&self, req: &Req) -> Option<String> {
        let c = cookie(req, COOKIE)?;
        let mut s = self.sessions.lock().unwrap();
        match s.get(&c) {
            Some((u, exp)) if Instant::now() < *exp => Some(u.clone()),
            _ => {
                s.remove(&c);
                None
            }
        }
    }

    pub async fn handle(self: Arc<Self>, req: Req, peer: Peer) -> Resp {
        if let Some(cert) = &self.cert {
            // Plain HTTP on the HTTPS port: redirect.
            if !peer.tls {
                let host = req.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                let uri = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
                return redirect(&format!("https://{host}{uri}"), StatusCode::PERMANENT_REDIRECT, req.method());
            }
            if req.uri().path() == crate::webtls::CA_PATH {
                let mut r = http::resp(StatusCode::OK, "application/x-x509-ca-cert", cert.ca_pem());
                r.headers_mut().insert("Content-Disposition", HeaderValue::from_static("attachment; filename=\"meshgate-ca.crt\""));
                return r;
            }
        }
        secure(self.route(req, peer).await)
    }

    async fn route(&self, req: Req, peer: Peer) -> Resp {
        let path = req.uri().path().to_string();
        let m = req.method().clone();
        let get = m == Method::GET || m == Method::HEAD;
        match path.as_str() {
            "/auth/login" | "/auth/logout" if m != Method::POST => return http::method_not_allowed(),
            "/auth/me" if !get => return http::method_not_allowed(),
            "/auth/login" => return self.login(req, peer).await,
            "/auth/logout" => {
                if let Some(c) = cookie(&req, COOKIE) {
                    self.sessions.lock().unwrap().remove(&c);
                }
                let mut r = http::resp(StatusCode::OK, "", r#"{"ok":true}"#);
                r.headers_mut().insert("Set-Cookie", HeaderValue::from_str(&format!("{COOKIE}=; Path=/; Max-Age=0")).unwrap());
                return r;
            }
            "/auth/me" => {
                let u = self.user(&req);
                return http::ok_json(&serde_json::json!({"ok": u.is_some(), "user": u.unwrap_or_default()}));
            }
            _ => {}
        }
        if path.starts_with("/api/") {
            if !get && m != Method::POST {
                return http::method_not_allowed();
            }
            if self.user(&req).is_none() {
                return http::error(StatusCode::UNAUTHORIZED, r#"{"error":"login required"}"#);
            }
            // CSRF: browsers cannot add custom headers to cross-site posts.
            if !get && req.headers().get("x-meshgate").and_then(|v| v.to_str().ok()) != Some("1") {
                return http::error(StatusCode::FORBIDDEN, r#"{"error":"missing csrf header"}"#);
            }
            if path == "/api/qr" && m == Method::POST {
                return qr(req).await;
            }
            return self.ops.handle("/api/", req).await.unwrap_or_else(http::not_found);
        }
        if !get {
            return http::method_not_allowed();
        }
        serve_static(&path)
    }

    async fn login(&self, req: Req, peer: Peer) -> Resp {
        let tls = peer.tls;
        let b: Login = match http::first_json(&http::body(req, 4096).await) {
            Ok(b) => b,
            Err(_) => return http::error(StatusCode::BAD_REQUEST, r#"{"error":"bad request"}"#),
        };
        if let Err(r) = self.lim.check(&peer, || self.ops.check_admin(&b.username, &b.password)) {
            return *r;
        }
        let tok = URL_SAFE_NO_PAD.encode(crate::util::random_bytes::<32>());
        self.sessions.lock().unwrap().insert(tok.clone(), (b.username, Instant::now() + SESSION_TTL));
        let mut r = http::resp(StatusCode::OK, "application/json", r#"{"ok":true}"#);
        let secure = if tls { "; Secure" } else { "" };
        let c = format!("{COOKIE}={tok}; Path=/; Max-Age={}; HttpOnly{secure}; SameSite=Strict", SESSION_TTL.as_secs());
        r.headers_mut().insert("Set-Cookie", HeaderValue::from_str(&c).unwrap());
        r
    }
}

fn redirect(to: &str, code: StatusCode, m: &Method) -> Resp {
    let body = if *m == Method::GET || *m == Method::HEAD {
        format!("<a href=\"{}\">{}</a>.\n\n", to.replace('&', "&amp;").replace('"', "&#34;"), code.canonical_reason().unwrap_or(""))
    } else {
        String::new()
    };
    let mut r = http::resp(code, if body.is_empty() { "" } else { "text/html; charset=utf-8" }, body);
    if let Ok(v) = HeaderValue::from_str(to) {
        r.headers_mut().insert("Location", v);
    }
    r
}

/// http.FileServer over the dashboard files.
fn serve_static(path: &str) -> Resp {
    if path == "/index.html" {
        return redirect("./", StatusCode::MOVED_PERMANENTLY, &Method::GET);
    }
    let name = if path == "/" { "index.html" } else { path.trim_start_matches('/') };
    match STATIC.iter().find(|(n, _, _)| *n == name) {
        Some((_, ctype, body)) => {
            let mut r = http::resp(StatusCode::OK, ctype, *body);
            r.headers_mut().insert("Accept-Ranges", HeaderValue::from_static("bytes"));
            r
        }
        None => http::not_found(),
    }
}

/// Renders {"text": ...} as a PNG data URL for the join dialogs.
pub async fn qr(req: Req) -> Resp {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct B {
        #[serde(alias = "Text", alias = "TEXT")]
        text: String,
    }
    let b: B = http::first_json(&http::body(req, 8192).await).unwrap_or_default();
    if b.text.is_empty() {
        return http::error(StatusCode::BAD_REQUEST, r#"{"error":"bad request"}"#);
    }
    match qr_png(&b.text, 320) {
        Some(png) => http::ok_json(&serde_json::json!({"png": format!("data:image/png;base64,{}", STANDARD.encode(png))})),
        None => http::error(StatusCode::BAD_REQUEST, r#"{"error":"qr failed"}"#),
    }
}

/// A QR code (medium error correction, 4-module quiet zone) as a size x size
/// grayscale PNG.
pub fn qr_png(text: &str, size: usize) -> Option<Vec<u8>> {
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M).ok()?;
    let n = code.width();
    let total = n + 8;
    let scale = (size / total).max(1);
    let offset = (size.saturating_sub(total * scale)) / 2 + 4 * scale;
    let colors = code.to_colors();
    let mut raw = Vec::with_capacity((size + 1) * size);
    for y in 0..size {
        raw.push(0); // filter: none
        for x in 0..size {
            let dark = x >= offset && y >= offset && {
                let (mx, my) = ((x - offset) / scale, (y - offset) / scale);
                mx < n && my < n && colors[my * n + mx] == qrcode::Color::Dark
            };
            raw.push(if dark { 0 } else { 255 });
        }
    }
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    std::io::Write::write_all(&mut z, &raw).ok()?;
    let idat = z.finish().ok()?;
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    let chunk = |png: &mut Vec<u8>, typ: &[u8], data: &[u8]| {
        png.extend_from_slice(&(data.len() as u32).to_be_bytes());
        let mut c = typ.to_vec();
        c.extend_from_slice(data);
        png.extend_from_slice(&c);
        png.extend_from_slice(&crc32fast::hash(&c).to_be_bytes());
    };
    let mut ihdr = vec![];
    ihdr.extend_from_slice(&(size as u32).to_be_bytes());
    ihdr.extend_from_slice(&(size as u32).to_be_bytes());
    ihdr.extend_from_slice(&[8, 0, 0, 0, 0]); // 8-bit grayscale
    chunk(&mut png, b"IHDR", &ihdr);
    chunk(&mut png, b"IDAT", &idat);
    chunk(&mut png, b"IEND", &[]);
    Some(png)
}

/// The phone app's management API on a server's mesh port, under /admin/.
/// A login yields a token signed with a key derived from the admin's stored
/// password hash, which every server has, so the app can move between
/// servers without logging in again.
pub struct AppApi {
    pub ops: Arc<Service>,
    lim: Limiter,
}

impl AppApi {
    pub fn new(ops: Arc<Service>) -> Arc<AppApi> {
        Arc::new(AppApi { ops, lim: Limiter::default() })
    }

    /// Serves /admin/...; None for other paths. off: this node opted out.
    pub async fn handle(&self, req: Req, peer: Peer, off: bool) -> Option<Resp> {
        let path = req.uri().path().to_string();
        if !path.starts_with("/admin/") {
            return None;
        }
        if off {
            return Some(http::error(StatusCode::NOT_FOUND, r#"{"error":"app management is turned off on this node"}"#));
        }
        let mut r = self.route(req, peer, &path).await;
        r.headers_mut().insert("Cache-Control", HeaderValue::from_static("no-store"));
        Some(r)
    }

    async fn route(&self, req: Req, peer: Peer, path: &str) -> Resp {
        if path == "/admin/login" {
            if req.method() != Method::POST {
                return http::method_not_allowed();
            }
            let b: Login = match http::first_json(&http::body(req, 4096).await) {
                Ok(b) => b,
                Err(_) => return http::error(StatusCode::BAD_REQUEST, r#"{"error":"bad request"}"#),
            };
            if let Err(r) = self.lim.check(&peer, || self.ops.check_admin(&b.username, &b.password)) {
                return *r;
            }
            let hash = self.ops.admin_hash(&b.username).unwrap_or_default();
            let exp = crate::util::now_unix() + TOKEN_TTL;
            return http::ok_json(
                &serde_json::json!({"ok": true, "user": b.username, "token": sign_token(&hash, &b.username, exp), "expires": exp}),
            );
        }
        if !path.starts_with("/admin/api/") {
            return http::not_found();
        }
        let auth = req.headers().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
        let tok = auth.strip_prefix("Bearer ").unwrap_or(auth);
        if !self.valid_token(tok) {
            return http::error(StatusCode::UNAUTHORIZED, r#"{"error":"login required"}"#);
        }
        if path == "/admin/api/qr" && req.method() == Method::POST {
            return qr(req).await;
        }
        self.ops.handle("/admin/api/", req).await.unwrap_or_else(http::not_found)
    }

    fn valid_token(&self, tok: &str) -> bool {
        let parts: Vec<&str> = tok.split('.').collect();
        if parts.len() != 3 {
            return false;
        }
        let (Ok(user), Ok(exp), Ok(mac)) = (URL_SAFE_NO_PAD.decode(parts[0]), parts[1].parse::<i64>(), hex::decode(parts[2])) else {
            return false;
        };
        if crate::util::now_unix() > exp {
            return false;
        }
        let Some(hash) = self.ops.admin_hash(&String::from_utf8_lossy(&user)) else { return false };
        let mut m = mac_for(&hash);
        m.update(format!("{}.{}", parts[0], parts[1]).as_bytes());
        m.verify_slice(&mac).is_ok()
    }
}

fn mac_for(hash: &str) -> Hmac<Sha256> {
    let key = Sha256::digest(format!("meshgate app token{hash}").as_bytes());
    Hmac::<Sha256>::new_from_slice(&key).expect("hmac key")
}

/// base64url(user) "." expiry "." hex(HMAC-SHA256(SHA-256("meshgate app
/// token" + hash), user "." expiry)).
pub fn sign_token(hash: &str, user: &str, exp: i64) -> String {
    let u = URL_SAFE_NO_PAD.encode(user);
    let msg = format!("{u}.{exp}");
    let mut m = mac_for(hash);
    m.update(msg.as_bytes());
    format!("{msg}.{}", hex::encode(m.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{self, Node};
    use crate::store::{Scope, Store};

    async fn start(ui: Arc<Ui>) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let h: Arc<dyn http::Handler> = Arc::new(move |r: Req, p: Peer| ui.clone().handle(r, p));
        tokio::spawn(http::serve(l, None, h));
        addr
    }

    fn ops() -> Arc<Service> {
        let s = Arc::new(Store::memory("self"));
        s.put(
            "node/self",
            &Node { id: "self".into(), name: "vps".into(), kind: model::NODE_SERVER.into(), ..Default::default() },
            Scope::Cluster,
        )
        .unwrap();
        let o = Service::new(s, "self");
        o.set_admin("admin", "password1").unwrap();
        o
    }

    async fn call(addr: &str, m: Method, path: &str, hdrs: &[(&str, &str)], body: &str) -> http::ClientResp {
        http::plain(addr, m, path, hdrs, body.to_string().into(), Duration::from_secs(5)).await.unwrap()
    }

    #[tokio::test]
    async fn login_session_csrf_and_files() {
        let addr = start(Ui::new(ops(), None)).await;
        let r = call(&addr, Method::GET, "/", &[], "").await;
        assert_eq!(r.status, 200);
        assert!(String::from_utf8_lossy(&r.body).contains("<html") || String::from_utf8_lossy(&r.body).contains("<!doctype"));
        assert_eq!(r.headers["x-frame-options"], "DENY");
        assert_eq!(call(&addr, Method::GET, "/app.js", &[], "").await.headers["content-type"], "text/javascript; charset=utf-8");
        assert_eq!(call(&addr, Method::GET, "/nope", &[], "").await.status, 404);
        assert_eq!(call(&addr, Method::GET, "/api/view", &[], "").await.status, 401);

        let bad = call(&addr, Method::POST, "/auth/login", &[], r#"{"username":"admin","password":"x"}"#).await;
        assert_eq!(bad.status, 401);
        let ok = call(&addr, Method::POST, "/auth/login", &[], r#"{"Username":"admin","Password":"password1"}"#).await;
        assert_eq!(ok.status, 200);
        let set = ok.headers["set-cookie"].to_str().unwrap().to_string();
        assert!(set.contains("HttpOnly") && set.contains("SameSite=Strict"));
        let c = set.split(';').next().unwrap().to_string();
        let view = call(&addr, Method::GET, "/api/view", &[("Cookie", &c)], "").await;
        assert_eq!(view.status, 200);
        assert!(String::from_utf8_lossy(&view.body).contains(r#""self_id":"self""#));
        let me = call(&addr, Method::GET, "/auth/me", &[("Cookie", &c)], "").await;
        assert!(String::from_utf8_lossy(&me.body).contains(r#""user":"admin""#));
        let no_csrf = call(&addr, Method::POST, "/api/network", &[("Cookie", &c)], r#"{"acme_email":"a@b.c"}"#).await;
        assert_eq!(no_csrf.status, 403);
        let with = call(&addr, Method::POST, "/api/network", &[("Cookie", &c), ("X-Meshgate", "1")], r#"{"acme_email":"a@b.c"}"#).await;
        assert_eq!(with.status, 200, "{:?}", with.body);
        let qr = call(&addr, Method::POST, "/api/qr", &[("Cookie", &c), ("X-Meshgate", "1")], r#"{"text":"mg1.abc"}"#).await;
        assert!(String::from_utf8_lossy(&qr.body).contains("data:image/png;base64,iVBOR"));
        // Five wrong passwords lock the address out.
        for _ in 0..5 {
            call(&addr, Method::POST, "/auth/login", &[], r#"{"username":"admin","password":"x"}"#).await;
        }
        let locked = call(&addr, Method::POST, "/auth/login", &[], r#"{"username":"admin","password":"password1"}"#).await;
        assert_eq!(locked.status, 429);
    }

    #[test]
    fn app_tokens_follow_the_password() {
        let o = ops();
        let api = AppApi::new(o.clone());
        let h = o.admin_hash("admin").unwrap();
        let t = sign_token(&h, "admin", crate::util::now_unix() + 60);
        assert!(api.valid_token(&t));
        assert!(!api.valid_token(&sign_token(&h, "admin", crate::util::now_unix() - 1)));
        o.set_admin("admin", "password2").unwrap();
        assert!(!api.valid_token(&t), "a changed password invalidates tokens");
    }

    #[test]
    fn qr_png_is_valid() {
        let png = qr_png("hello", 320).unwrap();
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(u32::from_be_bytes(png[16..20].try_into().unwrap()), 320);
    }
}
