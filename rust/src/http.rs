//! A small HTTP layer on hyper shared by the join API, the mesh API, the
//! local socket API and the web UI. Responses mimic Go's net/http helpers
//! (http.Error, json.NewEncoder) so clients see the same bytes.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{CONTENT_TYPE, HeaderValue};
use hyper::{HeaderMap, Method, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

pub type Req = hyper::Request<Incoming>;
/// A streaming response body.
pub type Body = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;
pub type Resp = hyper::Response<Body>;

/// A complete body.
pub fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).map_err(|never| match never {}).boxed()
}
pub type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Who sent a request.
#[derive(Clone, Copy, Debug)]
pub struct Peer {
    pub addr: Option<SocketAddr>,
    pub tls: bool,
}

pub trait Handler: Send + Sync + 'static {
    fn call(&self, req: Req, peer: Peer) -> BoxFut<Resp>;
}

impl<F, Fut> Handler for F
where
    F: Fn(Req, Peer) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Resp> + Send + 'static,
{
    fn call(&self, req: Req, peer: Peer) -> BoxFut<Resp> {
        Box::pin(self(req, peer))
    }
}

/// Builds a response.
pub fn resp(status: StatusCode, ctype: &str, body: impl Into<Bytes>) -> Resp {
    let mut r = hyper::Response::new(full(body));
    *r.status_mut() = status;
    if !ctype.is_empty() {
        r.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_str(ctype).unwrap());
    }
    r
}

/// Go's http.Error: plain text with a trailing newline.
pub fn error(status: StatusCode, msg: impl AsRef<str>) -> Resp {
    let mut r = resp(status, "text/plain; charset=utf-8", format!("{}\n", msg.as_ref()));
    r.headers_mut().insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    r
}

/// json.NewEncoder(w).Encode(v): JSON plus a newline.
pub fn json<T: Serialize + ?Sized>(status: StatusCode, v: &T) -> Resp {
    let mut b = crate::gojson::marshal(v);
    b.push(b'\n');
    resp(status, "application/json", b)
}

pub fn ok_json<T: Serialize + ?Sized>(v: &T) -> Resp {
    json(StatusCode::OK, v)
}

pub fn status(s: StatusCode) -> Resp {
    resp(s, "", Bytes::new())
}

pub fn not_found() -> Resp {
    error(StatusCode::NOT_FOUND, "404 page not found")
}

pub fn method_not_allowed() -> Resp {
    error(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
}

/// Reads at most `limit` bytes of the body (io.LimitReader: the rest is cut).
pub async fn body(req: Req, limit: usize) -> Bytes {
    let mut out = Vec::new();
    let mut b = req.into_body();
    while let Some(Ok(frame)) = b.frame().await {
        if let Ok(data) = frame.into_data() {
            let room = limit.saturating_sub(out.len());
            out.extend_from_slice(&data[..data.len().min(room)]);
            if out.len() >= limit {
                break;
            }
        }
    }
    out.into()
}

/// Decodes a JSON body read up to `limit` bytes.
pub async fn decode<T: DeserializeOwned>(req: Req, limit: usize) -> Result<T, Box<Resp>> {
    let b = body(req, limit).await;
    first_json(&b).map_err(|_| Box::new(error(StatusCode::BAD_REQUEST, "bad request")))
}

/// json.Decoder.Decode: reads the first JSON value, ignoring what follows.
pub fn first_json<T: DeserializeOwned>(b: &[u8]) -> serde_json::Result<T> {
    let mut it = serde_json::Deserializer::from_slice(b).into_iter::<T>();
    match it.next() {
        Some(r) => r,
        None => serde_json::from_slice(b), // produces the EOF error
    }
}

/// Serves HTTP/1.1 on a stream until it closes.
pub async fn serve_conn<S>(io: S, h: Arc<dyn Handler>, peer: Peer)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc = hyper::service::service_fn(move |req| {
        let h = h.clone();
        async move { Ok::<_, Infallible>(h.call(req, peer).await) }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .keep_alive(true)
        .serve_connection(TokioIo::new(io), svc)
        .with_upgrades()
        .await;
}

/// Accepts connections forever (plain or TLS).
pub async fn serve(l: TcpListener, tls: Option<tokio_rustls::TlsAcceptor>, h: Arc<dyn Handler>) {
    loop {
        let Ok((c, addr)) = l.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let _ = c.set_nodelay(true);
        let h = h.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            match tls {
                None => serve_conn(c, h, Peer { addr: Some(addr), tls: false }).await,
                Some(acc) => {
                    let Ok(Ok(s)) = tokio::time::timeout(Duration::from_secs(10), acc.accept(c)).await else { return };
                    serve_conn(s, h, Peer { addr: Some(addr), tls: true }).await
                }
            }
        });
    }
}

/// A finished client response.
#[derive(Debug)]
pub struct ClientResp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl ClientResp {
    pub fn status_line(&self) -> String {
        format!("{} {}", self.status.as_u16(), self.status.canonical_reason().unwrap_or(""))
    }
}

/// One HTTP/1.1 request over an established stream. `limit` caps the body.
pub async fn request_on<S>(
    io: S,
    method: Method,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Bytes,
    limit: usize,
) -> Result<ClientResp, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await.map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    let mut b = hyper::Request::builder().method(method).uri(path);
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        b = b.header("Host", host);
    }
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    if !body.is_empty() && !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
        b = b.header(CONTENT_TYPE, "application/json");
    }
    let req = b.body(Full::new(body)).map_err(|e| e.to_string())?;
    let res = send.send_request(req).await.map_err(|e| e.to_string())?;
    let (parts, inc) = res.into_parts();
    let body = Limited::new(inc, limit).collect().await.map_err(|e| e.to_string())?.to_bytes();
    Ok(ClientResp { status: parts.status, headers: parts.headers, body })
}

/// Connects with a timeout.
pub async fn dial(addr: &str, timeout: Duration) -> Result<tokio::net::TcpStream, String> {
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(c)) => {
            let _ = c.set_nodelay(true);
            Ok(c)
        }
        Ok(Err(e)) => Err(format!("dial tcp {addr}: {e}")),
        Err(_) => Err(format!("dial tcp {addr}: i/o timeout")),
    }
}

/// A plain-HTTP request to "host:port" with an overall timeout.
pub async fn plain(
    addr: &str,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body: Bytes,
    timeout: Duration,
) -> Result<ClientResp, String> {
    let fut = async {
        let c = dial(addr, timeout).await?;
        request_on(c, method, addr, path, headers, body, 64 << 20).await
    };
    tokio::time::timeout(timeout, fut).await.unwrap_or_else(|_| Err("Client.Timeout exceeded while awaiting headers".into()))
}

/// An HTTPS request to "host:port" with the given TLS config.
#[allow(clippy::too_many_arguments)]
pub async fn tls(
    addr: &str,
    server_name: &str,
    cfg: Arc<rustls::ClientConfig>,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body: Bytes,
    timeout: Duration,
) -> Result<ClientResp, String> {
    let fut = async {
        let c = dial(addr, timeout).await?;
        let name = rustls_pki_types::ServerName::try_from(server_name.to_string()).map_err(|e| e.to_string())?;
        let s = tokio_rustls::TlsConnector::from(cfg).connect(name, c).await.map_err(|e| e.to_string())?;
        request_on(s, method, server_name, path, headers, body, 64 << 20).await
    };
    tokio::time::timeout(timeout, fut).await.unwrap_or_else(|_| Err("Client.Timeout exceeded while awaiting headers".into()))
}

/// The host part of "host:port" for SNI; IPs are fine for rustls.
pub fn host_of(addr: &str) -> String {
    crate::netx::split_host_port(addr).map(|(h, _)| h).unwrap_or_else(|_| addr.to_string())
}

/// A query parameter (first value), URL-decoded.
pub fn query(req: &Req, name: &str) -> String {
    query_of(req.uri().query().unwrap_or(""), name)
}

pub fn query_of(q: &str, name: &str) -> String {
    for kv in q.split('&') {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        if url_decode(k) == name {
            return url_decode(v);
        }
    }
    String::new()
}

/// Query unescaping ('+' is a space).
pub fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => match u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16) {
                Ok(v) => {
                    out.push(v);
                    i += 2;
                }
                Err(_) => out.push(b'%'),
            },
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Query escaping (url.QueryEscape).
pub fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for c in s.bytes() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(c as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{c:02X}")),
        }
    }
    out
}

/// net.Listen("tcp", addr) with Go's address forms: ":port" listens on
/// every address (IPv6 and IPv4 when the system has IPv6).
pub async fn listen(addr: &str) -> std::io::Result<TcpListener> {
    if let Some(port) = addr.strip_prefix(':') {
        let port: u16 = port.parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("bad port in {addr}")))?;
        let any6 = std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port));
        if let Ok(s) = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, Some(socket2::Protocol::TCP)) {
            let ok = s.set_only_v6(false).is_ok()
                && s.set_reuse_address(true).is_ok()
                && s.bind(&any6.into()).is_ok()
                && s.listen(1024).is_ok()
                && s.set_nonblocking(true).is_ok();
            if ok {
                return TcpListener::from_std(s.into());
            }
        }
        return TcpListener::bind(("0.0.0.0", port)).await;
    }
    TcpListener::bind(addr).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries() {
        assert_eq!(query_of("a=1&node=x%20y&b", "node"), "x y");
        assert_eq!(query_of("q=a+b", "q"), "a b");
        assert_eq!(url_decode("100%"), "100%");
        assert_eq!(url_encode("a b&c"), "a+b%26c");
    }
}
