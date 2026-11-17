//! meshgate's built-in test kit (Go: internal/diag): a test service on one
//! TCP+UDP port, and checks run from this node (ping, traceroute, TCP, UDP,
//! HTTP/HTTPS, public IP).

use std::sync::Arc;
use std::time::{Duration, Instant};

use hyper::StatusCode;
use serde::{Deserialize, Serialize};

use crate::gojson::zero;
use crate::http::{self, Peer, Req};

/// The smallest UDP request the test service answers (no amplification).
pub const UDP_MIN: usize = 64;

pub fn udp_probe() -> String {
    format!("meshgate?{}", " ".repeat(UDP_MIN))
}

/// Answers with the caller's public IP in plain text.
pub fn myip_url() -> String {
    std::env::var("MESHGATE_MYIP_URL").unwrap_or_else(|_| "https://api.ipify.org".into())
}

/// Runs the test service on port (all interfaces) until the task is
/// dropped: HTTP on TCP, a one-line echo on UDP.
pub async fn serve(port: u16, node: String) -> Result<(), String> {
    let ln = http::listen(&format!(":{port}")).await.map_err(|e| format!("listen tcp :{port}: {e}"))?;
    let pc = tokio::net::UdpSocket::bind(("0.0.0.0", port)).await.map_err(|e| format!("listen udp :{port}: {e}"))?;
    let name = node.clone();
    let udp = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let Ok((n, from)) = pc.recv_from(&mut buf).await else { return };
            if n >= UDP_MIN {
                let mut reply = format!("meshgate test service on {name}: you are {from}\n").into_bytes();
                reply.truncate(n);
                let _ = pc.send_to(&reply, from).await;
            }
        }
    });
    struct Abort(tokio::task::JoinHandle<()>);
    impl Drop for Abort {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _udp = Abort(udp);
    let h: Arc<dyn http::Handler> = Arc::new(move |r: Req, p: Peer| {
        let node = node.clone();
        async move {
            let mut s = format!(
                "meshgate test service: it works\n\nnode:      {node}\nyou are:   {}\nhost:      {}\nprotocol:  {:?}\n",
                p.addr.map(|a| a.to_string()).unwrap_or_default(),
                r.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or(""),
                r.version()
            );
            if let Some(v) = r.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
                let proto = r.headers().get("x-forwarded-proto").and_then(|v| v.to_str().ok()).unwrap_or("");
                s.push_str(&format!("forwarded for: {v} (HTTPS route; original {proto})\n"));
            }
            s.push_str(&format!("time:      {}\n", rfc3339_local(crate::util::now_unix())));
            let mut res = http::resp(StatusCode::OK, "text/plain; charset=utf-8", s);
            res.headers_mut().insert("Cache-Control", hyper::header::HeaderValue::from_static("no-store"));
            res
        }
    });
    http::serve(ln, None, h).await;
    Ok(())
}

/// time.RFC3339 in local time.
fn rfc3339_local(t: i64) -> String {
    crate::util::go_time(t, 0)
}

/// One diagnostic request.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Check {
    pub kind: String,
    pub target: String,
    #[serde(skip_serializing_if = "zero")]
    pub port: i64,
}

/// A check's outcome; output is human-readable.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Outcome {
    pub ok: bool,
    pub output: String,
}

fn fail(s: impl Into<String>) -> Outcome {
    Outcome { ok: false, output: s.into() }
}

/// `^[A-Za-z0-9][A-Za-z0-9.\-:]*$`
fn host_ok(s: &str) -> bool {
    let mut c = s.chars();
    c.next().is_some_and(|f| f.is_ascii_alphanumeric()) && c.all(|x| x.is_ascii_alphanumeric() || x == '.' || x == '-' || x == ':')
}

/// Performs c from this node.
pub async fn run(c: Check) -> Outcome {
    let target = c.target.trim().to_string();
    if c.kind == "myip" {
        return match public_ip().await {
            Ok(ip) => Outcome { ok: true, output: format!("Websites see this device as {ip}") },
            Err(e) => fail(format!("could not get the public IP: {e}")),
        };
    }
    if c.kind != "http" && !host_ok(&target) {
        return fail("enter a host name or IP address");
    }
    match c.kind.as_str() {
        "ping" => command(Duration::from_secs(20), ping_args(&target)).await,
        "trace" => command(Duration::from_secs(60), trace_args(&target)).await,
        "tcp" => tcp_check(&target, c.port).await,
        "udp" => udp_check(&target, c.port).await,
        "http" => http_check(&target).await,
        k => fail(format!("unknown check {k}")),
    }
}

/// Which address our traffic leaves from.
pub async fn public_ip() -> Result<String, String> {
    let r =
        crate::httpc::fetch(&myip_url(), &crate::httpc::Opts { timeout: Duration::from_secs(10), limit: 64, ..Default::default() }).await?;
    let ip = String::from_utf8_lossy(&r.body).trim().to_string();
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Err(format!("unexpected answer {ip:?}"));
    }
    Ok(ip)
}

fn ping_args(host: &str) -> Vec<String> {
    let n = if cfg!(windows) { "-n" } else { "-c" };
    ["ping", n, "4", host].map(String::from).to_vec()
}

fn trace_args(host: &str) -> Vec<String> {
    let v: Vec<&str> = if cfg!(windows) {
        vec!["tracert", "-d", "-h", "20", host]
    } else if crate::util::look_path("traceroute") {
        vec!["traceroute", "-n", "-q", "1", "-w", "2", "-m", "20", host]
    } else if crate::util::look_path("tracepath") {
        vec!["tracepath", "-n", "-m", "20", host]
    } else {
        vec!["traceroute", host]
    };
    v.into_iter().map(String::from).collect()
}

async fn command(limit: Duration, args: Vec<String>) -> Outcome {
    if !crate::util::look_path(&args[0]) {
        return fail(format!("{} is not installed on this node", args[0]));
    }
    let mut cmd = tokio::process::Command::new(&args[0]);
    cmd.args(&args[1..]).stdin(std::process::Stdio::null()).kill_on_drop(true);
    let out = tokio::time::timeout(limit, cmd.output()).await;
    let timed_out = out.is_err();
    let (ok, mut s) = match out {
        Ok(Ok(o)) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.success(), s.trim().to_string())
        }
        Ok(Err(e)) => (false, e.to_string()),
        Err(_) => (false, String::new()),
    };
    if timed_out {
        s.push_str(&format!("\n(stopped after {}s)", limit.as_secs()));
    }
    Outcome { ok, output: format!("$ {}\n{s}", args.join(" ")) }
}

async fn tcp_check(host: &str, port: i64) -> Outcome {
    if !(1..=65535).contains(&port) {
        return fail("enter a port");
    }
    let addr = crate::netx::join_host_port(host, port);
    let start = Instant::now();
    match http::dial(&addr, Duration::from_secs(5)).await {
        Err(e) => fail(format!("TCP {addr}: not reachable ({e})")),
        Ok(_) => Outcome { ok: true, output: format!("TCP {addr}: open, connected in {}", ms(start.elapsed())) },
    }
}

async fn udp_check(host: &str, port: i64) -> Outcome {
    if !(1..=65535).contains(&port) {
        return fail("enter a port");
    }
    let addr = crate::netx::join_host_port(host, port);
    let target = match tokio::net::lookup_host(&addr).await.ok().and_then(|mut a| a.next()) {
        Some(t) => t,
        None => return fail(format!("UDP {addr}: dial udp {addr}: lookup failed")),
    };
    let bind = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let Ok(c) = tokio::net::UdpSocket::bind(bind).await else { return fail(format!("UDP {addr}: cannot open a socket")) };
    if let Err(e) = c.connect(target).await {
        return fail(format!("UDP {addr}: {e}"));
    }
    let start = Instant::now();
    let _ = c.send(udp_probe().as_bytes()).await;
    let mut buf = [0u8; 512];
    match tokio::time::timeout(Duration::from_secs(3), c.recv(&mut buf)).await {
        Ok(Ok(n)) => Outcome {
            ok: true,
            output: format!("UDP {addr}: answered in {}\n{}", ms(start.elapsed()), String::from_utf8_lossy(&buf[..n]).trim()),
        },
        _ => fail(format!(
            "UDP {addr}: no answer within 3s. UDP has no handshake, so this only works against a meshgate test service (or another service that replies)."
        )),
    }
}

/// Go's Duration.Round(time.Millisecond).String() for short durations.
pub fn ms(d: Duration) -> String {
    let m = d.as_millis();
    if m < 1000 { format!("{m}ms") } else { format!("{}s", m as f64 / 1000.0) }
}

async fn http_check(raw: &str) -> Outcome {
    let mut raw = raw.to_string();
    if !raw.contains("://") {
        raw = format!("https://{raw}");
    }
    if crate::httpc::Url::parse(&raw).is_none() {
        return fail("enter an http:// or https:// address");
    }
    let start = Instant::now();
    let opts = crate::httpc::Opts { timeout: Duration::from_secs(15), limit: 600, ..Default::default() };
    let res = match crate::httpc::fetch(&raw, &opts).await {
        Ok(r) => r,
        Err(e) => return fail(format!("GET {raw}: {e}")),
    };
    let mut b = format!("GET {}\nstatus:  {} in {}\n", res.url, res.status_line(), ms(start.elapsed()));
    let server = res.header("server");
    if !server.is_empty() {
        b.push_str(&format!("server:  {server}\n"));
    }
    if let Some(t) = &res.tls
        && let Ok((_, crt)) = x509_parser::parse_x509_certificate(&t.peer_cert)
    {
        let names: Vec<String> = crt
            .subject_alternative_name()
            .ok()
            .flatten()
            .map(|s| {
                s.value
                    .general_names
                    .iter()
                    .filter_map(|n| match n {
                        x509_parser::extensions::GeneralName::DNSName(d) => Some(d.to_string()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let issuer = crt.issuer().iter_common_name().next().and_then(|c| c.as_str().ok()).unwrap_or("").to_string();
        let exp = crt.validity().not_after.timestamp();
        let (y, m, d, ..) = crate::logx::utc(exp);
        b.push_str(&format!(
            "tls:     {}, certificate for {}\nissuer:  {issuer}\nexpires: {y:04}-{m:02}-{d:02} ({} days)\n",
            t.version,
            names.join(", "),
            (exp - crate::util::now_unix()) / 86400
        ));
    }
    b.push_str(&format!("\n{}", String::from_utf8_lossy(&res.body).trim()));
    Outcome { ok: res.status.as_u16() < 400, output: b }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_service_answers_tcp_and_udp() {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let srv = tokio::spawn(serve(port, "home".into()));
        tokio::time::sleep(Duration::from_millis(100)).await;
        let r = run(Check { kind: "tcp".into(), target: "127.0.0.1".into(), port: port as i64 }).await;
        assert!(r.ok, "{}", r.output);
        let r = run(Check { kind: "udp".into(), target: "127.0.0.1".into(), port: port as i64 }).await;
        assert!(r.ok && r.output.contains("meshgate test service on home"), "{}", r.output);
        let r = run(Check { kind: "http".into(), target: format!("http://127.0.0.1:{port}/"), port: 0 }).await;
        assert!(r.ok && r.output.contains("node:      home"), "{}", r.output);
        assert!(!run(Check { kind: "ping".into(), target: "-rf".into(), port: 0 }).await.ok);
        assert!(!run(Check { kind: "tcp".into(), target: "x".into(), port: 0 }).await.ok);
        srv.abort();
    }

    #[tokio::test]
    async fn short_udp_requests_get_no_answer() {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let srv = tokio::spawn(serve(port, "n".into()));
        tokio::time::sleep(Duration::from_millis(100)).await;
        let c = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        c.connect(("127.0.0.1", port)).await.unwrap();
        c.send(b"short").await.unwrap();
        let mut b = [0u8; 100];
        assert!(tokio::time::timeout(Duration::from_millis(300), c.recv(&mut b)).await.is_err());
        srv.abort();
    }
}
