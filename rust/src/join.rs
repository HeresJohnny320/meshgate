//! Join tokens and the join handshake (Go: internal/join).
//!
//! A token carries a random secret plus the addresses and certificate
//! fingerprints of the server nodes that accept it. The join API uses a
//! self-signed certificate pinned by that fingerprint.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hyper::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::gojson::{nullable, zero};
use crate::http::{self, Req, Resp};
use crate::model::{self, Network, Node};
use crate::store::{Entry, Scope, Store};
use crate::tlsx;

const TOKEN_PREFIX: &str = "mg1.";

pub const INSTALL_URL: &str = "https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.sh";
pub const INSTALL_URL_WINDOWS: &str = "https://raw.githubusercontent.com/heresjohnny320/meshgate/main/scripts/install.ps1";

/// One place a token can be redeemed.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Server {
    #[serde(rename = "a")]
    pub addr: String,
    pub fp: String,
}

/// The decoded form of a join token string.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Token {
    pub id: String,
    #[serde(rename = "s")]
    pub secret: String,
    #[serde(rename = "srv", deserialize_with = "nullable")]
    pub servers: Vec<Server>,
}

impl Token {
    pub fn encode(&self) -> String {
        format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(crate::gojson::marshal(self)))
    }
}

pub fn decode(s: &str) -> Result<Token, String> {
    let s = s.trim();
    let Some(rest) = s.strip_prefix(TOKEN_PREFIX) else {
        return Err("not a meshgate token".into());
    };
    let b = URL_SAFE_NO_PAD.decode(rest).map_err(|e| format!("token: {e}"))?;
    let t: Token = serde_json::from_slice(&b).map_err(|e| format!("token: {e}"))?;
    if t.id.is_empty() || t.secret.is_empty() || t.servers.is_empty() {
        return Err("token is incomplete".into());
    }
    Ok(t)
}

/// A random secret and its stored hash.
pub fn new_secret() -> (String, String) {
    let secret = URL_SAFE_NO_PAD.encode(crate::util::random_bytes::<24>());
    let hash = hash_secret(&secret);
    (secret, hash)
}

pub fn hash_secret(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

/// Compares a secret with a stored hash in constant time.
pub fn check_secret(secret: &str, hash: &str) -> bool {
    let h = hash_secret(secret);
    h.len() == hash.len() && bool::from(h.as_bytes().ct_eq(hash.as_bytes()))
}

/// A short random hex ID.
pub fn random_id() -> String {
    hex::encode(crate::util::random_bytes::<6>())
}

/// Copy-paste install-and-join commands: Linux, pfSense, Windows.
pub fn install_commands(token: &str) -> (String, String, String) {
    (
        format!("curl -fsSL {INSTALL_URL} | sudo sh -s -- join {token}"),
        format!("fetch -qo - {INSTALL_URL} | sh -s -- join {token}"),
        format!("& ([scriptblock]::Create((irm {INSTALL_URL_WINDOWS}))) join {token}"),
    )
}

/// Sent by a device that wants to join.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Request {
    pub token_id: String,
    pub secret: String,
    pub name: String,
    pub kind: String,
    pub public_key: String,
    #[serde(skip_serializing_if = "zero", deserialize_with = "nullable")]
    pub endpoints: Vec<String>,
    #[serde(skip_serializing_if = "zero", deserialize_with = "nullable")]
    pub routes: Vec<String>,
    #[serde(skip_serializing_if = "zero")]
    pub relay: bool,
    #[serde(skip_serializing_if = "zero")]
    pub listen_port: i64,
    #[serde(skip_serializing_if = "zero")]
    pub join_addr: String,
    #[serde(skip_serializing_if = "zero")]
    pub join_fp: String,
    #[serde(skip_serializing_if = "zero")]
    pub webui: bool,
    #[serde(skip_serializing_if = "zero")]
    pub lan_policy: String,
    #[serde(skip_serializing_if = "zero")]
    pub mesh_port: i64,
    #[serde(skip_serializing_if = "zero")]
    pub web_port: i64,
}

/// Tells the device who it is and seeds its store.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Response {
    pub node: Node,
    pub network: Network,
    #[serde(deserialize_with = "nullable")]
    pub entries: Vec<Entry>,
    #[serde(skip_serializing_if = "zero")]
    pub api_secret: String,
}

/// Body of /v1/client/sync in both directions.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientSync {
    pub since: u64,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub entries: Vec<Entry>,
}

/// Whether a record of key may be sent to a node of kind.
pub fn visible_to(kind: &str, key: &str) -> bool {
    if kind == model::NODE_SERVER {
        return true;
    }
    let (k, _) = model::split_key(key);
    k == model::KIND_NETWORK || k == model::KIND_NODE || k == model::KIND_STATUS
}

/// Entries visible to kind.
pub fn filter(kind: &str, input: Vec<Entry>) -> Vec<Entry> {
    if kind == model::NODE_SERVER {
        return input;
    }
    input.into_iter().filter(|e| visible_to(kind, &e.key)).collect()
}

/// What node n may see: a client also sees the access rules that name it;
/// any other rule reaches it only as a deletion.
pub fn filter_for(n: &Node, input: Vec<Entry>) -> Vec<Entry> {
    if n.kind == model::NODE_SERVER {
        return input;
    }
    let acls: Vec<Entry> = input.iter().filter(|e| model::split_key(&e.key).0 == model::KIND_ACL).cloned().collect();
    let mut out = filter(&n.kind, input);
    for e in acls {
        let names =
            !e.deleted && serde_json::from_str::<model::Acl>(e.value_str()).is_ok_and(|a| a.from.is_empty() || a.from.contains(&n.id));
        if names {
            out.push(e);
        } else {
            out.push(Entry { key: e.key, value: None, deleted: true, version: e.version, origin: e.origin, seq: e.seq });
        }
    }
    out
}

static ALLOC: Mutex<()> = Mutex::new(());

/// Validates a join request against the store and registers the node.
pub fn admit(s: &Store, mut req: Request, now: i64) -> Result<Response, String> {
    let _g = ALLOC.lock().unwrap();
    let tok: Option<model::Token> = s.get(&model::key(model::KIND_TOKEN, &req.token_id));
    let Some(mut tok) = tok.filter(|t| check_secret(&req.secret, &t.secret_hash)) else {
        return Err("invalid token".into());
    };
    if !tok.usable(now) {
        return Err("token expired or used up".into());
    }
    if req.kind.is_empty() {
        req.kind = tok.kind.clone();
    }
    if req.kind != tok.kind && !(tok.kind == model::NODE_SERVER && req.kind == model::NODE_CLIENT) {
        return Err(format!("this token is for {} nodes", tok.kind));
    }
    register(
        s,
        req,
        now,
        Some(&mut || {
            if tok.uses_left > 0 {
                tok.uses_left -= 1;
            }
            s.put(&model::key(model::KIND_TOKEN, &tok.id), &tok, Scope::Cluster).map(|_| ())
        }),
    )
}

/// Adds a node without a token (used locally by admins).
pub fn register_local(s: &Store, req: Request, now: i64) -> Result<Response, String> {
    let _g = ALLOC.lock().unwrap();
    register(s, req, now, None)
}

/// Whether s is a WireGuard key (base64 of 32 bytes).
pub fn parse_key(s: &str) -> Option<[u8; 32]> {
    STANDARD.decode(s).ok()?.try_into().ok()
}

fn register(s: &Store, mut req: Request, now: i64, consume: Option<&mut dyn FnMut() -> Result<(), String>>) -> Result<Response, String> {
    if parse_key(&req.public_key).is_none() {
        return Err("invalid public key".into());
    }
    req.name = req.name.trim().to_string();
    model::check_name(&req.name)?;
    for ep in &req.endpoints {
        model::check_endpoint(ep)?;
    }
    match req.lan_policy.as_str() {
        "" | model::POLICY_OPEN | model::POLICY_RESTRICTED | model::POLICY_FIREWALL => {}
        _ => return Err("bad lan policy".into()),
    }
    let netw: Network = s.get(&model::key(model::KIND_NETWORK, "main")).ok_or("mesh not initialised")?;
    let nodes: Vec<Node> = s.list(model::KIND_NODE);
    if let Some(n) = nodes.iter().find(|n| n.public_key == req.public_key) {
        // Retried join: the same identity, but only to the kind the token
        // admits (public keys are visible to every device).
        if n.kind != req.kind {
            return Err(format!("this key is already registered as a {} node", n.kind));
        }
        return Ok(snapshot(s, n.clone(), netw));
    }
    if nodes.iter().any(|n| n.name.to_lowercase() == req.name.to_lowercase()) {
        return Err(format!("a node named {:?} already exists", req.name));
    }
    for r in &req.routes {
        if crate::netx::parse_prefix(r).is_none() {
            return Err(format!("bad route {r:?}"));
        }
    }
    let ip = allocate_ip(&netw, &nodes)?;
    let server = req.kind == model::NODE_SERVER;
    let mut n = Node {
        id: random_id(),
        name: req.name,
        relay: req.relay && server,
        kind: req.kind,
        public_key: req.public_key,
        mesh_ip: ip.to_string(),
        listen_port: req.listen_port,
        endpoints: req.endpoints,
        routes: req.routes,
        join_addr: req.join_addr,
        join_fp: req.join_fp,
        webui: req.webui,
        lan_policy: req.lan_policy,
        mesh_port: req.mesh_port,
        web_port: req.web_port,
        created_at: now,
        ..Default::default()
    };
    if !server {
        n.relay = false;
        n.routes = vec![];
        n.join_addr.clear();
        n.join_fp.clear();
        n.webui = false;
    }
    let mut api_secret = String::new();
    if n.kind == model::NODE_CLIENT {
        let (sec, hash) = new_secret();
        api_secret = sec;
        n.api_hash = hash;
    }
    if let Some(c) = consume {
        c()?;
    }
    s.put(&model::key(model::KIND_NODE, &n.id), &n, Scope::Cluster)?;
    let mut resp = snapshot(s, n, netw);
    resp.api_secret = api_secret;
    Ok(resp)
}

fn snapshot(s: &Store, n: Node, netw: Network) -> Response {
    let all = s.since(0).0;
    let entries = filter_for(&n, all);
    Response { node: n, network: netw, entries, api_secret: String::new() }
}

/// A random free address in the mesh.
pub fn allocate_ip(netw: &Network, nodes: &[Node]) -> Result<Ipv4Addr, String> {
    let pfx = netw.prefix()?;
    let IpAddr::V4(base) = pfx.masked().addr else {
        return Err("mesh must be an IPv4 /30 or larger".into());
    };
    if pfx.bits > 30 {
        return Err("mesh must be an IPv4 /30 or larger".into());
    }
    let used: HashSet<Ipv4Addr> = nodes.iter().filter_map(|n| crate::netx::parse_addr4(&n.mesh_ip)).collect();
    let size = 1u64 << (32 - pfx.bits);
    let b = u32::from(base) as u64;
    for _ in 0..64 {
        let a = Ipv4Addr::from((b + 1 + crate::util::random_below(size - 2)) as u32);
        if !used.contains(&a) {
            return Ok(a);
        }
    }
    for off in 1..size - 1 {
        let a = Ipv4Addr::from((b + off) as u32);
        if !used.contains(&a) {
            return Ok(a);
        }
    }
    Err("mesh address space is full".into())
}

/// Serves POST /v1/join and POST /v1/client/sync; None for other paths.
pub async fn handle(s: &Store, req: Req) -> Option<Resp> {
    let path = req.uri().path().to_string();
    if path != "/v1/join" && path != "/v1/client/sync" {
        return None;
    }
    if req.method() != Method::POST {
        return Some(http::method_not_allowed());
    }
    if path == "/v1/join" {
        let r: Request = match http::decode(req, 1 << 16).await {
            Ok(r) => r,
            Err(e) => return Some(*e),
        };
        return Some(match admit(s, r, crate::util::now_unix()) {
            Ok(resp) => http::ok_json(&resp),
            Err(e) => {
                tokio::time::sleep(Duration::from_millis(500)).await; // slow down guessing
                http::error(StatusCode::FORBIDDEN, e)
            }
        });
    }
    let auth = req.headers().get("Authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let Some(node) = auth_client(s, &auth) else {
        tokio::time::sleep(Duration::from_millis(500)).await;
        return Some(http::error(StatusCode::UNAUTHORIZED, "unauthorized"));
    };
    let body: ClientSync = match http::decode(req, 1 << 20).await {
        Ok(r) => r,
        Err(e) => return Some(*e),
    };
    // A client may only publish its own status.
    let own = model::key(model::KIND_STATUS, &node.id);
    let accepted: Vec<Entry> = body.entries.into_iter().filter(|e| e.key == own && e.origin == node.id).collect();
    let _ = s.merge(accepted);
    let (entries, seq) = s.since(body.since);
    Some(http::ok_json(&ClientSync { entries: filter_for(&node, entries), since: seq }))
}

/// Checks "Bearer <node id>:<secret>".
fn auth_client(s: &Store, h: &str) -> Option<Node> {
    let cred = h.strip_prefix("Bearer ")?;
    let (id, secret) = cred.split_once(':')?;
    let n: Node = s.get(&model::key(model::KIND_NODE, id))?;
    (n.kind == model::NODE_CLIENT && !n.api_hash.is_empty() && check_secret(secret, &n.api_hash)).then_some(n)
}

/// One client sync round against a server's join API.
pub async fn sync_client(srv: &Server, node_id: &str, secret: &str, body: &ClientSync) -> Result<ClientSync, String> {
    sync_client_hooked(srv, node_id, secret, body, None).await
}

/// sync_client with a socket hook (phones keep it outside their VPN).
pub async fn sync_client_hooked(
    srv: &Server,
    node_id: &str,
    secret: &str,
    body: &ClientSync,
    hook: Option<&crate::util::SockHook>,
) -> Result<ClientSync, String> {
    let auth = format!("Bearer {node_id}:{secret}");
    let res = http::tls_hooked(
        &srv.addr,
        &http::host_of(&srv.addr),
        tlsx::pinned(&srv.fp),
        Method::POST,
        "/v1/client/sync",
        &[("Content-Type", "application/json"), ("Authorization", &auth)],
        crate::gojson::marshal(body).into(),
        Duration::from_secs(10),
        hook,
    )
    .await?;
    if res.status != StatusCode::OK {
        return Err(format!("sync: {}", res.status_line()));
    }
    http::first_json(&res.body).map_err(|e| e.to_string())
}

/// Redeems a token against the first server that answers.
pub async fn redeem(tok: &Token, req: Request) -> Result<Response, String> {
    redeem_hooked(tok, req, None).await
}

/// redeem with a socket hook.
pub async fn redeem_hooked(tok: &Token, mut req: Request, hook: Option<&crate::util::SockHook>) -> Result<Response, String> {
    req.token_id = tok.id.clone();
    req.secret = tok.secret.clone();
    let body = bytes::Bytes::from(crate::gojson::marshal(&req));
    let mut last = String::from("no servers in token");
    for srv in &tok.servers {
        match do_one(srv, body.clone(), hook).await {
            Ok(r) => return Ok(r),
            Err((msg, permanent)) => {
                last = format!("{}: {msg}", srv.addr);
                if permanent {
                    break;
                }
            }
        }
    }
    Err(last)
}

async fn do_one(srv: &Server, body: bytes::Bytes, hook: Option<&crate::util::SockHook>) -> Result<Response, (String, bool)> {
    let res = http::tls_hooked(
        &srv.addr,
        &http::host_of(&srv.addr),
        tlsx::pinned(&srv.fp),
        Method::POST,
        "/v1/join",
        &[("Content-Type", "application/json")],
        body,
        Duration::from_secs(15),
        hook,
    )
    .await
    .map_err(|e| (e, false))?;
    if res.status != StatusCode::OK {
        let msg = String::from_utf8_lossy(&res.body[..res.body.len().min(512)]).trim().to_string();
        return Err((msg, true));
    }
    http::first_json(&res.body).map_err(|e| (e.to_string(), false))
}

/// Loads or creates the join API certificate; returns it with its
/// fingerprint.
pub fn ensure_cert(cert: &Path, key: &Path) -> Result<(tlsx::KeyPair, String), String> {
    if let Ok(kp) = tlsx::KeyPair::load(cert, key) {
        let fp = kp.fingerprint();
        return Ok((kp, fp));
    }
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    let mut p = rcgen::CertificateParams::default();
    p.serial_number = Some(tlsx::serial(62));
    p.distinguished_name = rcgen::DistinguishedName::new();
    p.distinguished_name.push(rcgen::DnType::CommonName, "meshgate-join");
    let now = crate::util::now_unix();
    p.not_before = tlsx::date(now - 3600);
    p.not_after = tlsx::date(now + 20 * 365 * 86400 + 5 * 86400);
    p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let c = p.self_signed(&kp).map_err(|e| e.to_string())?;
    crate::config::write_mode(cert, c.pem().as_bytes(), 0o644).map_err(|e| e.to_string())?;
    crate::config::write_private(key, kp.serialize_pem().as_bytes()).map_err(|e| e.to_string())?;
    let kp = tlsx::KeyPair::load(cert, key)?;
    let fp = kp.fingerprint();
    Ok((kp, fp))
}

/// Creates and stores a token, returning its string form.
pub fn new_token(s: &Store, kind: &str, uses: i64, ttl_secs: i64, note: &str, now: i64) -> Result<(String, model::Token), String> {
    let servers: Vec<Server> = s
        .list::<Node>(model::KIND_NODE)
        .into_iter()
        .filter(|n| n.kind == model::NODE_SERVER && !n.join_addr.is_empty() && !n.join_fp.is_empty())
        .map(|n| Server { addr: n.join_addr, fp: n.join_fp })
        .collect();
    if servers.is_empty() {
        return Err(
            "no server node accepts joins yet: run `meshgate init` on a VPS (public IP) so it becomes a relay with a join address".into()
        );
    }
    let (secret, hash) = new_secret();
    let mut t = model::Token {
        id: random_id(),
        secret_hash: hash,
        kind: kind.into(),
        uses_left: uses,
        note: note.into(),
        created_at: now,
        ..Default::default()
    };
    if ttl_secs > 0 {
        t.expires_at = now + ttl_secs;
    }
    s.put(&model::key(model::KIND_TOKEN, &t.id), &t, Scope::Cluster)?;
    Ok((Token { id: t.id.clone(), secret, servers }.encode(), t))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn new_mesh() -> Store {
        let s = Store::memory("srv");
        s.put("network/main", &Network { cidr: "100.88.0.0/16".into(), ..Default::default() }, Scope::Cluster).unwrap();
        let n = Node {
            id: "srv".into(),
            name: "vps".into(),
            kind: model::NODE_SERVER.into(),
            mesh_ip: "100.88.0.1".into(),
            join_addr: "x:1".into(),
            join_fp: "ab".into(),
            relay: true,
            endpoints: vec!["1.1.1.1:51820".into()],
            ..Default::default()
        };
        s.put("node/srv", &n, Scope::Cluster).unwrap();
        s.put("admin/admin", &model::Admin { username: "admin".into(), password_hash: "secret-hash".into() }, Scope::Cluster).unwrap();
        s
    }

    fn pubkey() -> String {
        STANDARD.encode(crate::util::random_bytes::<32>())
    }

    fn req(t: &Token, name: &str, kind: &str) -> Request {
        Request {
            token_id: t.id.clone(),
            secret: t.secret.clone(),
            name: name.into(),
            kind: kind.into(),
            public_key: pubkey(),
            ..Default::default()
        }
    }

    #[test]
    fn token_lifecycle() {
        let s = new_mesh();
        let now = crate::util::now_unix();
        let (str_, _) = new_token(&s, model::NODE_CLIENT, 1, 3600, "", now).unwrap();
        let tok = decode(&str_).unwrap();
        let mut bad = req(&tok, "x", "");
        bad.secret = "wrong".into();
        assert!(admit(&s, bad, now).is_err(), "wrong secret accepted");
        assert!(admit(&s, req(&tok, "box", model::NODE_SERVER), now).is_err(), "client token admitted a server");
        let resp = admit(&s, req(&tok, "phone", ""), now).unwrap();
        assert!(resp.node.kind == model::NODE_CLIENT && !resp.api_secret.is_empty() && !resp.node.mesh_ip.is_empty());
        for e in &resp.entries {
            let k = model::split_key(&e.key).0;
            assert!(k != model::KIND_ADMIN && k != model::KIND_TOKEN, "client received {}", e.key);
        }
        assert!(admit(&s, req(&tok, "phone2", ""), now).is_err(), "single-use token reused");
        let (exp, _) = new_token(&s, model::NODE_CLIENT, 5, 60, "", now).unwrap();
        let et = decode(&exp).unwrap();
        assert!(admit(&s, req(&et, "late", ""), now + 120).is_err(), "expired token accepted");
    }

    #[test]
    fn allocate_ip_avoids_used() {
        let netw = Network { cidr: "10.9.0.0/30".into(), ..Default::default() };
        let one = |ip: &str| Node { mesh_ip: ip.into(), ..Default::default() };
        assert_eq!(allocate_ip(&netw, &[one("10.9.0.1")]).unwrap().to_string(), "10.9.0.2");
        assert!(allocate_ip(&netw, &[one("10.9.0.1"), one("10.9.0.2")]).is_err());
    }

    #[test]
    fn token_string_matches_go() {
        // Encoded by the Go build: {"id":"abc","s":"sec","srv":[{"a":"1.2.3.4:51821","fp":"ff"}]}
        let go = "mg1.eyJpZCI6ImFiYyIsInMiOiJzZWMiLCJzcnYiOlt7ImEiOiIxLjIuMy40OjUxODIxIiwiZnAiOiJmZiJ9XX0";
        let t = decode(go).unwrap();
        assert_eq!(t.servers[0].addr, "1.2.3.4:51821");
        assert_eq!(t.encode(), go);
    }

    #[tokio::test]
    async fn join_and_client_sync_over_tls() {
        let s = Arc::new(new_mesh());
        let dir = tempfile::tempdir().unwrap();
        let (kp, fp) = ensure_cert(&dir.path().join("c.crt"), &dir.path().join("c.key")).unwrap();
        // Loading again keeps the same certificate.
        assert_eq!(ensure_cert(&dir.path().join("c.crt"), &dir.path().join("c.key")).unwrap().1, fp);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let acc = tokio_rustls::TlsAcceptor::from(kp.server_config(&[]).unwrap());
        let st = s.clone();
        let h: Arc<dyn http::Handler> = Arc::new(move |r: Req, _p: http::Peer| {
            let st = st.clone();
            async move { handle(&st, r).await.unwrap_or_else(http::not_found) }
        });
        tokio::spawn(http::serve(l, Some(acc), h));

        let now = crate::util::now_unix();
        let (str_, _) = new_token(&s, model::NODE_CLIENT, 1, 0, "", now).unwrap();
        let mut tok = decode(&str_).unwrap();
        tok.servers = vec![Server { addr: addr.clone(), fp: fp.clone() }];
        let r = Request { name: "phone".into(), kind: model::NODE_CLIENT.into(), public_key: pubkey(), ..Default::default() };
        let resp = redeem(&tok, r).await.unwrap();

        let mut bad = tok.clone();
        bad.servers = vec![Server { addr: addr.clone(), fp: "00".into() }];
        let r = Request { name: "x".into(), public_key: pubkey(), ..Default::default() };
        assert!(redeem(&bad, r).await.is_err(), "pinning not enforced");

        let id = resp.node.id.clone();
        let raw = |s: String| Some(serde_json::value::RawValue::from_string(s).unwrap());
        let status = Entry {
            key: format!("status/{id}"),
            value: raw(format!(r#"{{"node_id":"{id}","home_relay":"srv"}}"#)),
            version: 1 << 60,
            origin: id.clone(),
            ..Default::default()
        };
        let evil =
            Entry { key: "forward/evil".into(), value: raw("{}".into()), version: 1 << 60, origin: id.clone(), ..Default::default() };
        let srv = Server { addr: addr.clone(), fp: fp.clone() };
        let out = sync_client(&srv, &id, &resp.api_secret, &ClientSync { entries: vec![status, evil], since: 0 }).await.unwrap();
        assert!(out.since != 0 && !out.entries.is_empty());
        let got: model::Status = s.get(&format!("status/{id}")).expect("status not stored");
        assert_eq!(got.home_relay, "srv");
        assert!(s.raw("forward/evil").is_none(), "client wrote config");
        assert!(sync_client(&srv, &id, "wrong", &ClientSync::default()).await.is_err(), "bad secret accepted");
    }

    #[test]
    fn retried_join_cannot_borrow_server_identity() {
        let s = new_mesh();
        let server_key = pubkey();
        let mut n: Node = s.get("node/srv").unwrap();
        n.public_key = server_key.clone();
        s.put("node/srv", &n, Scope::Cluster).unwrap();
        let now = crate::util::now_unix();
        let (str_, _) = new_token(&s, model::NODE_CLIENT, 5, 3600, "", now).unwrap();
        let tok = decode(&str_).unwrap();
        let mut r = req(&tok, "evil", "");
        r.public_key = server_key;
        assert!(admit(&s, r, now).is_err(), "phone token returned the server's identity");
    }

    #[test]
    fn join_rejects_bad_input() {
        let s = new_mesh();
        let now = crate::util::now_unix();
        let (str_, _) = new_token(&s, model::NODE_SERVER, 10, 3600, "", now).unwrap();
        let tok = decode(&str_).unwrap();
        let cases: Vec<Request> = vec![
            Request { name: "evil\x1b[2Jname".into(), ..Default::default() },
            Request { name: "rtl\u{202e}txt.exe".into(), ..Default::default() },
            Request { name: "ok".into(), endpoints: vec!["1.2.3.4:51820\nallowed_ip=0.0.0.0/0".into()], ..Default::default() },
            Request { name: "ok2".into(), endpoints: vec!["1.2.3.4:99999".into()], ..Default::default() },
            Request { name: "ok3".into(), lan_policy: "wide-open".into(), ..Default::default() },
        ];
        for mut r in cases {
            r.token_id = tok.id.clone();
            r.secret = tok.secret.clone();
            r.public_key = pubkey();
            r.kind = model::NODE_SERVER.into();
            let name = r.name.clone();
            assert!(admit(&s, r, now).is_err(), "accepted {name:?}");
        }
    }

    #[test]
    fn client_sees_only_its_rules() {
        let enc = |a: model::Acl| Entry {
            key: format!("acl/{}", a.id),
            value: Some(serde_json::value::RawValue::from_string(serde_json::to_string(&a).unwrap()).unwrap()),
            version: 7,
            origin: "srv".into(),
            ..Default::default()
        };
        let input = vec![
            enc(model::Acl { id: "mine".into(), from: vec!["phone".into()], ..Default::default() }),
            enc(model::Acl { id: "all".into(), ..Default::default() }),
            enc(model::Acl { id: "other".into(), from: vec!["laptop".into()], ..Default::default() }),
            Entry {
                key: "admin/admin".into(),
                value: Some(serde_json::value::RawValue::from_string("{}".into()).unwrap()),
                ..Default::default()
            },
        ];
        let phone = Node { id: "phone".into(), kind: model::NODE_CLIENT.into(), ..Default::default() };
        let got: std::collections::HashMap<String, bool> = filter_for(&phone, input).into_iter().map(|e| (e.key, e.deleted)).collect();
        assert!(!got.contains_key("admin/admin"));
        assert!(!got["acl/mine"] && !got["acl/all"] && got["acl/other"], "{got:?}");
    }
}
