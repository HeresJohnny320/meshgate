//! The records that make up a meshgate network (Go: internal/model).
//!
//! Every record is stored in the replicated store under "<kind>/<id>" as
//! JSON; field names and omitted-when-empty rules match Go exactly.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::gojson::{nullable, zero};
use crate::netx::{self, Prefix};

pub const KIND_NETWORK: &str = "network";
pub const KIND_NODE: &str = "node";
pub const KIND_STATUS: &str = "status";
pub const KIND_FORWARD: &str = "forward";
pub const KIND_ROUTE: &str = "httproute";
pub const KIND_TOKEN: &str = "token";
pub const KIND_ADMIN: &str = "admin";
pub const KIND_ACL: &str = "acl";
pub const KIND_EXIT_ROUTE: &str = "exitroute";
pub const KIND_MONITOR: &str = "monitor";

/// Node kinds (Go `NodeKind` is a string type; unknown values are kept).
pub const NODE_SERVER: &str = "server";
pub const NODE_CLIENT: &str = "client";
pub const NODE_STATIC: &str = "static";

pub const DEFAULT_WG_PORT: i64 = 51820;
pub const DEFAULT_JOIN_PORT: i64 = 51821;
pub const DEFAULT_PROBE_PORT: i64 = 51822;
pub const DEFAULT_MESH_PORT: i64 = 51823;
pub const DEFAULT_WEB_PORT: i64 = 8080;

pub const PROTO_TCP: &str = "tcp";
pub const PROTO_UDP: &str = "udp";
pub const PROTO_BOTH: &str = "both";

pub const POLICY_OPEN: &str = "open";
pub const POLICY_RESTRICTED: &str = "restricted";
pub const POLICY_FIREWALL: &str = "firewall";

/// ACL destination meaning "the enforcing node itself".
pub const TO_SELF: &str = "self";

pub type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Network {
    pub name: String,
    pub cidr: String,
    pub acme_email: String,
    pub created_at: i64,
    #[serde(skip_serializing_if = "zero")]
    pub log_server: String,
    #[serde(skip_serializing_if = "zero")]
    pub log_days: i64,
}

impl Network {
    pub fn history_days(&self) -> i64 {
        if self.log_days > 0 { self.log_days } else { 365 }
    }

    pub fn prefix(&self) -> Result<Prefix> {
        netx::parse_prefix(&self.cidr).ok_or_else(|| format!("netip.ParsePrefix({:?}): invalid prefix", self.cidr))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Node {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub public_key: String,
    pub mesh_ip: String,
    #[serde(skip_serializing_if = "zero")]
    pub listen_port: i64,
    #[serde(skip_serializing_if = "zero", deserialize_with = "nullable")]
    pub endpoints: Vec<String>,
    #[serde(skip_serializing_if = "zero")]
    pub relay: bool,
    #[serde(skip_serializing_if = "zero", deserialize_with = "nullable")]
    pub routes: Vec<String>,
    #[serde(skip_serializing_if = "zero")]
    pub lan_policy: String,
    #[serde(skip_serializing_if = "zero")]
    pub via_relay: String,
    #[serde(skip_serializing_if = "zero")]
    pub exit: bool,
    #[serde(skip_serializing_if = "zero")]
    pub exit_via: String,
    #[serde(skip_serializing_if = "zero", deserialize_with = "nullable")]
    pub lan_exits: Vec<LanExit>,
    #[serde(skip_serializing_if = "zero", deserialize_with = "nullable")]
    pub exits_allowed: Vec<String>,
    #[serde(skip_serializing_if = "zero")]
    pub exit_only: bool,
    #[serde(skip_serializing_if = "zero")]
    pub app_admin_off: bool,
    #[serde(skip_serializing_if = "zero")]
    pub beep_off: bool,
    #[serde(skip_serializing_if = "zero")]
    pub iptables_off: bool,
    #[serde(skip_serializing_if = "zero")]
    pub host_firewall_off: bool,
    #[serde(skip_serializing_if = "zero")]
    pub test_port: i64,
    #[serde(skip_serializing_if = "zero")]
    pub join_addr: String,
    #[serde(skip_serializing_if = "zero")]
    pub join_fp: String,
    #[serde(skip_serializing_if = "zero")]
    pub webui: bool,
    #[serde(skip_serializing_if = "zero")]
    pub web_port: i64,
    #[serde(skip_serializing_if = "zero")]
    pub web_tls: bool,
    #[serde(skip_serializing_if = "zero")]
    pub web_fp: String,
    #[serde(skip_serializing_if = "zero")]
    pub web_ca_fp: String,
    #[serde(skip_serializing_if = "zero")]
    pub mesh_port: i64,
    #[serde(skip_serializing_if = "zero")]
    pub api_hash: String,
    pub created_at: i64,
}

impl Node {
    /// May write cluster-wide config.
    pub fn writer(&self) -> bool {
        self.kind == NODE_SERVER
    }
    pub fn restricted(&self) -> bool {
        self.lan_policy == POLICY_RESTRICTED
    }
    pub fn firewall_managed(&self) -> bool {
        self.lan_policy == POLICY_FIREWALL
    }

    /// Whether this node may send internet traffic through exit node `ex`.
    pub fn may_use_exit(&self, ex: &str) -> bool {
        if !self.lan_exits.is_empty() {
            return true;
        }
        if self.exits_allowed.is_empty() {
            return !self.exit_via.is_empty();
        }
        self.exits_allowed.iter().any(|a| a == "*" || a == ex)
    }

    pub fn mesh_port_or_default(&self) -> i64 {
        if self.mesh_port == 0 { DEFAULT_MESH_PORT } else { self.mesh_port }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Status {
    pub node_id: String,
    #[serde(skip_serializing_if = "zero")]
    pub home_relay: String,
    #[serde(skip_serializing_if = "zero", deserialize_with = "nullable")]
    pub paths: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "zero", deserialize_with = "nullable")]
    pub lans: Vec<Lan>,
    #[serde(skip_serializing_if = "zero")]
    pub os: String,
    #[serde(skip_serializing_if = "zero")]
    pub version: String,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Forward {
    pub id: String,
    pub name: String,
    pub proto: String,
    pub edge_node: String,
    pub listen_port: i64,
    #[serde(skip_serializing_if = "zero")]
    pub listen_end: i64,
    pub target_node: String,
    #[serde(skip_serializing_if = "zero")]
    pub target_ip: String,
    pub target_port: i64,
    #[serde(skip_serializing_if = "zero")]
    pub preserve_client_ip: bool,
    pub enabled: bool,
}

impl Forward {
    /// The inclusive listen range.
    pub fn ports(&self) -> (i64, i64) {
        if self.listen_end > self.listen_port { (self.listen_port, self.listen_end) } else { (self.listen_port, self.listen_port) }
    }

    pub fn validate(&self) -> Result<()> {
        match self.proto.as_str() {
            PROTO_TCP | PROTO_UDP | PROTO_BOTH => {}
            _ => return Err("proto must be tcp, udp or both".into()),
        }
        if self.edge_node.is_empty() || self.target_node.is_empty() {
            return Err("edge and target node are required".into());
        }
        if self.edge_node == self.target_node {
            return Err("edge and target must be different nodes".into());
        }
        if !valid_port(self.listen_port) || !valid_port(self.target_port) {
            return Err("ports must be 1-65535".into());
        }
        if self.listen_end != 0 && (self.listen_end < self.listen_port || !valid_port(self.listen_end)) {
            return Err("invalid listen range".into());
        }
        if self.listen_end > self.listen_port && self.target_port != self.listen_port {
            return Err("port ranges are forwarded 1:1, so target port must equal the first listen port".into());
        }
        if !self.target_ip.is_empty() {
            if netx::parse_addr4(&self.target_ip).is_none() {
                return Err("target ip must be an IPv4 address".into());
            }
            if self.preserve_client_ip {
                return Err("preserve client IP only works when the service runs on the target node itself (leave target ip empty)".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpRoute {
    pub id: String,
    pub hostname: String,
    pub edge_node: String,
    pub target_node: String,
    #[serde(skip_serializing_if = "zero")]
    pub target_ip: String,
    pub target_port: i64,
    #[serde(skip_serializing_if = "zero")]
    pub target_tls: bool,
    pub force_https: bool,
    pub enabled: bool,
}

impl HttpRoute {
    pub fn validate(&self) -> Result<()> {
        let h = self.hostname.trim().to_lowercase();
        if h.len() > 253 || !valid_hostname(&h) {
            return Err("hostname must be a DNS name like app.example.com".into());
        }
        if self.edge_node.is_empty() || self.target_node.is_empty() {
            return Err("edge and target node are required".into());
        }
        if !valid_port(self.target_port) {
            return Err("target port must be 1-65535".into());
        }
        if !self.target_ip.is_empty() && netx::parse_addr(&self.target_ip).is_none() {
            return Err("invalid target ip".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Token {
    pub id: String,
    pub secret_hash: String,
    pub kind: String,
    pub uses_left: i64,
    pub expires_at: i64,
    #[serde(skip_serializing_if = "zero")]
    pub note: String,
    pub created_at: i64,
}

impl Token {
    /// Whether the token can still be used at unix time `now`.
    pub fn usable(&self, now: i64) -> bool {
        self.uses_left != 0 && (self.expires_at == 0 || now < self.expires_at)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Admin {
    pub username: String,
    pub password_hash: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Lan {
    pub iface: String,
    pub cidr: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Acl {
    pub id: String,
    pub name: String,
    pub node: String,
    #[serde(skip_serializing_if = "zero", deserialize_with = "nullable")]
    pub from: Vec<String>,
    pub to: String,
    pub proto: String,
    #[serde(skip_serializing_if = "zero")]
    pub ports: String,
    pub enabled: bool,
}

/// Splits "80, 443,8000-8100" into its single ports and ranges.
pub fn port_list(ports: &str) -> Vec<String> {
    ports.split(',').map(str::trim).filter(|p| !p.is_empty()).map(String::from).collect()
}

fn check_ports(list: &[String]) -> Result<()> {
    for p in list {
        let (lo, hi) = match p.split_once('-') {
            Some((lo, hi)) => (lo, Some(hi)),
            None => (p.as_str(), None),
        };
        let ok = port_str(lo) && hi.is_none_or(|hi| port_str(hi) && atoi(hi) >= atoi(lo));
        if !ok {
            return Err(format!("bad port {p:?}"));
        }
    }
    Ok(())
}

impl Acl {
    pub fn port_list(&self) -> Vec<String> {
        port_list(&self.ports)
    }

    pub fn validate(&self) -> Result<()> {
        if self.node.is_empty() {
            return Err("pick the node that enforces the rule".into());
        }
        match self.proto.as_str() {
            "tcp" | "udp" | "both" | "icmp" | "any" => {}
            _ => return Err("protocol must be tcp, udp, both, icmp or any".into()),
        }
        if self.to != TO_SELF && netx::parse_prefix(&self.to).is_none() && netx::parse_addr4(&self.to).is_none() {
            return Err("destination must be an IPv4 address, a subnet like 192.168.20.0/24, or self".into());
        }
        let ports = self.port_list();
        if !ports.is_empty() && !matches!(self.proto.as_str(), "tcp" | "udp" | "both") {
            return Err("ports need protocol tcp, udp or both".into());
        }
        check_ports(&ports)
    }

    /// `to` as a prefix (a host becomes /32); None for self.
    pub fn dest_prefix(&self) -> Option<Prefix> {
        if self.to == TO_SELF {
            return None;
        }
        if let Some(p) = netx::parse_prefix(&self.to) {
            return Some(p.masked());
        }
        let ip = netx::parse_addr(&self.to)?;
        Some(Prefix::new(ip, 32))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Monitor {
    pub id: String,
    pub name: String,
    pub node: String,
    #[serde(skip_serializing_if = "zero")]
    pub ip: String,
    pub proto: String,
    #[serde(skip_serializing_if = "zero")]
    pub ports: String,
}

impl Monitor {
    pub fn port_list(&self) -> Vec<String> {
        port_list(&self.ports)
    }

    pub fn validate(&self) -> Result<()> {
        if self.node.is_empty() {
            return Err("pick the node that measures".into());
        }
        if self.ip.is_empty() && self.ports.is_empty() {
            return Err("give an IP, a port, or both".into());
        }
        if !self.ip.is_empty() {
            let pfx_ok = netx::parse_prefix(&self.ip).is_some_and(|p| p.is4());
            if !pfx_ok && netx::parse_addr4(&self.ip).is_none() {
                return Err("IP must be an IPv4 address or a subnet like 192.168.1.0/24".into());
            }
        }
        match self.proto.as_str() {
            "tcp" | "udp" | "both" | "any" => {}
            _ => return Err("protocol must be tcp, udp, both or any".into()),
        }
        if !self.ports.is_empty() && self.proto == "any" {
            return Err("ports need protocol tcp, udp or both".into());
        }
        check_ports(&self.port_list())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LanExit {
    pub src: String,
    pub via: String,
}

/// Parses an IPv4 address or subnet ("192.168.1.205", "192.168.20.0/24").
pub fn src_prefix(src: &str) -> Result<Prefix> {
    if let Some(p) = netx::parse_prefix(src).filter(|p| p.is4()) {
        return Ok(p.masked());
    }
    match netx::parse_addr4(src) {
        Some(a) => Ok(Prefix::new(IpAddr::V4(a), 32)),
        None => Err(format!("{src:?}: want an IPv4 address or subnet")),
    }
}

impl LanExit {
    pub fn prefix(&self) -> Result<Prefix> {
        src_prefix(&self.src)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExitRoute {
    pub id: String,
    pub name: String,
    pub src: String,
    pub router: String,
    pub via: String,
    #[serde(skip_serializing_if = "zero")]
    pub exit_only: bool,
    pub enabled: bool,
}

impl ExitRoute {
    pub fn prefix(&self) -> Result<Prefix> {
        src_prefix(&self.src)
    }
}

/// Builds a store key.
pub fn key(kind: &str, id: &str) -> String {
    format!("{kind}/{id}")
}

/// Splits a store key into kind and id.
pub fn split_key(k: &str) -> (&str, &str) {
    k.split_once('/').unwrap_or((k, ""))
}

pub fn valid_port(p: i64) -> bool {
    p > 0 && p < 65536
}

fn port_str(s: &str) -> bool {
    let n = atoi(s);
    n > 0 && n < 65536
}

fn atoi(s: &str) -> i64 {
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|c| c.is_ascii_digit()) {
        return -1;
    }
    s.parse().unwrap_or(-1)
}

/// `^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`
fn valid_hostname(h: &str) -> bool {
    let labels: Vec<&str> = h.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            let b = l.as_bytes();
            let an = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
            !b.is_empty() && b.len() <= 63 && an(&b[0]) && an(&b[b.len() - 1]) && b.iter().all(|c| an(c) || *c == b'-')
        })
}

/// Validates a display name: 1-63 bytes, no control or invisible
/// formatting characters.
pub fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 63 {
        return Err("name must be 1-63 characters".into());
    }
    if name.chars().any(|c| c.is_control() || is_format_char(c) || c == '\u{FFFD}') {
        return Err("name contains a control or invisible character".into());
    }
    Ok(())
}

/// Unicode general category Cf (format characters).
fn is_format_char(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890..=0x0891 | 0x08E2 |
        0x180E | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F |
        0xFEFF | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3 |
        0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F)
}

/// Validates "host:port" (IPv4 address or DNS name).
pub fn check_endpoint(ep: &str) -> Result<()> {
    let (host, port) = netx::split_host_port(ep).map_err(|_| format!("endpoint {ep:?}: want host:port"))?;
    match crate::gojson::atoi(&port) {
        Some(p) if valid_port(p) => {}
        _ => return Err(format!("endpoint {ep:?}: bad port")),
    }
    if host.is_empty() || host.len() > 253 || !host.chars().all(|r| r.is_ascii_alphanumeric() || r == '.' || r == '-' || r == ':') {
        return Err(format!("endpoint {ep:?}: bad host"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_matches_go() {
        let n = Node { id: "a".into(), kind: NODE_SERVER.into(), relay: true, ..Default::default() };
        assert_eq!(
            serde_json::to_string(&n).unwrap(),
            r#"{"id":"a","name":"","kind":"server","public_key":"","mesh_ip":"","relay":true,"created_at":0}"#
        );
        let back: Node = serde_json::from_str(r#"{"id":"a","endpoints":null,"future_field":1}"#).unwrap();
        assert_eq!(back.id, "a");
        assert!(back.endpoints.is_empty());
    }

    #[test]
    fn names_and_endpoints() {
        assert!(check_name("johnnys vps").is_ok());
        assert!(check_name("evil\x1b[2Jname").is_err());
        assert!(check_name("rtl\u{202e}txt.exe").is_err());
        assert!(check_name("").is_err());
        assert!(check_endpoint("1.2.3.4:51820").is_ok());
        assert!(check_endpoint("vps.example.com:51820").is_ok());
        assert!(check_endpoint("1.2.3.4:51820\nallowed_ip=0.0.0.0/0").is_err());
        assert!(check_endpoint("1.2.3.4:99999").is_err());
    }

    #[test]
    fn validation() {
        let mut f = Forward {
            proto: "tcp".into(),
            edge_node: "a".into(),
            target_node: "b".into(),
            listen_port: 25565,
            target_port: 25565,
            ..Default::default()
        };
        assert!(f.validate().is_ok());
        f.listen_end = 25570;
        f.target_port = 1;
        assert!(f.validate().is_err());
        let a = Acl {
            node: "n".into(),
            to: "192.168.20.0/24".into(),
            proto: "tcp".into(),
            ports: "80, 8000-8100".into(),
            ..Default::default()
        };
        assert!(a.validate().is_ok());
        assert_eq!(a.port_list(), vec!["80", "8000-8100"]);
        let bad = Acl { ports: "90-80".into(), ..a.clone() };
        assert!(bad.validate().is_err());
        let r = HttpRoute {
            hostname: "App.Example.com".into(),
            edge_node: "a".into(),
            target_node: "b".into(),
            target_port: 80,
            ..Default::default()
        };
        assert!(r.validate().is_ok());
        let r2 = HttpRoute { hostname: "localhost".into(), ..r };
        assert!(r2.validate().is_err());
        assert_eq!(src_prefix("192.168.1.205").unwrap().to_string(), "192.168.1.205/32");
        assert_eq!(src_prefix("192.168.20.9/24").unwrap().to_string(), "192.168.20.0/24");
    }
}
