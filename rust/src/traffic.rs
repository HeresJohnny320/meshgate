//! Live traffic numbers a node reports (Go: internal/traffic).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::gojson::{nullable, zero};

/// A byte count with its current speed. In is toward the target / received
/// by this node, Out the other way.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Rate {
    #[serde(rename = "in")]
    pub in_: u64,
    pub out: u64,
    pub in_rate: f64,
    pub out_rate: f64,
}

/// An HTTPS route's traffic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Route {
    #[serde(flatten)]
    pub rate: Rate,
    pub http: Rate,
    pub requests: u64,
    pub errors: u64,
    pub req_rate: f64,
}

/// Requests to one hostname (kept by the HTTPS proxy).
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostStats {
    pub requests: u64,
    pub errors: u64,
    #[serde(rename = "in")]
    pub in_: u64,
    pub out: u64,
    #[serde(skip_serializing_if = "zero")]
    pub http_requests: u64,
    #[serde(skip_serializing_if = "zero")]
    pub http_in: u64,
    #[serde(skip_serializing_if = "zero")]
    pub http_out: u64,
}

/// One entry of the recent HTTPS requests list.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Request {
    pub time: i64,
    pub client: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub status: i64,
    pub bytes: u64,
    #[serde(rename = "ms")]
    pub ms: i64,
}

/// What one server reports. Totals count since meshgate started.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Node {
    pub node: String,
    #[serde(deserialize_with = "nullable")]
    pub forwards: BTreeMap<String, Rate>,
    #[serde(deserialize_with = "nullable")]
    pub routes: BTreeMap<String, Route>,
    #[serde(deserialize_with = "nullable")]
    pub acls: BTreeMap<String, u64>,
    #[serde(deserialize_with = "nullable")]
    pub peers: BTreeMap<String, Rate>,
    #[serde(deserialize_with = "nullable")]
    pub monitors: BTreeMap<String, Rate>,
    #[serde(deserialize_with = "nullable")]
    pub recent: Vec<Request>,
}
