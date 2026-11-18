//! meshgate: a WireGuard mesh with relays, port forwards and a web UI.
//! Rust build; drop-in replacement for the Go build in ../go (see PARITY.md).
//! The `meshgate` binary is `cli::main`; the phone apps use `mobile`.

// Modules are wired up step by step while the port is in progress.
#![allow(dead_code)]

#[macro_use]
pub mod logx;
pub mod agent;
pub mod changelog;
pub mod cli;
pub mod config;
pub mod diag;
pub mod events;
pub mod fw;
pub mod gojson;
pub mod history;
pub mod hostfw;
pub mod http;
pub mod httpc;
pub mod ifaces;
pub mod join;
pub mod localapi;
pub mod meshcfg;
pub mod mobile;
pub mod model;
pub mod netlink;
pub mod netx;
pub mod ops;
pub mod pathsel;
pub mod pfsense;
pub mod ports;
pub mod probe;
pub mod proxy;
pub mod store;
pub mod syncer;
pub mod tlsx;
pub mod traffic;
pub mod tui;
pub mod update;
pub mod util;
pub mod webtls;
pub mod webui;
pub mod wg;
pub mod wgdev;
#[cfg(unix)]
pub mod wgu;
#[cfg(windows)]
pub mod winnet;
#[cfg(windows)]
pub mod winsvc;

/// The release version, set at build time (Go: agent.Version).
pub const VERSION: &str = match option_env!("MESHGATE_VERSION") {
    Some(v) => v,
    None => "dev",
};
