//! meshgate: a WireGuard mesh with relays, port forwards and a web UI.
//! Rust build; drop-in replacement for the Go build in ../go (see PARITY.md).

// Modules are wired up step by step while the port is in progress.
#![allow(dead_code)]

#[macro_use]
mod logx;
mod agent;
mod changelog;
mod cli;
mod config;
mod diag;
mod events;
mod fw;
mod gojson;
mod history;
mod hostfw;
mod http;
mod httpc;
mod ifaces;
mod join;
mod localapi;
mod meshcfg;
mod model;
mod netlink;
mod netx;
mod ops;
mod pathsel;
mod pfsense;
mod ports;
mod probe;
mod proxy;
mod store;
mod syncer;
mod tlsx;
mod traffic;
mod tui;
mod update;
mod util;
mod webtls;
mod webui;
mod wg;
#[cfg(unix)]
mod wgu;
#[cfg(windows)]
mod winnet;
#[cfg(windows)]
mod winsvc;

/// The release version, set at build time (Go: agent.Version).
pub const VERSION: &str = match option_env!("MESHGATE_VERSION") {
    Some(v) => v,
    None => "dev",
};

fn main() {
    std::process::exit(cli::main());
}
