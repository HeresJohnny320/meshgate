//! Windows networking helpers (not ported yet; see wg::windows).

#![cfg(windows)]

use std::sync::Arc;

pub fn interfaces() -> Vec<crate::ifaces::Iface> {
    vec![]
}

pub fn read_password() -> String {
    crate::cli::term::read_line().trim_end_matches(['\r', '\n']).to_string()
}

pub async fn serve_local(_socket: &str, _h: Arc<dyn crate::http::Handler>) -> Result<(), String> {
    Err("the Rust build does not support Windows yet".into())
}

pub async fn connect_local(_socket: &str) -> Result<tokio::net::TcpStream, String> {
    Err("the Rust build does not support Windows yet".into())
}
