//! The Windows service (not ported yet; see wg::windows).

#![cfg(windows)]

use std::sync::Arc;

pub fn is_service() -> bool {
    false
}

pub async fn run(_a: Arc<crate::agent::Agent>) -> Result<(), String> {
    Err("the Rust build does not support Windows yet".into())
}

pub fn cmd_service(_cfg_path: &str, _args: &[String]) -> Result<(), String> {
    Err("the Rust build does not support Windows yet; use the Go build".into())
}

pub fn restart() -> Result<(), String> {
    Ok(())
}

pub fn set(_on: bool) -> Result<(), String> {
    Err("the Rust build does not support Windows yet".into())
}

pub fn stop_for_leave() {}
