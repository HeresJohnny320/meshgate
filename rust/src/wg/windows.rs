//! Windows: not ported yet. Windows release files stay the Go build (see
//! RELEASE_IMPL and PARITY.md) until this uses the WireGuardNT driver and
//! has been tested on Windows.

use std::collections::HashMap;

use super::PeerStat;
use crate::meshcfg;

const NOT_YET: &str = "the Rust build does not support Windows yet; use the Go build (the default release)";

pub struct Manager {
    pub iface: String,
}

impl Manager {
    pub fn new(iface: &str, _key: [u8; 32]) -> Manager {
        Manager { iface: iface.into() }
    }
    pub fn is_created(&self) -> bool {
        false
    }
    pub fn is_userspace(&self) -> bool {
        true
    }
    pub fn up(&self, _force_userspace: bool) -> Result<(), String> {
        Err(NOT_YET.into())
    }
    pub fn ensure(&self, _force_userspace: bool) -> Result<bool, String> {
        Ok(false)
    }
    pub fn apply(&self, _cfg: &meshcfg::Config) -> Result<(), String> {
        Err(NOT_YET.into())
    }
    pub fn reset_peers(&self, _keys: &[String]) -> Result<(), String> {
        Ok(())
    }
    pub fn stats(&self) -> HashMap<String, PeerStat> {
        HashMap::new()
    }
    pub fn sync_underlay(&self) {}
    pub fn release(&self) {}
    pub fn down(&self) {}
}

pub fn teardown(_iface: &str) {}
pub fn enable_forwarding() {}
pub fn destroy_interface(_name: &str) {}
