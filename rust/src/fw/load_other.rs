//! Windows nodes do not manage firewall rules: they cannot be forward
//! edges, subnet routers or enforce LAN policies (the agent warns).

use std::collections::HashMap;

use super::Plan;

pub fn render(_p: &Plan) -> String {
    String::new()
}
pub fn load(_rendered: &str) -> Result<(), String> {
    Ok(())
}
pub fn remove() -> Result<(), String> {
    Ok(())
}
pub fn detect_wan() -> String {
    String::new()
}
pub fn is_pfsense() -> bool {
    false
}
pub fn read_counters() -> Option<HashMap<String, [u64; 2]>> {
    None
}
pub fn sync_iptables(_rules: &[Vec<String>]) -> Result<(), String> {
    Ok(())
}
pub fn remove_iptables() {}
