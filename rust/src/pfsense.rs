//! meshgate in the pfSense GUI (Go: internal/pfsense): VPN > meshgate with
//! the dashboard behind the pfSense login, and the MESHGATE interface whose
//! Firewall > Rules decide what mesh devices may reach. The PHP files are
//! the Go build's own, installed as they are.

use std::path::Path;

/// The mesh interface name on pfSense (the tun_ prefix skips pfSense's
/// boot-time interface mismatch check).
pub const IFACE: &str = "tun_mg0";

const WWW: &str = "/usr/local/www";
const ASSETS_DIR: &str = "/usr/local/www/meshgate";
const HELPER_DIR: &str = "/usr/local/share/meshgate";
const PHP: &str = "/usr/local/bin/php";

const PAGE: &str = include_str!(concat!(env!("MESHGATE_GO_DIR"), "/internal/pfsense/files/vpn_meshgate.php"));
const PROXY: &str = include_str!(concat!(env!("MESHGATE_GO_DIR"), "/internal/pfsense/files/meshgate_api.php"));
const HELPER: &str = include_str!(concat!(env!("MESHGATE_GO_DIR"), "/internal/pfsense/files/meshgate_config.php"));

/// Installs the GUI pages, the dashboard assets and the config helper.
pub fn write_files(socket: &str, version: &str) -> Result<(), String> {
    let index =
        crate::webui::STATIC.iter().find(|f| f.0 == "index.html").map(|f| String::from_utf8_lossy(f.2).into_owned()).unwrap_or_default();
    let mut out: Vec<(String, Vec<u8>)> = vec![
        (format!("{WWW}/vpn_meshgate.php"), PAGE.as_bytes().to_vec()),
        (format!("{WWW}/meshgate_api.php"), PROXY.replace("@@SOCKET@@", socket).into_bytes()),
        (format!("{HELPER_DIR}/config.php"), HELPER.as_bytes().to_vec()),
        (format!("{ASSETS_DIR}/index.html"), dash_index(&index, version).into_bytes()),
    ];
    for name in ["app.js", "app.css"] {
        let b = crate::webui::STATIC.iter().find(|f| f.0 == name).map(|f| f.2.to_vec()).unwrap_or_default();
        out.push((format!("{ASSETS_DIR}/{name}"), b));
    }
    for (path, b) in out {
        let p = Path::new(&path);
        std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
        crate::config::write_mode(p, &b, 0o644).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Routes the dashboard's API calls through the PHP proxy and versions its
/// assets so browsers pick up new ones after an upgrade.
fn dash_index(index: &str, version: &str) -> String {
    index
        .replacen("<html", "<html data-api=\"/meshgate_api.php?p=\"", 1)
        .replacen("href=\"app.css\"", &format!("href=\"app.css?v={version}\""), 1)
        .replacen("src=\"app.js\"", &format!("src=\"app.js?v={version}\""), 1)
}

/// Deletes everything write_files installed.
pub fn remove_files() {
    let _ = std::fs::remove_file(format!("{WWW}/vpn_meshgate.php"));
    let _ = std::fs::remove_file(format!("{WWW}/meshgate_api.php"));
    let _ = std::fs::remove_dir_all(ASSETS_DIR);
    let _ = std::fs::remove_dir_all(HELPER_DIR);
}

/// Edits config.xml: "install" adds the menu entry, the MESHGATE interface
/// and its default pass rule and returns the interface's name (optN);
/// "remove" undoes it.
pub fn configure(action: &str) -> Result<String, String> {
    let helper = format!("{HELPER_DIR}/config.php");
    let mut args = vec!["-f", helper.as_str(), action];
    if action == "install" {
        args.push(IFACE);
    }
    let o = crate::util::run(PHP, &args, None);
    let s = o.out.trim().to_string();
    if !o.ok {
        return Err(format!("pfSense config: {}: {s}", o.err));
    }
    Ok(s)
}

/// Whether the GUI integration is installed here.
pub fn installed() -> bool {
    Path::new(&format!("{HELPER_DIR}/config.php")).exists()
}

#[cfg(test)]
mod tests {
    #[test]
    fn dash_index_like_go() {
        let s = super::dash_index("<!doctype html><html lang=\"en\"><link href=\"app.css\"><script src=\"app.js\">", "v1.2.3");
        assert_eq!(
            s,
            "<!doctype html><html data-api=\"/meshgate_api.php?p=\" lang=\"en\"><link href=\"app.css?v=v1.2.3\"><script src=\"app.js?v=v1.2.3\">"
        );
    }
}
