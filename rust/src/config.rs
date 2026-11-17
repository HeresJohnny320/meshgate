//! Node-local settings that never replicate (Go: internal/config).

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::gojson::{marshal_indent, nullable, zero};
use crate::model;

pub const DEFAULT_IFACE: &str = "mg0";

#[cfg(target_os = "freebsd")]
mod paths {
    // pfSense's "Use RAM Disks" wipes /var on reboot, so data lives in /usr/local/etc.
    pub const DEFAULT_PATH: &str = "/usr/local/etc/meshgate/node.json";
    pub const DEFAULT_DATA: &str = "/usr/local/etc/meshgate/data";
    pub const DEFAULT_SOCKET: &str = "/var/run/meshgate.sock";
}
#[cfg(target_os = "linux")]
mod paths {
    pub const DEFAULT_PATH: &str = "/etc/meshgate/node.json";
    pub const DEFAULT_DATA: &str = "/var/lib/meshgate";
    pub const DEFAULT_SOCKET: &str = "/run/meshgate/meshgate.sock";
}
#[cfg(not(any(target_os = "linux", target_os = "freebsd", windows)))]
mod paths {
    pub const DEFAULT_PATH: &str = "/etc/meshgate/node.json";
    pub const DEFAULT_DATA: &str = "/var/lib/meshgate";
    pub const DEFAULT_SOCKET: &str = "/var/run/meshgate.sock";
}

#[cfg(not(windows))]
pub fn default_path() -> String {
    paths::DEFAULT_PATH.into()
}
#[cfg(not(windows))]
pub fn default_data() -> String {
    paths::DEFAULT_DATA.into()
}
#[cfg(not(windows))]
pub fn default_socket() -> String {
    paths::DEFAULT_SOCKET.into()
}

#[cfg(windows)]
fn program_data() -> PathBuf {
    std::env::var_os("ProgramData").filter(|p| !p.is_empty()).map(PathBuf::from).unwrap_or_else(|| r"C:\ProgramData".into())
}
#[cfg(windows)]
pub fn default_path() -> String {
    program_data().join("meshgate").join("node.json").to_string_lossy().into()
}
#[cfg(windows)]
pub fn default_data() -> String {
    program_data().join("meshgate").join("data").to_string_lossy().into()
}
#[cfg(windows)]
pub fn default_socket() -> String {
    program_data().join("meshgate").join("meshgate.sock").to_string_lossy().into()
}

/// node.json.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Node {
    pub node_id: String,
    pub private_key: String,
    pub kind: String,
    pub iface: String,
    pub data_dir: String,
    pub socket: String,
    pub probe_port: i64,
    pub mesh_port: i64,
    #[serde(skip_serializing_if = "zero")]
    pub join_listen: String,
    #[serde(skip_serializing_if = "zero", deserialize_with = "nullable")]
    pub web_listen: Vec<String>,
    #[serde(skip_serializing_if = "zero")]
    pub web_plain_http: bool,
    #[serde(skip_serializing_if = "zero")]
    pub userspace: bool,
    #[serde(skip_serializing_if = "zero")]
    pub pf_nat_anchor: String,
    #[serde(skip_serializing_if = "zero")]
    pub pf_rdr_anchor: String,
    #[serde(skip_serializing_if = "zero")]
    pub pf_filter_anchor: String,
}

impl Node {
    fn data(&self, f: &str) -> PathBuf {
        Path::new(&self.data_dir).join(f)
    }
    pub fn state_path(&self) -> PathBuf {
        self.data("state.json")
    }
    pub fn host_firewall_state_path(&self) -> PathBuf {
        self.data("hostfw.json")
    }
    pub fn cert_path(&self) -> PathBuf {
        self.data("join.crt")
    }
    pub fn key_path(&self) -> PathBuf {
        self.data("join.key")
    }
    pub fn web_cert_path(&self) -> PathBuf {
        self.data("webui.crt")
    }
    pub fn web_key_path(&self) -> PathBuf {
        self.data("webui.key")
    }
    pub fn web_ca_cert_path(&self) -> PathBuf {
        self.data("webui-ca.crt")
    }
    pub fn web_ca_key_path(&self) -> PathBuf {
        self.data("webui-ca.key")
    }
    pub fn cert_magic_dir(&self) -> PathBuf {
        self.data("certs")
    }

    /// Fills empty fields.
    pub fn defaults(&mut self) {
        if self.iface.is_empty() {
            self.iface = DEFAULT_IFACE.into();
        }
        if self.data_dir.is_empty() {
            self.data_dir = default_data();
        }
        if self.socket.is_empty() {
            self.socket = default_socket();
        }
        if self.probe_port == 0 {
            self.probe_port = model::DEFAULT_PROBE_PORT;
        }
        if self.mesh_port == 0 {
            self.mesh_port = model::DEFAULT_MESH_PORT;
        }
    }
}

/// Reads the node config.
pub fn load(path: impl AsRef<Path>) -> io::Result<Node> {
    let b = std::fs::read(path)?;
    let mut n: Node = serde_json::from_slice(&b).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    n.defaults();
    Ok(n)
}

/// Writes the node config with owner-only permissions.
pub fn save(path: impl AsRef<Path>, n: &Node) -> io::Result<()> {
    let path = path.as_ref();
    let b = marshal_indent(n, "  ");
    secure_dir(path.parent().unwrap_or(Path::new(".")))?;
    let tmp = tmp_path(path);
    write_private(&tmp, &b)?;
    std::fs::rename(tmp, path)
}

pub fn tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

/// Writes a file readable by the owner only (0600).
pub fn write_private(path: &Path, b: &[u8]) -> io::Result<()> {
    write_mode(path, b, 0o600)
}

/// os.WriteFile(path, b, mode): the mode applies when the file is created.
pub fn write_mode(path: &Path, b: &[u8], mode: u32) -> io::Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    use std::io::Write;
    o.open(path)?.write_all(b)
}

/// Creates dir readable by root only.
#[cfg(unix)]
pub fn secure_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
}

/// Creates dir and restricts it to SYSTEM and Administrators: it holds the
/// private key and the local control socket.
#[cfg(windows)]
pub fn secure_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let st = std::process::Command::new("icacls")
        .arg(dir)
        .args(["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F"])
        .stdout(std::process::Stdio::null())
        .status()?;
    if st.success() { Ok(()) } else { Err(io::Error::other("icacls failed")) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("etc/node.json");
        let n = Node { node_id: "abc".into(), kind: "server".into(), data_dir: "/d".into(), ..Default::default() };
        save(&p, &n).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.starts_with("{\n  \"node_id\": \"abc\",\n  \"private_key\": \"\""));
        assert!(!text.contains("web_listen"));
        let got = load(&p).unwrap();
        assert_eq!(got.iface, "mg0");
        assert_eq!(got.mesh_port, 51823);
        assert_eq!(got.state_path(), Path::new("/d/state.json"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}
