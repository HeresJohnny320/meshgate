//! The agent's local API socket and its client (Go: internal/localapi),
//! used by the CLI, the TUI and the pfSense pages: HTTP over a unix socket,
//! readable by root only.

use std::sync::Arc;
use std::time::Duration;

use hyper::{Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::http::{self, Peer};

/// Serves h on the socket path.
#[cfg(unix)]
pub async fn serve(socket: &str, h: Arc<dyn http::Handler>) -> Result<(), String> {
    let p = std::path::Path::new(socket);
    if let Some(d) = p.parent() {
        let _ = crate::config::secure_dir(d);
    }
    let _ = std::fs::remove_file(p);
    let l = tokio::net::UnixListener::bind(p).map_err(|e| format!("listen unix {socket}: {e}"))?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
    }
    loop {
        let Ok((c, _)) = l.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let h = h.clone();
        tokio::spawn(http::serve_conn(c, h, Peer { addr: None, tls: false }));
    }
}

#[cfg(windows)]
pub async fn serve(socket: &str, h: Arc<dyn http::Handler>) -> Result<(), String> {
    crate::winnet::serve_local(socket, h).await
}

/// Talks to a local agent.
pub struct Client {
    socket: String,
}

#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct ApiError {
    #[serde(alias = "Error")]
    error: String,
}

impl Client {
    pub fn new(socket: &str) -> Client {
        Client { socket: socket.into() }
    }

    async fn raw(&self, method: Method, op: &str, body: Vec<u8>) -> Result<bytes::Bytes, String> {
        let path = format!("/v1/{op}");
        let fut = async {
            #[cfg(unix)]
            let c = tokio::net::UnixStream::connect(&self.socket).await.map_err(|e| format!("dial unix {}: {e}", self.socket))?;
            #[cfg(windows)]
            let c = crate::winnet::connect_local(&self.socket).await?;
            http::request_on(c, method, "meshgate", &path, &[("Content-Type", "application/json")], body.into(), 256 << 20).await
        };
        let res = tokio::time::timeout(Duration::from_secs(15), fut)
            .await
            .unwrap_or_else(|_| Err("timeout".into()))
            .map_err(|e| format!("cannot reach the meshgate agent (is it running? try `sudo systemctl status meshgate`): {e}"))?;
        if res.status != StatusCode::OK {
            let e: ApiError = serde_json::from_slice(&res.body).unwrap_or_default();
            return Err(if e.error.is_empty() { res.status_line() } else { e.error });
        }
        Ok(res.body)
    }

    /// Reads an operation's result, e.g. "history?range=1d".
    pub async fn get<T: DeserializeOwned>(&self, op: &str) -> Result<T, String> {
        let b = self.raw(Method::GET, op, vec![]).await?;
        http::first_json(&b).map_err(|e| e.to_string())
    }

    /// Calls an operation.
    pub async fn post<T: DeserializeOwned, B: Serialize>(&self, op: &str, body: &B) -> Result<T, String> {
        let b = self.raw(Method::POST, op, crate::gojson::marshal(body)).await?;
        http::first_json(&b).map_err(|e| e.to_string())
    }

    /// Calls an operation, ignoring its answer.
    pub async fn post_ok<B: Serialize>(&self, op: &str, body: &B) -> Result<(), String> {
        self.raw(Method::POST, op, crate::gojson::marshal(body)).await.map(|_| ())
    }

    /// The raw JSON of a GET.
    pub async fn get_raw(&self, op: &str) -> Result<bytes::Bytes, String> {
        self.raw(Method::GET, op, vec![]).await
    }
}
