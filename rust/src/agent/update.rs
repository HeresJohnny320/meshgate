//! Self-update and remote updates (Go: internal/agent/update.go).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::{Method, StatusCode};

use super::Agent;
use crate::http::{self, Peer, Resp};
use crate::model::{self, Node};

static LATEST: Mutex<String> = Mutex::new(String::new());
static UPDATING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Keeps the newest release tag for the dashboard (every 30 minutes).
pub async fn latest_loop() {
    loop {
        if let Ok(tag) = crate::update::latest().await {
            *LATEST.lock().unwrap() = tag;
        }
        tokio::time::sleep(Duration::from_secs(30 * 60)).await;
    }
}

pub fn latest_release() -> String {
    LATEST.lock().unwrap().clone()
}

impl Agent {
    /// Makes node (this one or another over the mesh) update itself.
    pub(super) async fn update(self: Arc<Self>, node: &str) -> Result<String, String> {
        if node.is_empty() || node == self.cfg.node_id {
            return self.start_self_update();
        }
        let n: Node = self.store.get(&model::key(model::KIND_NODE, node)).filter(|n: &Node| !n.mesh_ip.is_empty()).ok_or("unknown node")?;
        if n.kind == model::NODE_CLIENT && !n.api_hash.is_empty() {
            return Err(format!("{} is a phone: update it in the meshgate app", n.name));
        }
        if n.kind == model::NODE_STATIC {
            return Err(format!("{} uses the official WireGuard app", n.name));
        }
        let r = http::plain(
            &Agent::mesh_addr(&n),
            Method::POST,
            "/v1/update",
            &[("Content-Type", "application/json")],
            bytes::Bytes::new(),
            Duration::from_secs(10),
        )
        .await
        .map_err(|e| format!("{} did not answer: {e}", n.name))?;
        match r.status {
            StatusCode::ACCEPTED => Ok(format!("{} is updating; it restarts by itself when done", n.name)),
            StatusCode::NOT_FOUND => {
                Err(format!("{} runs a meshgate too old for remote updates: run `meshgate update` on it once", n.name))
            }
            _ => Err(format!("{} refused: {}", n.name, r.status_line())),
        }
    }

    /// Lets servers ask this node to update (mesh port).
    pub(super) fn serve_update(self: Arc<Self>, peer: Peer) -> Resp {
        if self.server_caller(&peer).is_err() {
            return http::error(StatusCode::FORBIDDEN, "only servers may update nodes");
        }
        match self.start_self_update() {
            Ok(_) => http::status(StatusCode::ACCEPTED),
            Err(e) => http::error(StatusCode::CONFLICT, e),
        }
    }

    /// Installs the latest release in the background and exits with code
    /// 3; the service manager starts the new version.
    fn start_self_update(self: Arc<Self>) -> Result<String, String> {
        let Ok(guard) = UPDATING.try_lock() else { return Err("an update is already running".into()) };
        tokio::spawn(async move {
            let _g = guard;
            let r = tokio::time::timeout(Duration::from_secs(600), async {
                let tag = crate::update::latest().await?;
                if !crate::update::newer(crate::VERSION, &tag) {
                    logf!("update: {} is current (latest {tag})", crate::VERSION);
                    return Ok(None);
                }
                let exe = std::env::current_exe().and_then(|p| p.canonicalize()).map_err(|e| e.to_string())?;
                crate::update::install(&tag, &exe).await.map_err(|e| format!("update to {tag} failed: {e}"))?;
                Ok::<_, String>(Some(tag))
            })
            .await;
            match r {
                Ok(Ok(Some(tag))) => {
                    logf!("updated {} -> {tag}; restarting", crate::VERSION);
                    let a = self.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        a.flush_events(); // the log server should know why we vanish
                        a.wg.release();
                    })
                    .await;
                    tokio::time::sleep(Duration::from_secs(1)).await; // let the API answer go out
                    std::process::exit(3);
                }
                Ok(Ok(None)) => {}
                Ok(Err(e)) => logf!("update: {e}"),
                Err(_) => logf!("update: timed out"),
            }
        });
        Ok("updating to the latest release; meshgate restarts by itself when done".into())
    }
}
