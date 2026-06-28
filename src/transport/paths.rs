//! Connection path reporting (direct vs relay).
//!
//! Logs the currently selected iroh connection path(s) with RTT and logs
//! again whenever the selected path changes (e.g., relay -> direct).

use futures::StreamExt;
use iroh::TransportAddr;
use iroh::endpoint::{Connection, PathList};
use tokio::task::JoinHandle;

/// Format connection path info for display, showing selected paths with RTT.
pub fn format_connection_paths(paths: &PathList<'_>) -> String {
    if paths.is_empty() {
        return "establishing...".to_string();
    }
    let parts: Vec<String> = paths
        .iter()
        .filter(|p| p.is_selected())
        .map(|path| {
            let rtt = path.rtt();
            match path.remote_addr() {
                TransportAddr::Ip(addr) => format!("Direct {} (rtt {:.0?})", addr, rtt),
                TransportAddr::Relay(url) => format!("Relay {} (rtt {:.0?})", url, rtt),
                other => format!("{:?} (rtt {:.0?})", other, rtt),
            }
        })
        .collect();
    if parts.is_empty() {
        "no selected path".to_string()
    } else {
        parts.join(", ")
    }
}

/// Key identifying the selected-path topology, excluding the volatile RTT,
/// so we only log when the path actually changes.
fn paths_key(paths: &PathList<'_>) -> (bool, Vec<String>) {
    let selected = paths
        .iter()
        .filter(|p| p.is_selected())
        .map(|p| format!("{:?}", p.remote_addr()))
        .collect();
    (paths.is_empty(), selected)
}

/// RAII guard that aborts the background path watcher task on drop.
pub struct PathWatcherGuard(JoinHandle<()>);

impl Drop for PathWatcherGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Log the current connection path and spawn a background task that logs
/// updates whenever the selected path changes (e.g., relay -> direct).
///
/// The returned [`PathWatcherGuard`] aborts the background task when dropped.
/// Callers must keep the guard alive for the duration of the connection.
pub fn watch_connection_paths(connection: &Connection, label: &str) -> PathWatcherGuard {
    let connection = connection.clone();
    let label = label.to_string();
    PathWatcherGuard(tokio::spawn(async move {
        // The stream yields the current snapshot on the first poll, then a
        // fresh snapshot whenever the open or selected paths change; it ends
        // when the connection closes.
        let mut stream = connection.paths_stream();
        let mut last_key = None;
        while let Some(paths) = stream.next().await {
            let key = paths_key(&paths);
            if last_key.as_ref() != Some(&key) {
                log::info!("{}: {}", label, format_connection_paths(&paths));
                last_key = Some(key);
            }
        }
    }))
}
