//! Active backend health checking.
//!
//! Each reload, every discovered backend is probed with a short TCP connect.
//! Only backends that answer are placed into the Maglev table, so a crashed
//! instance is evicted within one reload cycle and re-added automatically once
//! it recovers (or when discovery / config changes the set).

use crate::discovery::Backend;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::task::JoinSet;

/// Return only the backends that accept a TCP connection on their probe port.
///
/// `probe_port` overrides the port to connect to; otherwise the backend's own
/// port is used, falling back to `default_port` (the first listen port).
pub async fn filter_healthy(
    backends: Vec<Backend>,
    probe_port: Option<u16>,
    default_port: u16,
    timeout: Duration,
) -> Vec<Backend> {
    let mut set = JoinSet::new();
    for b in backends {
        set.spawn(async move {
            let port = probe_port.or(b.port).unwrap_or(default_port);
            let addr = SocketAddr::from((b.ip, port));
            match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
                Ok(Ok(_stream)) => Some(b),
                _ => None,
            }
        });
    }

    let mut healthy = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(Some(b)) = res {
            healthy.push(b);
        }
    }
    // Keep a stable order so the Maglev table is deterministic across reloads.
    healthy.sort_by_key(|b| (b.ip, b.port));
    healthy
}
