//! Optional, opt-in observability endpoint.
//!
//! Disabled unless `observability.metrics_addr` is set in config, so the default
//! deployment runs with zero extra surface. When enabled it serves a tiny
//! dependency-free HTTP endpoint:
//!   - `GET /metrics`  Prometheus text exposition of data-plane counters.
//!   - `GET /healthz`  200 when the shield has at least one healthy backend, else 503.

use anyhow::{Context as _, Result};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Snapshot of counters shared between the reload loop (writer) and the HTTP
/// server (reader). Updated each reload from the eBPF stats map.
#[derive(Default)]
pub struct MetricsState {
    pub routed: AtomicU64,
    pub dropped_validation: AtomicU64,
    pub dropped_blocked: AtomicU64,
    pub dropped_rate: AtomicU64,
    pub dropped_nobackend: AtomicU64,
    pub backends_total: AtomicU64,
    pub backends_healthy: AtomicU64,
    /// Readiness: true once the data plane has at least one healthy backend.
    pub ready: AtomicBool,
}

impl MetricsState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn render(&self) -> String {
        let g = |v: &AtomicU64| v.load(Ordering::Relaxed);
        format!(
            "# HELP l4_packets_routed_total Packets DNAT'd to a backend.\n\
             # TYPE l4_packets_routed_total counter\n\
             l4_packets_routed_total {}\n\
             # HELP l4_packets_dropped_total Packets dropped, by reason.\n\
             # TYPE l4_packets_dropped_total counter\n\
             l4_packets_dropped_total{{reason=\"validation\"}} {}\n\
             l4_packets_dropped_total{{reason=\"blocked\"}} {}\n\
             l4_packets_dropped_total{{reason=\"rate\"}} {}\n\
             l4_packets_dropped_total{{reason=\"no_backend\"}} {}\n\
             # HELP l4_backends Backend counts.\n\
             # TYPE l4_backends gauge\n\
             l4_backends{{state=\"total\"}} {}\n\
             l4_backends{{state=\"healthy\"}} {}\n",
            g(&self.routed),
            g(&self.dropped_validation),
            g(&self.dropped_blocked),
            g(&self.dropped_rate),
            g(&self.dropped_nobackend),
            g(&self.backends_total),
            g(&self.backends_healthy),
        )
    }
}

/// Run the metrics/health HTTP server until the process exits.
pub async fn serve(addr: String, state: Arc<MetricsState>) -> Result<()> {
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("binding metrics endpoint on {addr}"))?;
    log::info!("metrics/health endpoint listening on {addr}");

    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        let state = state.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let n = match sock.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };
            let req = String::from_utf8_lossy(&buf[..n]);
            let path = req
                .split_whitespace()
                .nth(1) // "GET <path> HTTP/1.1"
                .unwrap_or("/");

            let (status, content_type, body) = match path {
                "/metrics" => ("200 OK", "text/plain; version=0.0.4", state.render()),
                "/healthz" => {
                    if state.ready.load(Ordering::Relaxed) {
                        ("200 OK", "text/plain", "ok\n".to_string())
                    } else {
                        ("503 Service Unavailable", "text/plain", "no healthy backends\n".to_string())
                    }
                }
                _ => ("404 Not Found", "text/plain", "not found\n".to_string()),
            };

            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
            );
            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.shutdown().await;
        });
    }
}
