//! Configuration parsing for the ingress shield.
//!
//! The format mirrors a simple nginx-style proxy config: a `gateway` block of
//! public ports to intercept and a `discovery` block describing where the
//! backends live (static list, Docker, or DNS), plus optional `protection`,
//! `health_check`, and `observability` blocks.

use anyhow::{Context as _, Result};
use serde::Deserialize;
use std::{path::Path, time::Duration};

fn default_true() -> bool {
    true
}

/// How backends are discovered.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Strategy {
    /// A fixed list of backends from `static_routes`.
    Static,
    /// Containers discovered via the Docker API.
    Docker,
    /// Hostname(s) resolved via DNS.
    Dns,
}

/// Public-facing ports to intercept on the host.
#[derive(Debug, Clone, Deserialize)]
pub struct Gateway {
    pub listen_ports: Vec<u16>,
    /// XDP attach mode: "auto" (default), "skb", "drv"/"native", or "hw".
    #[serde(default)]
    pub xdp_mode: Option<String>,
}

/// A statically configured backend. `ip` may be `"1.2.3.4"` or `"1.2.3.4:3000"`;
/// an explicit `port` field takes precedence. `mac` is optional and resolved
/// from the host neighbour table when omitted.
#[derive(Debug, Clone, Deserialize)]
pub struct StaticRoute {
    pub ip: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub mac: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Discovery {
    pub strategy: Strategy,
    #[serde(default)]
    pub target_service_name: Option<String>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub target_port: Option<u16>,
    #[serde(default)]
    pub sync_interval_ms: Option<u64>,
    #[serde(default)]
    pub static_routes: Option<Vec<StaticRoute>>,
    #[serde(default)]
    pub drop_unmatched: bool,
}

/// Per-source-IP abuse protection. A source that exceeds `rate_limit_per_sec`
/// valid requests or `malformed_limit` malformed packets within `window_ms` is
/// blacklisted for `block_duration_secs`.
#[derive(Debug, Clone, Deserialize)]
pub struct Protection {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub rate_limit_per_sec: Option<u32>,
    #[serde(default)]
    pub malformed_limit: Option<u32>,
    #[serde(default)]
    pub window_ms: Option<u32>,
    #[serde(default)]
    pub block_duration_secs: Option<u32>,
}

/// Active TCP health checking of backends.
#[derive(Debug, Clone, Deserialize)]
pub struct HealthCheck {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Probe this port instead of the backend's routed/listen port.
    #[serde(default)]
    pub port: Option<u16>,
}

/// Optional observability endpoint. Disabled unless `metrics_addr` is set.
#[derive(Debug, Clone, Deserialize)]
pub struct Observability {
    /// e.g. "0.0.0.0:9100" — serves `/metrics` (Prometheus) and `/healthz`.
    #[serde(default)]
    pub metrics_addr: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub gateway: Option<Gateway>,
    pub discovery: Discovery,
    #[serde(default)]
    pub protection: Option<Protection>,
    #[serde(default)]
    pub health_check: Option<HealthCheck>,
    #[serde(default)]
    pub observability: Option<Observability>,
}

/// Resolved protection thresholds pushed into the data plane. `rate_max` /
/// `malformed_max` of `0` disable the respective check.
#[derive(Debug, Clone, Copy)]
pub struct ProtectionSettings {
    pub rate_max: u32,
    pub window_ms: u32,
    pub malformed_max: u32,
    pub block_secs: u32,
}

impl Config {
    /// Parse the YAML configuration at `path`.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let yaml = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let config: Config = serde_yaml::from_str(&yaml)
            .with_context(|| format!("parsing config {}", path.display()))?;
        Ok(config)
    }

    /// Ports the shield should intercept, defaulting to HTTP/HTTPS.
    pub fn listen_ports(&self) -> Vec<u16> {
        match &self.gateway {
            Some(g) if !g.listen_ports.is_empty() => g.listen_ports.clone(),
            _ => vec![80, 443],
        }
    }

    /// Discovery poll interval, defaulting to 3s.
    pub fn sync_interval(&self) -> Duration {
        Duration::from_millis(self.discovery.sync_interval_ms.unwrap_or(3000))
    }

    /// XDP attach mode, defaulting to "auto".
    pub fn xdp_mode(&self) -> &str {
        self.gateway
            .as_ref()
            .and_then(|g| g.xdp_mode.as_deref())
            .unwrap_or("auto")
    }

    /// Resolved protection thresholds. Defaults to enabled with conservative,
    /// abuse-level limits so it never trips on legitimate per-client traffic.
    pub fn protection_settings(&self) -> ProtectionSettings {
        match &self.protection {
            // Explicitly disabled.
            Some(p) if !p.enabled => ProtectionSettings {
                rate_max: 0,
                window_ms: 1000,
                malformed_max: 0,
                block_secs: 300,
            },
            // Enabled (explicitly or by default).
            other => ProtectionSettings {
                rate_max: other
                    .as_ref()
                    .and_then(|p| p.rate_limit_per_sec)
                    .unwrap_or(5000),
                window_ms: other.as_ref().and_then(|p| p.window_ms).unwrap_or(1000),
                malformed_max: other
                    .as_ref()
                    .and_then(|p| p.malformed_limit)
                    .unwrap_or(20),
                block_secs: other
                    .as_ref()
                    .and_then(|p| p.block_duration_secs)
                    .unwrap_or(300),
            },
        }
    }

    /// Whether active backend health checking is enabled (default true).
    pub fn health_check_enabled(&self) -> bool {
        self.health_check.as_ref().map(|h| h.enabled).unwrap_or(true)
    }

    /// Health-check connect timeout, defaulting to 500ms.
    pub fn health_timeout(&self) -> Duration {
        Duration::from_millis(
            self.health_check
                .as_ref()
                .and_then(|h| h.timeout_ms)
                .unwrap_or(500),
        )
    }

    /// Explicit health-check probe port override, if any.
    pub fn health_probe_port(&self) -> Option<u16> {
        self.health_check.as_ref().and_then(|h| h.port)
    }

    /// Metrics/health bind address, if observability is enabled.
    pub fn metrics_addr(&self) -> Option<String> {
        self.observability
            .as_ref()
            .and_then(|o| o.metrics_addr.clone())
    }
}
