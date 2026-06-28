//! Backend discovery: static lists, Docker containers, or DNS names.
//!
//! Every strategy resolves to a set of [`Backend`]s carrying the IPv4 address,
//! an optional destination port (`None` keeps the original listen port), and the
//! L2 MAC the data plane rewrites the Ethernet destination to. For XDP_TX to
//! deliver the frame, backends must be reachable on the same L2 segment as the
//! shield's interface.

use crate::config::{Config, Strategy};
use anyhow::{Context as _, Result, anyhow, bail};
use bollard::Docker;
use bollard::container::ListContainersOptions;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

/// A resolved backend the data plane can route to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backend {
    pub ip: Ipv4Addr,
    /// `None` keeps the packet's original destination port.
    pub port: Option<u16>,
    pub mac: [u8; 6],
}

impl Backend {
    /// Stable key used to seed the Maglev permutation. Independent of MAC so a
    /// neighbour-table refresh doesn't reshuffle the whole table.
    pub fn key(&self) -> String {
        format!("{}:{}", self.ip, self.port.unwrap_or(0))
    }
}

/// Resolve the current backend set for `cfg`.
pub async fn discover(cfg: &Config) -> Result<Vec<Backend>> {
    match cfg.discovery.strategy {
        Strategy::Static => discover_static(cfg),
        Strategy::Docker => discover_docker(cfg).await,
        Strategy::Dns => discover_dns(cfg).await,
    }
}

fn discover_static(cfg: &Config) -> Result<Vec<Backend>> {
    let routes = cfg
        .discovery
        .static_routes
        .as_ref()
        .ok_or_else(|| anyhow!("strategy 'static' requires discovery.static_routes"))?;

    let mut backends = Vec::with_capacity(routes.len());
    for route in routes {
        let (ip, parsed_port) = parse_endpoint(&route.ip)
            .with_context(|| format!("invalid static route ip {:?}", route.ip))?;
        let port = route.port.or(parsed_port);

        let mac = match &route.mac {
            Some(s) => parse_mac(s).with_context(|| format!("invalid mac {s:?}"))?,
            None => resolve_mac(ip)
                .with_context(|| format!("no mac for {ip}; set it explicitly in config"))?,
        };

        backends.push(Backend { ip, port, mac });
    }
    Ok(backends)
}

async fn discover_docker(cfg: &Config) -> Result<Vec<Backend>> {
    let docker =
        Docker::connect_with_local_defaults().context("connecting to the Docker daemon")?;

    // Match either a Docker network membership or a service/container name.
    let network = cfg.discovery.network.clone();
    let service = cfg.discovery.target_service_name.clone();
    if network.is_none() && service.is_none() {
        bail!("strategy 'docker' requires discovery.network or discovery.target_service_name");
    }

    let mut filters: HashMap<String, Vec<String>> = HashMap::new();
    if let Some(net) = &network {
        filters.insert("network".to_string(), vec![net.clone()]);
    }

    let containers = docker
        .list_containers(Some(ListContainersOptions {
            all: false, // running only
            filters,
            ..Default::default()
        }))
        .await
        .context("listing Docker containers")?;

    let mut backends = Vec::new();
    for c in containers {
        // When matching by service name, filter on the compose service label or
        // the container name.
        if let Some(svc) = &service {
            let matches_label = c
                .labels
                .as_ref()
                .and_then(|l| l.get("com.docker.compose.service"))
                .is_some_and(|v| v == svc);
            let matches_name = c
                .names
                .as_ref()
                .is_some_and(|names| names.iter().any(|n| n.trim_start_matches('/').contains(svc)));
            if !matches_label && !matches_name {
                continue;
            }
        }

        let Some(settings) = c.network_settings else {
            continue;
        };
        let Some(networks) = settings.networks else {
            continue;
        };

        // Prefer the configured network; otherwise take the first usable one.
        let candidate = match &network {
            Some(net) => networks.get(net),
            None => networks.values().next(),
        };
        let Some(epn) = candidate else { continue };

        let Some(ip_str) = epn.ip_address.as_ref().filter(|s| !s.is_empty()) else {
            continue;
        };
        let ip: Ipv4Addr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };

        let mac = match epn.mac_address.as_ref().filter(|s| !s.is_empty()) {
            Some(s) => parse_mac(s).with_context(|| format!("bad docker mac {s:?}"))?,
            None => match resolve_mac(ip) {
                Some(m) => m,
                None => continue,
            },
        };

        backends.push(Backend {
            ip,
            port: cfg.discovery.target_port,
            mac,
        });
    }

    backends.sort_by_key(|b| b.ip);
    backends.dedup();
    Ok(backends)
}

async fn discover_dns(cfg: &Config) -> Result<Vec<Backend>> {
    let host = cfg
        .discovery
        .target_service_name
        .as_ref()
        .ok_or_else(|| anyhow!("strategy 'dns' requires discovery.target_service_name"))?;
    let port = cfg.discovery.target_port.unwrap_or(443);

    // Resolve A records; AAAA is ignored since the data plane is IPv4-only.
    let addrs = tokio::net::lookup_host((host.as_str(), port))
        .await
        .with_context(|| format!("resolving {host}"))?;

    let mut backends = Vec::new();
    for addr in addrs {
        let IpAddr::V4(ip) = addr.ip() else { continue };
        let Some(mac) = resolve_mac(ip) else { continue };
        backends.push(Backend {
            ip,
            port: cfg.discovery.target_port,
            mac,
        });
    }

    backends.sort_by_key(|b| b.ip);
    backends.dedup();
    if backends.is_empty() {
        bail!("dns resolved no IPv4 backends with a known MAC for {host}");
    }
    Ok(backends)
}

/// Parse `"1.2.3.4"` or `"1.2.3.4:3000"` into an address and optional port.
fn parse_endpoint(s: &str) -> Result<(Ipv4Addr, Option<u16>)> {
    if let Some((ip, port)) = s.rsplit_once(':') {
        // Only treat the suffix as a port when the prefix is a valid IPv4.
        if let Ok(ip) = ip.parse::<Ipv4Addr>() {
            let port: u16 = port.parse().with_context(|| format!("bad port in {s:?}"))?;
            return Ok((ip, Some(port)));
        }
    }
    Ok((s.parse().with_context(|| format!("bad ipv4 {s:?}"))?, None))
}

/// Parse a `aa:bb:cc:dd:ee:ff` MAC address.
fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = s.split(':');
    for (i, slot) in mac.iter_mut().enumerate() {
        let part = parts
            .next()
            .ok_or_else(|| anyhow!("mac {s:?} has fewer than 6 octets"))?;
        *slot = u8::from_str_radix(part, 16)
            .with_context(|| format!("bad mac octet {part:?} (slot {i})"))?;
    }
    if parts.next().is_some() {
        bail!("mac {s:?} has more than 6 octets");
    }
    Ok(mac)
}

/// Resolve an IPv4's MAC from the host neighbour table (`/proc/net/arp`).
///
/// Returns `None` if there is no entry yet (the kernel only populates it after
/// traffic to the host). For such cases, set the MAC explicitly in config.
fn resolve_mac(ip: Ipv4Addr) -> Option<[u8; 6]> {
    let arp = std::fs::read_to_string("/proc/net/arp").ok()?;
    let target = ip.to_string();
    // Columns: IP address, HW type, Flags, HW address, Mask, Device
    for line in arp.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let entry_ip = cols.next()?;
        if entry_ip != target {
            continue;
        }
        let hw = cols.nth(2)?; // skip HW type + Flags
        if hw == "00:00:00:00:00:00" {
            continue;
        }
        if let Ok(mac) = parse_mac(hw) {
            return Some(mac);
        }
    }
    None
}
