//! Userspace side of the double-buffered data plane.
//!
//! Owns the eBPF maps and applies updates by filling the *standby* buffer, then
//! flipping the single `CTRL_ACTIVE` value so the data plane switches over
//! atomically. The XDP program is never detached, so traffic keeps flowing
//! across reloads.

use anyhow::{Context as _, Result};
use aya::{
    Ebpf,
    maps::{Array, HashMap, MapData, PerCpuArray},
};
use l4_common::{
    CTRL_ACTIVE, CTRL_BLOCK_SECS, CTRL_DROP_UNMATCHED, CTRL_MALFORMED_MAX, CTRL_RATE_MAX,
    CTRL_RATE_WINDOW_MS, M, N, Node, STAT_DROPPED_BLOCKED, STAT_DROPPED_NOBACKEND,
    STAT_DROPPED_RATE, STAT_DROPPED_VALIDATION, STAT_ROUTED,
};

use crate::{config::ProtectionSettings, discovery::Backend};

/// Data-plane counters scraped from the eBPF per-CPU stats map.
#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub routed: u64,
    pub dropped_validation: u64,
    pub dropped_blocked: u64,
    pub dropped_rate: u64,
    pub dropped_nobackend: u64,
}

pub struct DataPlane {
    route: Array<MapData, u32>,
    backends: HashMap<MapData, u32, Node>,
    ctrl: Array<MapData, u32>,
    ports: HashMap<MapData, u16, u8>,
    stats: PerCpuArray<MapData, u64>,
    /// Buffer the data plane is currently reading from.
    active: u32,
    /// Ports currently programmed into `PORT_MAP`, so we can diff on reload.
    installed_ports: Vec<u16>,
}

impl DataPlane {
    /// Take ownership of the maps from a loaded eBPF object and initialise CTRL.
    pub fn new(ebpf: &mut Ebpf) -> Result<Self> {
        let route = Array::try_from(take_map(ebpf, "ROUTE_MAP")?)?;
        let backends = HashMap::try_from(take_map(ebpf, "BACKEND_MAP")?)?;
        let mut ctrl = Array::try_from(take_map(ebpf, "CTRL")?)?;
        let ports = HashMap::try_from(take_map(ebpf, "PORT_MAP")?)?;
        let stats = PerCpuArray::try_from(take_map(ebpf, "STATS")?)?;

        // Start on buffer 0 with passthrough for unmatched traffic.
        ctrl.set(CTRL_ACTIVE, 0u32, 0)?;
        ctrl.set(CTRL_DROP_UNMATCHED, 0u32, 0)?;

        Ok(Self {
            route,
            backends,
            ctrl,
            ports,
            stats,
            active: 0,
            installed_ports: Vec::new(),
        })
    }

    /// Push abuse-protection thresholds into the data plane.
    pub fn set_protection(&mut self, p: ProtectionSettings) -> Result<()> {
        self.ctrl.set(CTRL_RATE_MAX, p.rate_max, 0)?;
        self.ctrl.set(CTRL_RATE_WINDOW_MS, p.window_ms, 0)?;
        self.ctrl.set(CTRL_MALFORMED_MAX, p.malformed_max, 0)?;
        self.ctrl.set(CTRL_BLOCK_SECS, p.block_secs, 0)?;
        Ok(())
    }

    /// Read and sum the per-CPU data-plane counters.
    pub fn read_stats(&self) -> Stats {
        let sum = |idx: u32| -> u64 {
            self.stats
                .get(&idx, 0)
                .map(|vals| vals.iter().copied().sum())
                .unwrap_or(0)
        };
        Stats {
            routed: sum(STAT_ROUTED),
            dropped_validation: sum(STAT_DROPPED_VALIDATION),
            dropped_blocked: sum(STAT_DROPPED_BLOCKED),
            dropped_rate: sum(STAT_DROPPED_RATE),
            dropped_nobackend: sum(STAT_DROPPED_NOBACKEND),
        }
    }

    /// Set whether validated-but-unrouted packets are dropped.
    pub fn set_drop_unmatched(&mut self, drop: bool) -> Result<()> {
        self.ctrl
            .set(CTRL_DROP_UNMATCHED, drop as u32, 0)
            .context("writing CTRL_DROP_UNMATCHED")
    }

    /// Reconcile the load-balanced port set, adding/removing entries as needed.
    pub fn set_ports(&mut self, ports: &[u16]) -> Result<()> {
        for &p in ports {
            if !self.installed_ports.contains(&p) {
                self.ports
                    .insert(p, 1u8, 0)
                    .context("inserting listen port")?;
            }
        }
        for &p in &self.installed_ports {
            if !ports.contains(&p) {
                let _ = self.ports.remove(&p);
            }
        }
        self.installed_ports = ports.to_vec();
        Ok(())
    }

    /// Apply a new backend set + Maglev table to the standby buffer, then flip.
    ///
    /// `table` has length `M`; each entry is a *local* backend index (or
    /// `u32::MAX` for an empty slot).
    pub fn apply(&mut self, backends: &[Backend], table: &[u32]) -> Result<()> {
        anyhow::ensure!(
            backends.len() as u32 <= N,
            "{} backends exceeds the per-buffer limit of {N}",
            backends.len()
        );
        anyhow::ensure!(table.len() as u32 == M, "table must have exactly M entries");

        let standby = 1 - self.active;
        let base_id = standby * N;

        // 1. Fill the standby backend table.
        for (i, b) in backends.iter().enumerate() {
            let node = Node {
                daddr: b.ip.to_bits(),
                dport: b.port.unwrap_or(0),
                dmac: b.mac,
            };
            self.backends
                .insert(base_id + i as u32, node, 0)
                .context("inserting backend node")?;
        }

        // 2. Fill the standby route table with global backend ids.
        let route_base = standby * M;
        for (slot, &local) in table.iter().enumerate() {
            let value = if local == u32::MAX {
                u32::MAX // sentinel: data plane lookup misses -> pass/drop
            } else {
                base_id + local
            };
            self.route
                .set(route_base + slot as u32, value, 0)
                .context("writing route slot")?;
        }

        // 3. Atomically switch the data plane to the freshly built buffer.
        self.ctrl
            .set(CTRL_ACTIVE, standby, 0)
            .context("flipping active buffer")?;
        self.active = standby;
        Ok(())
    }
}

fn take_map(ebpf: &mut Ebpf, name: &str) -> Result<aya::maps::Map> {
    ebpf.take_map(name)
        .with_context(|| format!("eBPF map {name} not found"))
}
