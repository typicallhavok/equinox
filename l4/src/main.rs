mod config;
mod dataplane;
mod discovery;
mod health;
mod maglev;
mod metrics;

use std::{
    path::{Path, PathBuf},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use anyhow::{Context as _, Result};
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
use config::Config;
use dataplane::DataPlane;
use log::{error, info, warn};
use metrics::MetricsState;
use tokio::{signal, sync::mpsc};

#[derive(Debug, Parser)]
struct Opt {
    /// Network interface to attach the XDP shield to.
    /// Auto-detected from the default route when unset.
    #[clap(short, long, env = "IFACE")]
    iface: Option<String>,

    /// Path to the YAML configuration file.
    #[clap(short, long, env = "CONFIG", default_value = "config.yaml")]
    config: PathBuf,
}

/// Find the interface that owns the default route (`/proc/net/route`), so a bare
/// `docker run` with host networking just works without naming the NIC.
fn detect_default_iface() -> Result<String> {
    let route = std::fs::read_to_string("/proc/net/route").context("reading /proc/net/route")?;
    for line in route.lines().skip(1) {
        let mut cols = line.split_whitespace();
        // Columns: Iface Destination Gateway Flags ...
        if let (Some(iface), Some(dest)) = (cols.next(), cols.next()) {
            if dest == "00000000" {
                return Ok(iface.to_string());
            }
        }
    }
    anyhow::bail!("no default route found; pass --iface or set IFACE")
}

/// Attach the XDP program, honouring the configured mode and falling back from
/// native (driver) to SKB mode when "auto" is requested.
fn attach_xdp(program: &mut Xdp, iface: &str, mode: &str) -> Result<()> {
    let modes: &[(XdpFlags, &str)] = match mode {
        "skb" => &[(XdpFlags::SKB_MODE, "skb")],
        "drv" | "native" => &[(XdpFlags::DRV_MODE, "native")],
        "hw" => &[(XdpFlags::HW_MODE, "hardware")],
        _ => &[(XdpFlags::DRV_MODE, "native"), (XdpFlags::SKB_MODE, "skb")],
    };

    let mut last_err = None;
    for (flags, name) in modes {
        match program.attach(iface, *flags) {
            Ok(_) => {
                info!("XDP shield attached to {iface} in {name} mode");
                return Ok(());
            }
            Err(e) => {
                warn!("attach in {name} mode failed: {e}");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap()).context("failed to attach the XDP program in any mode")
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    env_logger::init();

    let iface = match &opt.iface {
        Some(i) => i.clone(),
        None => {
            let detected = detect_default_iface()?;
            info!("auto-detected interface: {detected}");
            detected
        }
    };

    // Bump the memlock rlimit for older kernels without memcg-based accounting.
    // See https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Load + attach the eBPF data plane.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/l4")))?;

    let xdp_mode = Config::load(&opt.config)
        .map(|c| c.xdp_mode().to_string())
        .unwrap_or_else(|_| "auto".to_string());

    let program: &mut Xdp = ebpf.program_mut("l4").unwrap().try_into()?;
    program.load()?;
    attach_xdp(program, &iface, &xdp_mode)?;

    // Bring up the userspace control plane and program the initial state.
    let mut dp = DataPlane::new(&mut ebpf)?;
    let metrics = MetricsState::new();

    // Optional observability endpoint (only when configured).
    if let Some(addr) = Config::load(&opt.config)
        .ok()
        .and_then(|c| c.metrics_addr())
    {
        let m = metrics.clone();
        tokio::spawn(async move {
            if let Err(e) = metrics::serve(addr, m).await {
                error!("metrics server stopped: {e:#}");
            }
        });
    }

    if let Err(e) = reload(&opt.config, &mut dp, &metrics).await {
        // Don't abort on a bad first load; keep the shield up and retry on the
        // next reload trigger so we never take the data plane down.
        error!("initial config load failed: {e:#}");
    }

    // Hot reload: react to config-file edits and poll discovery on an interval.
    let (tx, mut rx) = mpsc::channel::<()>(8);
    let _watcher = watch_config(&opt.config, tx);

    let interval = Config::load(&opt.config)
        .map(|c| c.sync_interval())
        .unwrap_or_else(|_| Duration::from_millis(3000));
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    info!("ingress shield up; hot reload active (poll every {interval:?})");

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("signal received, detaching XDP and shutting down");
                break;
            }
            _ = ticker.tick() => {
                if let Err(e) = reload(&opt.config, &mut dp, &metrics).await {
                    warn!("discovery reload failed: {e:#}");
                }
            }
            Some(()) = rx.recv() => {
                info!("config change detected, reloading");
                if let Err(e) = reload(&opt.config, &mut dp, &metrics).await {
                    warn!("config reload failed: {e:#}");
                }
            }
        }
    }

    // Dropping `ebpf` here detaches the XDP program and frees its maps.
    Ok(())
}

/// Wait for either SIGINT (Ctrl-C) or SIGTERM (container stop).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

/// Re-read config, re-discover + health-check backends, rebuild the table, flip
/// the buffer, and refresh metrics.
async fn reload(path: &Path, dp: &mut DataPlane, metrics: &Arc<MetricsState>) -> Result<()> {
    let cfg = Config::load(path)?;
    let listen_ports = cfg.listen_ports();

    dp.set_ports(&listen_ports)?;
    dp.set_drop_unmatched(cfg.discovery.drop_unmatched)?;
    dp.set_protection(cfg.protection_settings())?;

    let mut backends = discovery::discover(&cfg).await?;
    let total = backends.len();

    if cfg.health_check_enabled() {
        let default_port = listen_ports.first().copied().unwrap_or(80);
        backends = health::filter_healthy(
            backends,
            cfg.health_probe_port(),
            default_port,
            cfg.health_timeout(),
        )
        .await;
    }
    let healthy = backends.len();

    let keys: Vec<String> = backends.iter().map(|b| b.key()).collect();
    let table = maglev::build_table(&keys);
    dp.apply(&backends, &table)?;

    // Refresh metrics snapshot from the eBPF stats map.
    let s = dp.read_stats();
    metrics.routed.store(s.routed, Ordering::Relaxed);
    metrics
        .dropped_validation
        .store(s.dropped_validation, Ordering::Relaxed);
    metrics
        .dropped_blocked
        .store(s.dropped_blocked, Ordering::Relaxed);
    metrics
        .dropped_rate
        .store(s.dropped_rate, Ordering::Relaxed);
    metrics
        .dropped_nobackend
        .store(s.dropped_nobackend, Ordering::Relaxed);
    metrics
        .backends_total
        .store(total as u64, Ordering::Relaxed);
    metrics
        .backends_healthy
        .store(healthy as u64, Ordering::Relaxed);
    metrics.ready.store(healthy > 0, Ordering::Relaxed);

    info!("reloaded: {healthy}/{total} backend(s) healthy");
    Ok(())
}

/// Watch the config file's directory and signal `tx` on any change to it.
///
/// Watching the parent directory (rather than the file) survives the
/// rename-on-save pattern used by most editors. The returned watcher must be
/// kept alive for events to keep flowing.
fn watch_config(path: &Path, tx: mpsc::Sender<()>) -> Option<notify::RecommendedWatcher> {
    use notify::{EventKind, RecursiveMode, Watcher};

    let path = path.to_path_buf();
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let watch_target = dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let file_name = path.file_name().map(|n| n.to_os_string());

    let mut watcher =
        match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            let Ok(event) = res else { return };
            if !matches!(
                event.kind,
                EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
            ) {
                return;
            }
            // Only react to the config file itself.
            let touched = match &file_name {
                Some(name) => event
                    .paths
                    .iter()
                    .any(|p| p.file_name() == Some(name.as_os_str())),
                None => true,
            };
            if touched {
                let _ = tx.try_send(());
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                warn!("config file watch disabled: {e}");
                return None;
            }
        };

    if let Err(e) = watcher.watch(&watch_target, RecursiveMode::NonRecursive) {
        warn!("could not watch {}: {e}", watch_target.display());
        return None;
    }
    Some(watcher)
}
