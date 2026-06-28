#![no_std]

//! Types and constants shared between the userspace control plane (`l4`) and the
//! eBPF data plane (`l4-ebpf`).
//!
//! The data plane is kept dependency-free; only the userspace side pulls in `aya`
//! (via the `user` feature) so that the POD types implement [`aya::Pod`].

/// A single backend the data plane can rewrite a packet towards.
///
/// Field byte-order is chosen to match the arithmetic done in the eBPF program:
/// `daddr` is stored in **host byte order** (same as `Ipv4Addr::to_bits`) so the
/// checksum fix-up can shift/mask it directly. `dmac` is written verbatim into
/// the Ethernet destination. `dport` is the L4 destination port in host order;
/// `0` means "leave the original destination port untouched".
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Node {
    /// Backend IPv4 address, host byte order.
    pub daddr: u32,
    /// Backend L4 port, host byte order. `0` == keep the packet's original port.
    pub dport: u16,
    /// Backend L2 (Ethernet) destination MAC.
    pub dmac: [u8; 6],
}

/// Per-source-IP sliding-window counters backing the abuse blacklist.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RateState {
    /// Start of the current window (ns, from `bpf_ktime_get_ns`).
    pub window_start: u64,
    /// Valid requests seen in the current window.
    pub count: u32,
    /// Malformed packets seen in the current window.
    pub malformed: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Node {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for RateState {}

/// Size of the Maglev lookup table. Must be prime for good distribution.
pub const M: u32 = 65537;

/// Maximum number of backends per buffer. Tuned together with [`M`] so the
/// table distributes near-perfectly across this many backends.
pub const N: u32 = 650;

/// Number of independent table/backend regions used for double-buffering.
/// The data plane reads from one while the control plane rebuilds the other.
pub const BUFFERS: u32 = 2;

// ---- CTRL array indices (u32 values written by userspace) ----

/// Buffer (`0` or `1`) the data plane currently reads.
pub const CTRL_ACTIVE: u32 = 0;
/// `1` = drop validated-but-unrouted packets to a shielded port (else pass).
pub const CTRL_DROP_UNMATCHED: u32 = 1;
/// Max valid requests per window per source IP. `0` disables rate limiting.
pub const CTRL_RATE_MAX: u32 = 2;
/// Sliding-window length in milliseconds.
pub const CTRL_RATE_WINDOW_MS: u32 = 3;
/// Max malformed packets per window per source IP. `0` disables this check.
pub const CTRL_MALFORMED_MAX: u32 = 4;
/// Blacklist duration in seconds once a source trips a threshold.
pub const CTRL_BLOCK_SECS: u32 = 5;
/// Number of CTRL slots to allocate.
pub const CTRL_LEN: u32 = 8;

// ---- STATS per-CPU array indices (u64 counters) ----

pub const STAT_ROUTED: u32 = 0;
pub const STAT_DROPPED_VALIDATION: u32 = 1;
pub const STAT_DROPPED_BLOCKED: u32 = 2;
pub const STAT_DROPPED_RATE: u32 = 3;
pub const STAT_DROPPED_NOBACKEND: u32 = 4;
/// Number of STATS slots to allocate.
pub const STATS_LEN: u32 = 8;
