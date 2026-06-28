#![no_std]
#![no_main]
// Aya maps are accessed through `static mut`; taking method receivers on them
// trips the 2024-edition `static_mut_refs` lint. This is the documented aya
// pattern, so silence it crate-wide.
#![allow(static_mut_refs)]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{Array, HashMap, LruHashMap, PerCpuArray},
    programs::XdpContext,
};
use l4_common::{
    BUFFERS, CTRL_ACTIVE, CTRL_BLOCK_SECS, CTRL_DROP_UNMATCHED, CTRL_LEN, CTRL_MALFORMED_MAX,
    CTRL_RATE_MAX, CTRL_RATE_WINDOW_MS, M, N, Node, RateState, STAT_DROPPED_BLOCKED,
    STAT_DROPPED_NOBACKEND, STAT_DROPPED_RATE, STAT_DROPPED_VALIDATION, STAT_ROUTED, STATS_LEN,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// TCP flag bits (byte 13 of the TCP header).
const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const URG: u8 = 0x20;

/// Maglev lookup table, double-buffered: `[buffer 0 | buffer 1]`, each `M` long.
/// Each slot stores a *global* backend id (`buffer * N + local_id`).
#[map]
static mut ROUTE_MAP: Array<u32> = Array::with_max_entries(M * BUFFERS, 0);

/// Backend table, double-buffered and keyed by the global backend id stored in
/// `ROUTE_MAP`, so a single active-buffer flip switches both tables atomically.
#[map]
static mut BACKEND_MAP: HashMap<u32, Node> = HashMap::with_max_entries(N * BUFFERS, 0);

/// Control values written by userspace. See `CTRL_*` indices in `l4-common`.
#[map]
static mut CTRL: Array<u32> = Array::with_max_entries(CTRL_LEN, 0);

/// Set of destination ports that should be load-balanced/routed. Everything else is
/// passed straight to the host stack so we never break unrelated traffic.
#[map]
static mut PORT_MAP: HashMap<u16, u8> = HashMap::with_max_entries(64, 0);

/// Source IPs currently blacklisted, value = expiry timestamp (ns).
#[map]
static mut BLOCKLIST: LruHashMap<u32, u64> = LruHashMap::with_max_entries(131072, 0);

/// Per-source-IP sliding-window counters used to decide blacklisting.
#[map]
static mut RATE: LruHashMap<u32, RateState> = LruHashMap::with_max_entries(131072, 0);

/// Per-CPU counters scraped by userspace for metrics. See `STAT_*` indices.
#[map]
static mut STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(STATS_LEN, 0);

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn ctrl(idx: u32) -> u32 {
    unsafe { *CTRL.get(idx).unwrap_or(&0) }
}

#[inline(always)]
fn stat(idx: u32) {
    unsafe {
        if let Some(p) = STATS.get_ptr_mut(idx) {
            *p += 1;
        }
    }
}

/// Incremental 16-bit one's-complement checksum update (RFC 1624):
/// `HC' = ~(~HC + ~m + m')`. All values are the plain 16-bit numeric words.
#[inline(always)]
fn csum_replace(hc: u16, old: u16, new: u16) -> u16 {
    let mut sum: u32 = (!hc as u32) & 0xFFFF;
    sum += (!old as u32) & 0xFFFF;
    sum += new as u32;
    // Fold carries (at most two folds are ever needed).
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    !(sum as u16)
}

#[xdp]
pub fn l4(ctx: XdpContext) -> u32 {
    match try_l4(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_l4(ctx: XdpContext) -> Result<u32, u32> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0) }.map_err(|_| xdp_action::XDP_PASS)?;

    // Only IPv4 is handled; everything else is passed through untouched.
    if let Ok(EtherType::Ipv4) = unsafe { (*ethhdr).ether_type() } {
        let ipv4hdr: *const Ipv4Hdr =
            unsafe { ptr_at(&ctx, EthHdr::LEN) }.map_err(|_| xdp_action::XDP_PASS)?;
        let source_addr = unsafe { (*ipv4hdr).src_addr() };
        let dest_addr = unsafe { (*ipv4hdr).dst_addr() };

        let l4_off = EthHdr::LEN + Ipv4Hdr::LEN;

        let (source_port, dest_port, is_tcp) = match unsafe { (*ipv4hdr).proto } {
            IpProto::Tcp => {
                let tcphdr: *const TcpHdr =
                    unsafe { ptr_at(&ctx, l4_off) }.map_err(|_| xdp_action::XDP_PASS)?;
                (
                    u16::from_be_bytes(unsafe { (*tcphdr).source }),
                    u16::from_be_bytes(unsafe { (*tcphdr).dest }),
                    true,
                )
            }
            IpProto::Udp => {
                let udphdr: *const UdpHdr =
                    unsafe { ptr_at(&ctx, l4_off) }.map_err(|_| xdp_action::XDP_PASS)?;
                unsafe { ((*udphdr).src_port(), (*udphdr).dst_port(), false) }
            }
            _ => return Ok(xdp_action::XDP_PASS),
        };

        // ---- forwarding plane: only configured listen ports are inspected ----
        if unsafe { PORT_MAP.get(&dest_port) }.is_none() {
            // Not a load-balanced port: leave it entirely to the host stack so we never
            // disrupt SSH, the control plane, or any other local traffic.
            return Ok(xdp_action::XDP_PASS);
        }

        let src = source_addr.to_bits();
        let now = unsafe { bpf_ktime_get_ns() };

        // ---- blacklist: drop everything from a blocked source until it expires ----
        if let Some(expiry) = unsafe { BLOCKLIST.get(&src) } {
            if now < *expiry {
                stat(STAT_DROPPED_BLOCKED);
                return Ok(xdp_action::XDP_DROP);
            }
        }

        // ---- validation (load-balanced ports only) ----
        let is_malformed = if is_tcp {
            // Flags live in byte 13 of the TCP header.
            let flags_ptr: *const u8 =
                unsafe { ptr_at(&ctx, l4_off + 13) }.map_err(|_| xdp_action::XDP_DROP)?;
            let f = unsafe { *flags_ptr };
            f == 0                                     // NULL scan
                || (f & SYN != 0 && f & FIN != 0)     // SYN+FIN
                || (f & SYN != 0 && f & RST != 0)     // SYN+RST
                || (f & FIN != 0 && f & RST != 0)     // FIN+RST
                || (f & (FIN | PSH | URG) == (FIN | PSH | URG)) // XMAS
        } else {
            false
        };

        // ---- abuse tracking: rate + malformed counters -> blacklist ----
        let rate_max = ctrl(CTRL_RATE_MAX);
        let malformed_max = ctrl(CTRL_MALFORMED_MAX);
        if rate_max > 0 || malformed_max > 0 {
            let window_ns = (ctrl(CTRL_RATE_WINDOW_MS).max(1) as u64) * 1_000_000;
            let block_ns = (ctrl(CTRL_BLOCK_SECS) as u64) * 1_000_000_000;

            let tripped = unsafe {
                if let Some(p) = RATE.get_ptr_mut(&src) {
                    let s = &mut *p;
                    if now.wrapping_sub(s.window_start) > window_ns {
                        s.window_start = now;
                        s.count = 0;
                        s.malformed = 0;
                    }
                    if is_malformed {
                        s.malformed += 1;
                    } else {
                        s.count += 1;
                    }
                    (rate_max > 0 && s.count > rate_max)
                        || (malformed_max > 0 && s.malformed > malformed_max)
                } else {
                    let s = RateState {
                        window_start: now,
                        count: if is_malformed { 0 } else { 1 },
                        malformed: u32::from(is_malformed),
                    };
                    let _ = RATE.insert(&src, &s, 0);
                    false
                }
            };

            if tripped {
                let _ = unsafe { BLOCKLIST.insert(&src, &(now + block_ns), 0) };
                stat(STAT_DROPPED_RATE);
                return Ok(xdp_action::XDP_DROP);
            }
        }

        if is_malformed {
            stat(STAT_DROPPED_VALIDATION);
            return Ok(xdp_action::XDP_DROP);
        }

        // ---- hash the 4-tuple (FNV-1a) ----
        let mut tuple = [0u8; 12];
        tuple[0..4].copy_from_slice(&source_addr.octets());
        tuple[4..8].copy_from_slice(&dest_addr.octets());
        tuple[8..10].copy_from_slice(&source_port.to_be_bytes());
        tuple[10..12].copy_from_slice(&dest_port.to_be_bytes());

        let mut hash: u32 = 2166136261;
        for byte in tuple {
            hash ^= byte as u32;
            hash = hash.wrapping_mul(16777619);
        }
        let h = hash % M;

        // ---- double-buffered lookup against the active buffer ----
        let active = ctrl(CTRL_ACTIVE);
        let slot = active.wrapping_mul(M).wrapping_add(h);

        let drop_or_pass = if ctrl(CTRL_DROP_UNMATCHED) == 1 {
            xdp_action::XDP_DROP
        } else {
            xdp_action::XDP_PASS
        };

        let backend_id = match unsafe { ROUTE_MAP.get(slot) } {
            Some(id) => *id,
            None => {
                stat(STAT_DROPPED_NOBACKEND);
                return Ok(drop_or_pass);
            }
        };
        let node = match unsafe { BACKEND_MAP.get(&backend_id) } {
            Some(n) => *n,
            None => {
                stat(STAT_DROPPED_NOBACKEND);
                return Ok(drop_or_pass);
            }
        };

        // ---- DNAT rewrite + checksum fix-ups ----
        let backend_ip = node.daddr; // host order
        let old_ip = dest_addr.to_bits(); // host order
        let new_port = if node.dport != 0 {
            node.dport
        } else {
            dest_port
        };

        // The high/low 16-bit words of a host-order IPv4 value equal the
        // big-endian on-wire words, so the checksum math works directly.
        let old_hi = (old_ip >> 16) as u16;
        let old_lo = (old_ip & 0xFFFF) as u16;
        let new_hi = (backend_ip >> 16) as u16;
        let new_lo = (backend_ip & 0xFFFF) as u16;

        // L4 checksum + destination port live at fixed offsets; re-validate the
        // bounds so the verifier is happy before we write through them.
        let l4_cksum_off = if is_tcp { 16 } else { 6 };
        let l4_cksum_ptr = unsafe { ptr_at::<[u8; 2]>(&ctx, l4_off + l4_cksum_off) }
            .map_err(|_| xdp_action::XDP_DROP)? as *mut [u8; 2];
        let dport_ptr = unsafe { ptr_at::<[u8; 2]>(&ctx, l4_off + 2) }
            .map_err(|_| xdp_action::XDP_DROP)? as *mut [u8; 2];

        unsafe {
            let ipv4_ptr = ipv4hdr as *mut Ipv4Hdr;
            let ethr_ptr = ethhdr as *mut EthHdr;

            // IPv4 header checksum: only the destination address changed.
            let mut ipck = u16::from_be_bytes((*ipv4_ptr).check);
            ipck = csum_replace(ipck, old_hi, new_hi);
            ipck = csum_replace(ipck, old_lo, new_lo);

            (*ipv4_ptr).dst_addr = backend_ip.to_be_bytes();
            (*ipv4_ptr).check = ipck.to_be_bytes();
            (*ethr_ptr).dst_addr = node.dmac;

            // L4 (TCP/UDP) checksum carries the IPv4 pseudo-header, so the dst-IP
            // change must be folded in too. UDP checksum 0 means "no checksum".
            let cur = u16::from_be_bytes(*l4_cksum_ptr);
            if is_tcp || cur != 0 {
                let mut l4 = csum_replace(cur, old_hi, new_hi);
                l4 = csum_replace(l4, old_lo, new_lo);
                if new_port != dest_port {
                    l4 = csum_replace(l4, dest_port, new_port);
                }
                // A computed UDP checksum of zero must be transmitted as 0xFFFF.
                let l4 = if !is_tcp && l4 == 0 { 0xFFFF } else { l4 };
                *l4_cksum_ptr = l4.to_be_bytes();
            }

            if new_port != dest_port {
                *dport_ptr = new_port.to_be_bytes();
            }
        }

        stat(STAT_ROUTED);
        return Ok(xdp_action::XDP_TX);
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Kernel-facing license string for the eBPF object. Must be GPL-compatible to
// load programs that use restricted helpers.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
