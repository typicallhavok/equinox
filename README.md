# l4

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## L4 load balancer forwarding plane

`l4` is an XDP-based L4 load balancer forwarding plane: instead of a userspace load balancer,
an eBPF program attached to the NIC validates and routes packets in-kernel. Traffic to the configured
`listen_ports` is checked, hashed with Maglev consistent hashing, and DNAT'd to a backend
with `XDP_TX`. Everything else is passed straight to the host stack, so unrelated traffic
(SSH, etc.) is never disrupted.

The control plane (`l4`, userspace) discovers backends, builds the Maglev table, and pushes
it into the data plane. Updates are **hot-reloaded with zero downtime**: the table is written
into a standby buffer and the data plane is flipped onto it atomically. The XDP program is
never detached.

### Quick start (prebuilt image)

Like nginx, but the config is optional to start. The image ships a default `config.yaml`
baked in, so it runs with **no volume flag at all**. CI publishes the image to GHCR (always)
and Docker Hub (when configured) — see [`.github/workflows/docker.yml`](.github/workflows/docker.yml).

```shell
docker pull ghcr.io/<owner>/<repo>:latest

# zero config — starts on the baked-in default:
docker run --rm --network host --privileged \
  ghcr.io/<owner>/<repo>:latest
```

To use and live-edit your own config, mount the current directory as `/app`. On first run the
forwarding plane **seeds a `config.yaml` template into it for you** if one isn't there yet; edit
that file and it hot-reloads:

```shell
docker run --rm --network host --privileged \
  -v "$(pwd):/app" \
  ghcr.io/<owner>/<repo>:latest
```

The interface is auto-detected from the host's default route; override with `-e IFACE=eth0`.
The config path defaults to `/app/config.yaml` (override with `-e CONFIG=...`). The capability
set `--cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add BPF` works in place of `--privileged`
on most kernels. (`<owner>/<repo>` is filled in by CI to match your GitHub repository; the
Docker Hub image is `<dockerhub-user>/equinox:latest`.)

### Configuration

Config is YAML (see [`config.example.yaml`](config.example.yaml) for every option). Editing
the file while `l4` is running triggers a live reload; backends are also re-discovered every
`sync_interval_ms`.

```yaml
gateway:
  # Ports to intercept on the host. Everything else is passed through untouched.
  listen_ports: [80, 443]

discovery:
  strategy: "static"        # "static" | "docker" | "dns"
  sync_interval_ms: 3000    # re-run discovery this often
  drop_unmatched: false     # drop validated packets to a listen port with no backend

  # strategy: static — backends already on the same L2 segment.
  # "ip" may be "ip" or "ip:port"; "port" overrides; omit both to keep the listen port.
  # "mac" is optional (resolved from the host ARP table when omitted).
  static_routes:
    - ip: "172.18.0.10"
      port: 3000
      mac: "02:42:ac:12:00:0a"

  # strategy: docker — discovers running containers via /var/run/docker.sock.
  # network: "equinox_backends"        # match by Docker network membership
  # target_service_name: "backend"     # and/or compose service name
  # target_port: 80

  # strategy: dns — resolves A records; MAC comes from the host ARP table.
  # target_service_name: "backend.internal"
  # target_port: 443
```

**Validation.** On a load-balanced port, truncated packets and illegal TCP flag combinations
(NULL, SYN+FIN, SYN+RST, FIN+RST, XMAS) are dropped. A valid packet with no backend is
passed through unless `drop_unmatched: true`.

**Abuse protection (blacklist).** Enabled by default. Per source IP, the data plane counts
valid requests and malformed packets in a sliding window; a source that exceeds
`rate_limit_per_sec` or `malformed_limit` is blacklisted in-kernel for `block_duration_secs`
(default 5 minutes), during which all its packets are dropped. Tune in the `protection` block,
or set `enabled: false`. Note: if many clients share one IP (NAT / upstream proxy), raise the
limits accordingly.

**Health checking.** Enabled by default. Each reload, backends are probed with a short TCP
connect; only healthy ones enter the Maglev table, so a crashed backend is evicted within a
reload cycle and re-added automatically when it recovers. Configure under `health_check`.

**Metrics & health (opt-in).** Off unless you set `observability.metrics_addr`. When set, the
forwarding plane serves Prometheus counters at `GET /metrics` (routed / dropped-by-reason, backend
counts) and a readiness probe at `GET /healthz` (200 with ≥1 healthy backend, else 503). Zero
setup required to run without it.

### Running it

Bare metal / VM (needs `CAP_NET_ADMIN`+`CAP_SYS_ADMIN`, so run as root):

```shell
cargo build --release --package l4
sudo RUST_LOG=info ./target/release/l4 --config config.yaml
# --iface is auto-detected from the default route; override with --iface eth0
```

Docker (nginx-style quick setup — forwarding plane + two nginx backends on a fixed bridge `equinox0`):

```shell
docker compose up --build
```

Edit `./config.yaml` on the host while it runs to reload live. Override the interface/config
with the `IFACE` and `CONFIG` environment variables.

### Operational notes

- **L2 reachability**: `XDP_TX` rewrites the destination MAC and re-transmits out the *same*
  interface, so backends must be on that interface's L2 segment. The compose attaches the
  forwarding plane to the `equinox0` bridge the backends live on; to load-balance external
  traffic, attach to your uplink NIC and keep backends on that L2.
- **Return path**: only the destination IP is rewritten (no SNAT), so backends reply with
  their own address. Backends need the VIP configured (DSR-style) for client connections to
  match.
- **Limits**: up to `N = 650` backends per buffer (Maglev table size `M = 65537`); change
  both together in `l4-common` if you need more.

### Performance: native XDP

`xdp_mode: "auto"` (the default) attaches in native/driver mode and falls back to SKB
(generic) mode if the NIC/driver doesn't support it. Native mode runs the program in the
driver before `skb` allocation and is where the real throughput win comes from — prefer it in
production on NICs with XDP driver support (most modern Intel/Mellanox/virtio-net). SKB mode
works everywhere but is slower. Force a mode with `gateway.xdp_mode: "drv"` / `"skb"` / `"hw"`.
Check `ethtool -i <iface>` and your driver's XDP support; if native attach fails you'll see a
log line and (in auto mode) an automatic fallback to SKB.

### Roadmap / not yet done

- **Automated tests** — unit tests for the Maglev table builder, config parsing, and the
  eBPF checksum math are planned and not yet in the tree. The checksum logic in particular
  should get golden-value tests before relying on this in production.
- Active health checks are TCP-connect only; richer checks (HTTP, expected response) are TODO.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package l4 --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/l4` can be
copied to a Linux server or VM and run there.

## License

The product — the userspace control plane (`l4`, `l4-common`) — is licensed under the
[Apache License, Version 2.0](LICENSE-APACHE).

The eBPF data plane (`l4-ebpf`) is licensed under the
[GNU General Public License, Version 2](LICENSE-GPL2). This is required: the Linux kernel
only loads eBPF programs whose license string is GPL-compatible when they use restricted
helpers. This split (permissive userspace, GPL kernel object) is the same model used by
Cilium and Katran.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in the work by you shall be licensed as above, without any additional terms or conditions.
