# syntax=docker/dockerfile:1

# ====================================================================
# Builder: compiles the userspace loader and the eBPF object.
# Building eBPF needs a nightly toolchain with rust-src, plus bpf-linker
# (which links against LLVM). If the LLVM version below drifts from what
# bpf-linker expects, bump the `llvm-19` packages to match.
# ====================================================================
FROM rustlang/rust:nightly-bookworm AS builder

ARG LLVM_VERSION=19

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang-${LLVM_VERSION} \
        llvm-${LLVM_VERSION} \
        llvm-${LLVM_VERSION}-dev \
        libclang-${LLVM_VERSION}-dev \
        libpolly-${LLVM_VERSION}-dev \
        pkg-config \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/usr/lib/llvm-${LLVM_VERSION}/bin:${PATH}"

# eBPF build prerequisites.
RUN rustup component add rust-src --toolchain nightly \
    && cargo install bpf-linker --locked

WORKDIR /build
COPY . .

# Cargo build scripts compile the eBPF object and embed it in the `l4` binary.
RUN cargo build --release --package l4

# ====================================================================
# Runtime: minimal image that loads/attaches the XDP program.
# Must run with host networking + NET_ADMIN/SYS_ADMIN (see compose).
# ====================================================================
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/target/release/l4 /usr/local/bin/l4

# Bundled default config. It lives in two places:
#   /usr/share/equinox/config.default.yaml — immutable template the entrypoint
#       seeds from when a config-less directory is mounted over /app.
#   /app/config.yaml — so a bare `docker run` (no -v) works out of the box.
COPY config.example.yaml /usr/share/equinox/config.default.yaml
COPY config.example.yaml /app/config.yaml

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV RUST_LOG=info
ENV CONFIG=/app/config.yaml
# Zero-config by default: the entrypoint guarantees a config exists at $CONFIG
# (seeding the bundled template if you mounted an empty dir) and the binary
# auto-detects the interface from the default route. Override with IFACE /
# CONFIG. Needs --network host + NET_ADMIN/SYS_ADMIN (or --privileged).
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
