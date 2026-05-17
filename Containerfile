# USG RADIUS Server - OCI image (Podman / Docker / Buildah compatible)
# Multi-stage build, default-features include `ha` (Valkey backend + HTTP health/metrics).

# ---- Build stage ----
FROM docker.io/library/rust:1-bookworm AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY tools/ ./tools/
COPY benches/ ./benches/

# `ha` is in default-features; pass --locked for reproducible builds.
RUN cargo build --release --locked -p radius-server --bin usg-radius

# ---- Runtime stage ----
FROM docker.io/library/debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r -g 999 radius \
    && useradd  -r -u 999 -g radius -s /sbin/nologin -d /nonexistent radius \
    && mkdir -p /etc/radius \
    && chown radius:radius /etc/radius

COPY --from=builder /build/target/release/usg-radius /usr/local/bin/usg-radius

USER 999:999

# 1812 = RADIUS auth (UDP), 1813 = RADIUS accounting (UDP), 8080 = HTTP health/metrics (TCP)
EXPOSE 1812/udp 1813/udp 8080/tcp

ENV HEALTH_LISTEN_ADDR=0.0.0.0:8080 \
    RUST_LOG=info

# tini reaps zombies and forwards SIGTERM cleanly to the Rust binary.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/usg-radius"]
CMD ["/etc/radius/config.json"]
