# syntax=docker/dockerfile:1.7
# usg-radius image for the interop test. Built from the repository root
# (`docker compose build` uses context ../../.. relative to this file), on plain
# Debian so it runs on amd64 and arm64 without any private registry. Not the
# shipping image (see /Dockerfile for that); same features: observability + tls + revocation.
ARG RUST_VERSION=1.92
FROM rust:${RUST_VERSION}-slim-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake perl pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
# Cache mounts keep the registry and target dir across builds so a source
# change only rebuilds the crates that changed.
ARG CARGO_BUILD_JOBS=2
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release -p radius-server --no-default-features \
        --features observability,tls,revocation --bin usg-radius \
    && cp target/release/usg-radius /usr/local/bin/usg-radius

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/radius /var/log/radius
COPY --from=builder /usr/local/bin/usg-radius /usr/local/bin/usg-radius
EXPOSE 1812/udp 1813/udp
ENTRYPOINT ["/usr/local/bin/usg-radius"]
CMD ["/etc/radius/config.json"]
