# syntax=docker/dockerfile:1.7
# USG RADIUS server container image.
#
# Multi-arch (linux/amd64 + linux/arm64), built on the Iron Bank hardened Alpine
# base. Alpine is musl-native, so a plain `cargo build` here yields a musl binary
# for whichever platform buildx is targeting — no cross-compilation gymnastics.
# cargo-chef is used so the dependency build is cached in its own layer.
#
# Build (both arches, pushed to a registry):
#   docker buildx build --platform linux/amd64,linux/arm64 \
#       -t <registry>/usg-radius-server:<tag> --push .
#
# Iron Bank images require an authenticated pull:
#   docker login registry1.dso.mil
# or mirror the base images into an internal registry and override IB_ALPINE.
ARG IB_ALPINE=registry1.dso.mil/ironbank/opensource/alpinelinux/alpine:3.22

# ---- chef: Rust toolchain + cargo-chef (cached base for planner/builder) ----
# Alpine's packaged Rust is too old for this project's dependency tree, so install
# a pinned modern toolchain via rustup. Alpine is musl-native, so rustup selects the
# *-unknown-linux-musl host toolchain automatically (per build platform under buildx).
FROM ${IB_ALPINE} AS chef
USER root
ARG RUST_VERSION=1.92.0
ENV PATH="/root/.cargo/bin:${PATH}"
RUN apk add --no-cache \
        build-base musl-dev pkgconfig curl ca-certificates \
        openssl-dev openssl-libs-static \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain "${RUST_VERSION}" \
    && cargo install cargo-chef --locked
WORKDIR /build

# ---- planner: capture the dependency graph into recipe.json ----
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---- builder: cook deps (cached layer), then build the binary ----
FROM chef AS builder
# Statically link OpenSSL if any transitive dep pulls openssl-sys.
ENV OPENSSL_STATIC=1
COPY --from=planner /build/recipe.json recipe.json
# Cook only the dependencies for the feature set we ship (observability =
# health + Prometheus metrics HTTP servers; no Redis/HA).
RUN cargo chef cook --release -p radius-server --no-default-features --features observability --recipe-path recipe.json
COPY . .
RUN cargo build --release -p radius-server --no-default-features --features observability --bin usg-radius \
    && strip target/release/usg-radius

# ---- runtime: minimal Iron Bank Alpine, non-root ----
FROM ${IB_ALPINE} AS runtime
RUN apk add --no-cache ca-certificates libgcc \
    && adduser -D -H -u 999 -s /sbin/nologin radius \
    && mkdir -p /etc/radius /var/log/radius \
    && chown -R radius:radius /etc/radius /var/log/radius
COPY --from=builder /build/target/release/usg-radius /usr/local/bin/usg-radius
COPY examples/configs/docker.json /etc/radius/config.example.json
USER radius
# RADIUS auth (1812/udp) + accounting (1813/udp); health (2812/tcp); metrics (3812/tcp)
EXPOSE 1812/udp 1813/udp 2812/tcp 3812/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/usg-radius", "--version"]
ENTRYPOINT ["/usr/local/bin/usg-radius"]
CMD ["/etc/radius/config.json"]
