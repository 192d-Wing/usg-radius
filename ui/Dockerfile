# SPDX-License-Identifier: Apache-2.0
# usg-radius-ui: Cloudscape SPA + Rust/axum BFF in one image.
# Build context = ui/ . Arch-native (the release matrix builds amd64 and arm64).
ARG IB_ALPINE=registry1.dso.mil/ironbank/opensource/alpinelinux/alpine:3.22

# Stage 1: build the Cloudscape SPA.
FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json ./
RUN npm install --no-audit --no-fund
COPY web/ ./
RUN npm run build

# Stage 2: build the BFF (musl, native target). reqwest is HTTP-only so no
# TLS/native deps are required. Pinned modern toolchain (Alpine's apk rust is too
# old for the dependency tree).
FROM rust:1.92-alpine AS bff
RUN apk add --no-cache musl-dev
WORKDIR /bff
COPY bff/ ./
RUN cargo build --release

# Stage 3: minimal Iron Bank runtime.
FROM ${IB_ALPINE} AS runtime
RUN apk add --no-cache ca-certificates && adduser -D -H -u 999 -s /sbin/nologin ui
COPY --from=bff /bff/target/release/radius-ui-bff /usr/local/bin/radius-ui-bff
COPY --from=web /web/dist /app/web
USER ui
EXPOSE 8088
ENV UI_STATIC_DIR=/app/web
ENTRYPOINT ["/usr/local/bin/radius-ui-bff"]
