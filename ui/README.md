# usg-radius-ui

Operator UI for the RADIUS server — a Cloudscape SPA served by a small Rust/axum
BFF, shipped as a single container (`usg-radius-ui`). Mirrors the `usg-tacacs/ui`
pattern. See [the design plan](../docs/docs/development/UI_AND_POLICY_PLAN.md).

```
ui/
  web/   React + TypeScript + Vite + Cloudscape SPA
  bff/   Rust + axum backend-for-frontend (serves the SPA, aggregates /metrics)
  Dockerfile   3-stage build (node SPA -> rust BFF -> Iron Bank Alpine runtime)
```

## Status (Phase 0)

Read-only **Dashboard** (live service health + metrics scraped from the RADIUS
server). Sessions / Clients / Users / Policy are placeholders pending the server
management API and policy engine (Phases 1–3 in the plan).

## Local dev

```bash
# Terminal 1 — BFF (point it at a reachable radius metrics/health endpoint)
cd ui/bff
RADIUS_METRICS_URL=http://localhost:3812 RADIUS_HEALTH_URL=http://localhost:2812 cargo run

# Terminal 2 — SPA dev server (proxies /api to the BFF on :8088)
cd ui/web
npm install
npm run dev
```

## Container

Built by the release pipeline (`build-image` matrix, `ui` component) for amd64 +
arm64 → `ghcr.io/192d-wing/usg-radius-ui:<tag>`.

```bash
docker build -t usg-radius-ui ./ui     # context is ui/
```

## Deploy

```bash
kubectl apply -k deploy/ui          # into the existing `radius` namespace
kubectl -n radius port-forward svc/usg-radius-ui 8088:80   # quick look
```

Front with oauth2-proxy (Keycloak OIDC) + an ingress for real access; the BFF
reads identity from `X-Auth-Request-*` headers.

## Auth

- **UI**: oauth2-proxy forward-auth (Keycloak). Identity via `X-Auth-Request-*`
  headers exposed at `GET /api/me`.
- The BFF talks to the RADIUS server's in-cluster health/metrics over plain HTTP
  (`RADIUS_METRICS_URL`, `RADIUS_HEALTH_URL`).
