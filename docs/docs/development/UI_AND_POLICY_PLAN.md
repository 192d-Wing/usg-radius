# usg-radius-ui + Policy Engine — Design Plan

## Context & goal

Add a web management UI (`usg-radius-ui`) for the RADIUS server, built with the same
stack as `usg-tacacs/ui` (React + TypeScript + Vite + **Cloudscape**, Rust/axum BFF,
oauth2-proxy auth, single Iron Bank container, k3s/Cilium deploy). The headline feature
is an **ISE-style authorization policy builder** (Policy Sets + Condition Studio) —
which neither project has today.

Two hard facts shape the work:
- `usg-radius` currently has **no management API** (config-file only; health/metrics aside).
- `usg-radius` has **no authorization policy engine** — auth today is username/password +
  client-by-IP. The ISE/Forescout-style decisioning must be built.

`usg-tacacs` is the architectural reference but has **no visual policy builder** (policy =
hand-edited JSON uploaded via API), so the builder UI is net-new.

## Decisions (confirmed)

- Policy model: **ISE-style policy sets**, built **phased**.
- Builder UI: **policy-set table + Condition Studio** (not a node-graph canvas; a React Flow
  visualization is an optional later add).

## Architecture (three workstreams)

```
        oauth2-proxy (Keycloak OIDC, X-Auth-Request-* headers)
                 │
        ┌────────▼─────────┐    serves SPA + aggregates
        │  usg-radius-ui   │    (Prometheus/Loki) + proxies mgmt API
        │  React+Cloudscape│
        │   SPA  +  axum BFF│
        └────────┬─────────┘
                 │  mTLS + RBAC (client-cert CN)
        ┌────────▼─────────┐
        │  usg-radius      │  NEW: /api/v1 management API
        │  server          │  NEW: policy engine in request path
        └──────────────────┘
```

### A. `usg-radius-ui` (mirror `usg-tacacs/ui`)
- **SPA** (`ui/web/`): React 18 + TS + Vite + `@cloudscape-design/components` v3 +
  `global-styles`, react-router-dom, thin `fetch` wrapper (`src/api.ts`). Pages:
  Dashboard, Sessions, Audit, Clients, Users, **Policy**, Conditions, Simulate.
- **BFF** (`ui/bff/`): Rust + axum 0.8; serves `dist/`, reads oauth2-proxy headers →
  `/api/me`, aggregates Prometheus/Loki for metrics/audit, and **proxies** the server's
  `/api/v1/*` with the caller's identity. No DB (pure aggregation), same as tacacs.

### B. Management API + policy engine on `usg-radius` (server-side; the biggest lift)
New axum API (separate port, **mTLS + RBAC by client-cert CN**, mirroring
`usg-tacacs/crates/tacacs-server/src/api/`):

```
GET  /api/v1/status                     server stats, uptime, sessions
GET  /api/v1/sessions  DELETE /{id}      live sessions; terminate
GET/POST/PATCH/DELETE  /api/v1/clients   NAS clients CRUD
GET/POST/PATCH/DELETE  /api/v1/users     local users CRUD
GET  /api/v1/dictionary                  attributes + operators for the Condition Studio
GET/PUT /api/v1/policy                   full policy doc (schema-validated)
       /api/v1/policy/sets  (CRUD + reorder), /rules (CRUD + reorder)
GET/POST/PATCH/DELETE /api/v1/policy/profiles    reusable Authorization Profiles
GET/POST/PATCH/DELETE /api/v1/policy/conditions  reusable named conditions
POST /api/v1/policy/dry-run              evaluate candidate policy vs recent requests
POST /api/v1/policy/reload               hot reload
```

**Policy model (ISE-style):**
```rust
PolicyConfig {
  device_groups: Map<String, Vec<Cidr>>,      // NAD groups by CIDR
  conditions: Vec<NamedCondition>,             // reusable library
  authz_profiles: Vec<AuthzProfile>,           // reusable results
  policy_sets: Vec<PolicySet>,                 // ordered; first matching set wins
  default_result: ResultRef,                   // fallback (reject)
}
PolicySet { id, name, enabled, order, match: Condition, rules: Vec<Rule> }
Rule      { id, name, enabled, order, condition: Condition, result: ResultRef }

enum Condition {                               // AND/OR tree
  All(Vec<Condition>), Any(Vec<Condition>), Not(Box<Condition>),
  Attr { attribute: AttrRef, op: Operator, value: Value },
  Ref(String),                                 // named condition
}
// AttrRef: User-Name, identity/LDAP group, NAS-IP, device group, NAS-Port-Type,
//   Called/Calling-Station-Id, EAP type, client-cert CN/SAN, time/schedule, ...
// Operator: equals, not_equals, contains, starts_with, matches_regex, in_cidr,
//   in_group, in_time_window
AuthzProfile { id, name, effect: Accept|Reject, attributes: Vec<RadiusAttr>, reply_message? }
// attributes: VLAN/Tunnel-*, Filter-Id, dACL, Class, Session-Timeout, rate limits, ...
```
**Engine:** after authentication, walk policy sets in order → first set whose `match`
passes → first rule whose `condition` passes → apply its `AuthzProfile` (Accept + reply
attributes, or Reject); else `default_result`. Reuse the existing client/IP + LDAP/Postgres
identity plumbing for attribute/group lookups.

### C. The ISE-style policy builder UI
- **Policy Sets table** (Cloudscape `Table`): ordered rows, drag-to-reorder, enable/disable,
  inline match summary, click → expand to the set's **Rules** table.
- **Condition Studio** (custom Cloudscape component): nested AND/OR groups of
  `attribute · operator · value` rows; attribute/operator pickers driven by
  `/api/v1/dictionary`; save as reusable named conditions.
- **Authorization Profile editor**: form for returned RADIUS attributes (Cloudscape forms +
  attribute dictionary).
- **Simulate / dry-run**: paste or pick a sample request → show which set/rule matches and the
  resulting attributes, and "what-if" a candidate policy against recent live requests
  (`/api/v1/policy/dry-run`).
- Optional later: a **React Flow** read-only visualization of the same policy.

## Container, build, deploy
- **`usg-radius-ui`** image: 3-stage (node→build SPA, rust→build BFF, **Iron Bank Alpine**
  runtime serving both), built with the **native arm64 matrix** release pipeline we just
  added (amd64 + arm64), pushed to GHCR.
- Deploy as a sibling overlay (`deploy/overlays/uk8w` style) behind **oauth2-proxy/Keycloak**
  (Traefik or Cilium ingress) — e.g. a `10.10.10.57` anycast VIP or a ClusterIP+Ingress.
- The server's new management API needs a TLS cert + RBAC config; the UI's BFF holds the
  client cert (or runs in-cluster with mTLS to the server service).

## Auth / RBAC
- **UI**: oauth2-proxy forward-auth (Keycloak OIDC), identity via `X-Auth-Request-*` →
  `/api/me`. Reuse the tacacs `deploy/k3s/ui/oauth2-proxy.yaml` pattern.
- **Management API**: mTLS client-cert; RBAC roles (viewer / operator / policy-admin) keyed
  on cert CN (+ optionally the oauth2 group claim forwarded by the BFF).

## Phased roadmap
1. **P0 — UI scaffold** (`usg-radius-ui` SPA+BFF, container, deploy behind oauth2-proxy):
   read-only Dashboard/Sessions/Metrics/Audit. Fast; proves the stack end-to-end.
2. **P1 — Management API**: clients/users CRUD + status/sessions on the server; UI pages.
3. **P2 — Policy engine + API**: model, evaluation in the request path, dictionary, dry-run.
4. **P3 — Policy builder UI**: Policy Sets table + Condition Studio + Authorization Profiles +
   Simulate.
5. **P4 — Advanced**: cert/posture/time conditions, change history & approvals, RBAC roles,
   optional React Flow visualization.

## Reuse from `usg-tacacs`
- BFF skeleton, `api.ts` fetch wrapper, Cloudscape app shell + nav, oauth2-proxy manifests,
  the `/api/policy/dry-run` idea, the mTLS+RBAC management-API pattern
  (`crates/tacacs-server/src/api/`), and the container layout (`ui/Dockerfile`).

## Open questions
- Where does policy live — server-local file (hot-reloaded, like tacacs) vs. a shared store
  (Postgres/Redis already optionally present) for multi-replica consistency? (Recommend:
  config file in a ConfigMap/Secret for P2, move to Postgres in P4 if multi-writer editing
  needs it.)
- Identity groups for conditions: drive from the existing LDAP/AD integration?
- Keycloak realm/clients for oauth2-proxy — reuse the tacacs realm or a new one?
```
