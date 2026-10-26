# Triage Matrix — which roles run

The orchestrator picks the roster from the paths a change touches. When in
doubt, include the reviewer: a skipped reviewer is a silent gap, an extra one
costs only tokens.

## Always-on for any code change

- `qa-engineer`
- `security-reviewer`
- `docs-scribe`

## Path-triggered roles

| Touched path / topic | Add |
|----------------------|-----|
| `crates/radius-proto/src/auth.rs`, `chap.rs`, `message_auth.rs`, `mppe.rs`, `tunnel_password.rs`, `kat.rs` (authenticators, password/key encryption, HMAC) | `crypto-reviewer`, `rfc-conformance-reviewer`; QA must run the known-answer gate |
| `crates/radius-proto/src/eap.rs`, `eap/**` (EAP state machine, EAP-TLS, EAP-TEAP, MSK/EMSK derivation, exporters) | `crypto-reviewer`, `rfc-conformance-reviewer`; QA runs the interop harness |
| `crates/radius-proto/src/packet/**`, `attributes/**`, `validation.rs`, `accounting.rs`, `dynauth.rs` (wire format, attribute codecs, enumerations) | `rfc-conformance-reviewer` |
| `crates/radius-proto/src/revocation/**` (CRL/OCSP) | `crypto-reviewer`, `rfc-conformance-reviewer` |
| `crates/radius-server/src/radsec.rs`, `tls_certs.rs`, any rustls `ServerConfig`/`ClientConfig`, `usg-fips-tls` usage | `crypto-reviewer`, `rfc-conformance-reviewer` (RFC 6614) |
| `crates/radius-server/src/proxy/**` (forwarding, response rewrite, retry, realms) | `rfc-conformance-reviewer`, `crypto-reviewer` (per-hop re-encryption); QA runs the interop harness with the proxy cases |
| `crates/radius-server/src/server.rs`, `eap_auth.rs` (request pipeline, Access-Accept builder) | `rfc-conformance-reviewer`, `crypto-reviewer`; QA runs the interop harness |
| `crates/radius-server/src/coa.rs` (CoA/Disconnect) | `rfc-conformance-reviewer` (RFC 5176) |
| Status-Server handling in `crates/radius-server/src/server.rs` and `proxy/health.rs` (home-server probes) | `rfc-conformance-reviewer` (RFC 5997) |
| `crates/radius-server/src/mgmt.rs`, `access.rs`, `policy.rs`, `policy_enforce.rs` (management API, mTLS, ABAC, authorization policy) | (always-on set; flag mTLS identity, ABAC bypass and policy-precedence focus in the security prompt) |
| `crates/radius-server/src/ldap_auth.rs`, `postgres_auth.rs`, `accounting/**`, `state/**` (backends, sessions) | (always-on set; flag injection, credential handling and session-state focus); QA marks LDAP/PostgreSQL tests NOT RUN unless a service is available |
| `crates/radius-server/src/ratelimit.rs`, `buffer_pool.rs`, `cache.rs` (DoS protection, resource limits) | (always-on set; flag exhaustion and eviction focus) |
| `crates/radius-server/src/audit.rs`, `metrics.rs` | (always-on set; flag "no secrets or passwords in logs/metrics" focus) |
| `crates/radius-server/src/config.rs`, `examples/configs/**` | `release-engineer` (config keys appear in examples and docs with secure defaults) |
| `ui/web/**`, `ui/bff/**` | (always-on set; flag XSS/CSRF/session and BFF→mgmt-API credential focus); QA runs the Web UI and UI BFF gates; `release-engineer` if `ui/Dockerfile` or `ui/bff/Cargo.*` changed |
| `Cargo.toml`, `Cargo.lock` (root or `ui/bff`) | `release-engineer` (cargo audit in both workspaces) |
| `Dockerfile`, `ui/Dockerfile`, `deploy/**`, `Makefile` | `release-engineer` |
| `.github/workflows/**` | `release-engineer` (release.yml must keep the draft → upload → publish order: the repository uses immutable releases) |
| `tests/**`, `benches/**` only | `qa-engineer` only (+ `docs-scribe` if `INTEROP_TESTING.md` or test-evidence claims change) |
| `docs/**`, `README.md`, `CHANGELOG.md` only | `docs-scribe` + markdownlint only |

## Phase skips

| Situation | Skip |
|-----------|------|
| Docs / comments only | Phases 1–4; run scribe + markdownlint only |
| Bug fix with an obvious one-file cause | Phase 1 may be a short inline plan written by the orchestrator into `plan.md` |
| Internal refactor, no behaviour/API/wire change | Phase 6 |
| `review` mode | Phases 1–2 |

Record every skipped role or phase, with the reason, in `brief.md`.
