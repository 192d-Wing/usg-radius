# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

usg-radius is a RADIUS/EAP server in Rust: `crates/radius-proto` (packet,
attribute, authenticator, EAP-TLS/TEAP, MS-MPPE, Tunnel-Password, CRL/OCSP
codecs) and `crates/radius-server` (UDP and RadSec transports, proxy, CoA,
PostgreSQL/LDAP backends, policy, management API with mTLS + ABAC). `ui/web`
is a React/Vite UI and `ui/bff` its Rust backend. Deployment is Kubernetes via
`deploy/`. The security posture is TLS 1.3 with ML-KEM through aws-lc-rs; no
DTLS and no legacy EAP methods.

## Multi-Agent Workflow

For features, bug fixes, and reviews that need the full team, use the
`/radius-workflow` skill (`.claude/skills/radius-workflow/SKILL.md`). The main
conversation acts as orchestrator and delegates to the subagents in
`.claude/agents/`: `radius-architect`, `radius-coder`, `qa-engineer`,
`security-reviewer`, `crypto-reviewer`, `rfc-conformance-reviewer`,
`docs-scribe`, `release-engineer`.

- `/radius-workflow <task>` — plan → build → test → parallel review → fix loop → docs → release gate
- `/radius-workflow review [base-ref]` — review the current diff only
- `/radius-workflow plan <task>` — plan only

## Commands

| Purpose | Command |
|---------|---------|
| Format | `cargo fmt --all -- --check` |
| Lint (as CI runs it) | `cargo clippy --workspace --all-targets --all-features -- -D warnings` |
| Tests (as CI runs them) | `cargo test --workspace --all-targets` |
| Interop against FreeRADIUS + eapol_test | `tests/interop/run.sh` (Docker; see `docs/docs/development/INTEROP_TESTING.md`) |
| Web UI | `cd ui/web && npm ci && npx tsc --noEmit -p . && npm run build` |
| Dependency audit | `cargo audit` in the root and in `ui/bff` |

## Rules of the road

- Verify authenticators before using any attribute; discard silently on failure.
- Secrets, passwords and keys never appear in logs, `Debug` output, errors,
  metrics or audit records.
- Encrypted attributes are bound to a secret and Request Authenticator; when
  a packet crosses a hop, decrypt with the sender's pair and re-encrypt with
  the receiver's.
- Anything on the wire or in key derivation needs a known-answer vector or an
  interop assertion; the unit tests otherwise check this codebase against itself.
- `docs/docs/protocol/RFC-COMPLIANCE.md` is the statement of record. Every code
  change that affects a claim there updates it in the same change.
- Releases are immutable on GitHub: `release.yml` creates a draft, uploads
  assets, then publishes. Do not reorder.
