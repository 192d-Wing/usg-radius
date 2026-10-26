# Report Formats

## Findings file (`findings-<role>.md`)

```markdown
# Findings — <role>

Scope: <base>...<head> (<n> files), plan: <run>/plan.md
Verdict: APPROVE | APPROVE WITH COMMENTS | CHANGES REQUESTED

## <ROLE-PREFIX>-001 [BLOCKER] <one-line title>

- **Location**: `crates/radius-server/src/proxy/handler.rs:123`
- **Reference**: RFC 2865 §3 | RFC 3579 §3.2 | RFC 2548 §2.4.2 | RFC 9190 §2.5 | FIPS 140-3 | CWE-...
- **Problem**: what is wrong, in one or two sentences.
- **Failure scenario**: concrete packet/state → concrete bad outcome.
- **Fix**: the smallest change that resolves it.
- **Confidence**: high | medium | low
```

Role prefixes: `SEC` (security), `CRYPTO` (crypto/FIPS), `RFC` (protocol),
`QA` (testing), `DOCS` (documentation), `REL` (release).

### Severity

| Severity | Meaning | Gate effect |
|----------|---------|-------------|
| BLOCKER | Shared secret or key material exposed; authenticator or Message-Authenticator not verified where the RFC requires it; Access-Accept reachable without a passing credential or certificate check; keys delivered to the NAS that it cannot decrypt or that are wrong; TLS verification disabled or weakened; broken RFC MUST on the wire | Must fix |
| MAJOR | Missing required test or known-answer vector; RFC SHOULD violated without reason; fail-open path on error; packet field trusted without length/range validation even if no sink is reached yet; proxy hop that trusts the wrong secret or authenticator | Must fix |
| MINOR | Hardening, missing RFC citation in code, weak test, unclear error type, log noise | Advisory |
| NIT | Style, naming, comments | Advisory |

A finding without a location and a failure scenario is MINOR at most.

## Fix response (`fixes-round-<n>.md`)

```markdown
| Finding | Action | Change |
|---------|--------|--------|
| SEC-001 | Fixed | `handler.rs:120-131` verify Response Authenticator before touching attributes |
| RFC-002 | Rebutted | RFC 2865 §5.33 only requires Proxy-State order to be preserved; the response leg strips ours and keeps the rest in order (test `proxy_state_order_preserved`) |
```

## Gate summary

`gate.md`, written by the orchestrator:

```markdown
# Gate — <task>

Verdict: PASS | PASS WITH GAPS | FAIL

| Gate | Result | Evidence |
|------|--------|----------|
| fmt | PASS | `cargo fmt --all -- --check` |
| clippy | PASS | `cargo clippy --workspace --all-targets --all-features -- -D warnings` |
| unit tests | PASS (482) | `cargo test --workspace --all-targets` |
| integration | PASS (ignored: 9 need LDAP/PostgreSQL) | `cargo test --test '*'` |
| interop | PASS (24/24) | `tests/interop/run.sh` |
| security review | APPROVE | findings-security.md (0 open) |
| crypto review | APPROVE WITH COMMENTS | findings-crypto.md (1 MINOR) |
| RFC review | APPROVE | findings-rfc.md |
| docs | UPDATED | docs-update.md |
| release | CHANGELOG + patch bump suggested | release-notes.md |

## Open items
- CRYPTO-003 [MINOR] ...

## Accepted gaps
- (none) | `// TODO(gap):` at file:line, recorded in RFC-COMPLIANCE.md, accepted by user on <date>

## Dropped findings
- SEC-004: not reachable; length already validated at `packet.rs:110`.
```
