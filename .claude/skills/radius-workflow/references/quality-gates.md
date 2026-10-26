# Quality Gates

Commands match `Makefile` and `.github/workflows/ci.yml`. Scope to the touched
crate (`-p <crate>`) while iterating; run the workspace-wide form once before
the final gate. Note that CI's clippy uses `--all-features` (the `Makefile`
`lint` target does not), so the final lint must use the CI form.

| Gate | Iterating | Final | Required |
|------|-----------|-------|----------|
| Format | `cargo fmt --all` | `cargo fmt --all -- --check` | Yes |
| Lint | `cargo clippy -p <crate> --all-targets --all-features -- -D warnings` | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Yes |
| Unit tests | `cargo test -p <crate> --lib` | `cargo test --workspace --all-targets` | Yes |
| Doc tests | `cargo test -p <crate> --doc` | `cargo test --workspace --doc` | When public API or doc examples changed |
| Integration | `cargo test --test <name>` | `cargo test --test '*'` | When server behaviour changed. LDAP/PostgreSQL cases are `#[ignore]`d and need a live service: run with `-- --ignored` when one is available, otherwise NOT RUN |
| Interop | — | `tests/interop/run.sh` (Docker; on this Mac via a Lima VM, see `docs/docs/development/INTEROP_TESTING.md`) | When EAP, proxy, RadSec, MPPE/Tunnel-Password, authenticator or Dockerfile code changed |
| Known-answer | `cargo test -p radius-proto kat` | same | When anything cryptographic changed: new vectors required, produced by an independent implementation |
| Benches compile | — | `cargo bench --no-run` | When `benches/` or a benched API changed |
| Supply chain | — | `cargo audit` in the root and in `ui/bff` (two lockfiles) | When `Cargo.toml`/`Cargo.lock` changed in either |
| Web UI | `npx tsc --noEmit -p .` in `ui/web` | `npm ci && npx tsc --noEmit -p . && npm run build` in `ui/web` | When `ui/web/**` changed |
| UI BFF | `cargo clippy --all-targets -- -D warnings` in `ui/bff` | same plus `cargo test` in `ui/bff` | When `ui/bff/**` changed |
| Image | — | `docker build .` (needs Iron Bank login, or `--build-arg IB_ALPINE=docker.io/library/alpine:3.22` for the public fallback) | When `Dockerfile`, `ui/Dockerfile` or build deps changed |
| Manifests | — | `kubectl kustomize deploy/overlays/k8s` and `deploy/overlays/uk8w` | When `deploy/**` changed |
| Markdown | — | `npx markdownlint-cli "docs/**/*.md" README.md CHANGELOG.md` (config: `.markdownlint.json`; not wired into CI) | When docs changed |

## Rules

- Record every command with its exit status and the last relevant lines of
  output in `qa-report.md`. "Tests pass" without the command is not evidence.
- If an environment dependency is missing (Docker/Lima for interop, LDAP,
  PostgreSQL, Iron Bank credentials), say so explicitly and mark that gate
  **NOT RUN**, not PASS.
- No new `#[allow(clippy::...)]`, `#[ignore]`, or `unwrap()`/`expect()` on
  packet or peer-supplied data to get a gate green without a justification
  comment and a finding entry.
- Unit tests here exercise this codebase against itself (rustls peer against a
  rustls server, this codec decoding what it encoded). Anything that changes
  bytes on the wire or key derivation needs an independent check: a known-answer
  vector or an interop assertion.
- Run the final workspace-wide gates and the interop harness in the background;
  they take minutes.
