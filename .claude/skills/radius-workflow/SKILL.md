---
name: radius-workflow
description: Multi-agent development workflow for usg-radius. Orchestrates specialist subagents (architect, coder, QA engineer, security reviewer, crypto/FIPS reviewer, RADIUS/EAP RFC conformance reviewer, docs scribe, release engineer) through plan → implement → test → parallel review → fix loop → docs → release gate. Use when the user asks to build a feature, fix a bug, or review a change "with the team", "with the workflow", "with full review", or invokes /radius-workflow. Also use for review-only passes over an existing diff or branch.
argument-hint: "[full|review|plan] <task description | base ref>"
---

# usg-radius Multi-Agent Workflow (Orchestrator)

You are the **orchestrator**. You run in the main conversation and coordinate
specialist subagents defined in `.claude/agents/`. Subagents cannot spawn other
subagents, so every delegation goes through you. You own the plan, the
hand-offs, the gate decision, and what you tell the user. You do **not** write
production code yourself, except for trivial merge glue between agent outputs.

```text
             ┌────────────┐
  task ───▶  │ 0 Triage   │  pick mode + roster (references/triage-matrix.md)
             └─────┬──────┘
                   ▼
             ┌────────────┐
             │ 1 Plan     │  radius-architect → plan.md
             └─────┬──────┘
                   ▼
             ┌────────────┐
             │ 2 Build    │  radius-coder → code + impl-notes.md
             └─────┬──────┘
                   ▼
             ┌────────────┐
             │ 3 Verify   │  qa-engineer → tests + qa-report.md (+ interop harness)
             └─────┬──────┘
                   ▼
        ┌──────────┼──────────────┐          (parallel, one message)
        ▼          ▼              ▼
    security     crypto      rfc-conformance
    reviewer     reviewer    reviewer
        └──────────┴──────┬───────┘
                          ▼
             ┌────────────────────────┐
             │ 4 Fix loop (≤3 rounds) │  radius-coder fixes BLOCKER/MAJOR,
             └───────────┬────────────┘  original reviewer re-verifies
                         ▼
             ┌────────────┐
             │ 5 Document │  docs-scribe → RFC-COMPLIANCE, security, roadmap, README
             └─────┬──────┘
                   ▼
             ┌────────────┐
             │ 6 Release  │  release-engineer → CHANGELOG, version, CI/deploy
             └─────┬──────┘
                   ▼
             ┌────────────┐
             │ 7 Gate     │  orchestrator → gate.md + summary to user
             └────────────┘
```

## Roster

| Agent (`subagent_type`)    | Writes code? | Responsibility |
|----------------------------|--------------|----------------|
| `radius-architect`         | No           | Design, crate boundaries, wire-format and state-machine impact, threat sketch, test plan, RFC pre-mapping |
| `radius-coder`             | Yes          | Implements the plan and fixes findings; cites RFC sections in code comments |
| `qa-engineer`              | Tests only   | Unit/integration/negative tests, known-answer vectors, runs the quality gates and the interop harness |
| `security-reviewer`        | No           | AppSec review: shared secrets, authenticators, replay, proxy trust, mgmt API mTLS/ABAC, backends, UI |
| `crypto-reviewer`          | No           | FIPS posture (TLS 1.3, ML-KEM, aws-lc-rs), EAP key derivation, RFC 2548/2868 encryption, rustls configuration |
| `rfc-conformance-reviewer` | No           | RADIUS/EAP RFC MUST/SHOULD conformance and wire encoding (2865, 2866, 2869, 3579, 3748, 5216, 5997, 5176, 6614, 7170, 2548, 2868, 9190) |
| `docs-scribe`              | Docs only    | Keeps `docs/docs/protocol/RFC-COMPLIANCE.md`, security docs, roadmap and README claims equal to the code |
| `release-engineer`         | Release files| CHANGELOG, workspace version, deploy overlays, Dockerfile, CI and release workflow, cargo audit |

## Modes

Parse `$ARGUMENTS`:

- `full <task>` (default when the first word is not a mode): all phases.
- `review [base-ref]`: skip phases 1–2. Diff the working tree (or `base-ref...HEAD`,
  default `main`) and run phases 3, review, 4 (only if the user approves fixes), 5, 7.
- `plan <task>`: phase 0 and 1 only; present the plan and stop.

If the task is ambiguous in a way that changes the design (which crate owns it,
proto vs. server, which transport, breaking config or wire behaviour or not),
ask the user **once**, before phase 1.

## Run workspace

Create a run directory so agents hand off through files instead of lossy
summaries. `target/` is gitignored, so nothing leaks into commits:

```bash
RUN=target/agent-workflow/$(date +%Y%m%d-%H%M%S)-<short-slug>
mkdir -p "$RUN"
```

Files in the run directory:

| File                     | Written by          | Read by |
|--------------------------|---------------------|---------|
| `brief.md`               | orchestrator        | everyone |
| `plan.md`                | radius-architect    | coder, QA, reviewers |
| `impl-notes.md`          | radius-coder        | QA, reviewers, scribe |
| `qa-report.md`           | qa-engineer         | reviewers, gate |
| `findings-<role>.md`     | each reviewer       | coder (fix loop), gate |
| `fixes-round-<n>.md`     | radius-coder        | re-verifying reviewers |
| `docs-update.md`         | docs-scribe         | gate |
| `release-notes.md`       | release-engineer    | gate |
| `gate.md`                | orchestrator        | user |

Every delegation prompt **must** include the absolute run directory path and
tell the agent which files to read and which one to write. Agents return a
short summary to you; the detail lives in the file.

## Phase 0 — Triage

1. Restate the task in `brief.md`: goal, out-of-scope, acceptance criteria,
   constraints from the user.
2. Identify the touched area (`crates/radius-proto`, `crates/radius-server`,
   `ui/`, `deploy/`, `tests/interop/`, docs). For `review` mode run
   `git diff --stat <base>...HEAD` plus `git status --short`.
3. Select reviewers using [references/triage-matrix.md](references/triage-matrix.md).
   Record the roster and the reason for each skipped role in `brief.md`.
4. Docs-only or comment-only changes: skip to phase 5 + markdownlint.

## Phase 1 — Plan (`radius-architect`)

Delegate with the brief path. Expect `plan.md` containing: approach, files to
touch, public API and config changes, wire-format or state-machine changes,
threat sketch, test plan (including which interop assertions apply),
pre-mapped RFC sections and FIPS/TLS obligations, and open questions.

- If `plan.md` has open questions that change behaviour, put them to the user
  before building.
- For a large plan, show the user the plan summary and get a go-ahead before
  phase 2. For a small, well-specified change, proceed.

## Phase 2 — Build (`radius-coder`)

Delegate with paths to `brief.md` and `plan.md`. The coder implements, cites
the governing RFC section in a comment wherever it implements a MUST/SHOULD,
runs `cargo fmt`, `cargo clippy` and the touched crates' tests, and writes
`impl-notes.md` (files changed, deviations from plan, known limitations, any
`// TODO(gap):` items added).

Parallel coders are allowed **only** when the plan splits into work units with
disjoint file sets and no ordering dependency. Then launch one `radius-coder`
per unit with `isolation: "worktree"` and merge their branches yourself
afterwards. Otherwise run one coder. Never let two coders edit the same files.

## Phase 3 — Verify (`qa-engineer`)

Delegate with the run directory. QA reads plan + impl notes, adds missing tests
(positive, negative, boundary, fail-secure, known-answer vectors for anything
cryptographic), and runs the gates in
[references/quality-gates.md](references/quality-gates.md), including the
interop harness when the triage matrix calls for it. Expect `qa-report.md`
with commands run, pass/fail, and coverage gaps.

If QA reports a failing build or tests, go straight to the fix loop before
spending reviewer time.

## Review — parallel

Launch every selected reviewer **in a single message** so they run
concurrently. Each gets the same context: run directory, base ref for the
diff, and the instruction to write `findings-<role>.md` in the format from
[references/report-format.md](references/report-format.md).

Do not paste your own opinion of the change into reviewer prompts; give them
the diff location and the plan, and let them form an independent view.

## Phase 4 — Fix loop

1. Collect all findings. De-duplicate across reviewers (same file+line+issue →
   keep the highest severity, credit both reviewers).
2. Sort into **must-fix** (BLOCKER, MAJOR) and **advisory** (MINOR, NIT).
3. Sanity-check each must-fix before sending it on: read the cited code. Drop
   findings that are clearly wrong and note why in `gate.md`.
4. Send must-fix findings to `radius-coder` (round *n*), who writes
   `fixes-round-<n>.md` mapping each finding ID → change or rebuttal.
5. Re-run `qa-engineer` gates, then re-run **only the reviewers whose findings
   were touched**, asking them to verify their specific IDs and to look for
   regressions in the changed hunks.
6. Stop after 3 rounds. Anything still open goes to the user as an explicit
   decision (accept as a documented gap in RFC-COMPLIANCE.md, change approach,
   or stop).

Advisory findings: batch them into one coder pass if cheap, otherwise list
them in `gate.md`.

## Phase 5 — Document (`docs-scribe`)

Mandatory for any code change. The scribe updates
`docs/docs/protocol/RFC-COMPLIANCE.md` (status tables, gap sections, matrix
rows, version history), `docs/docs/security/*.md`, `docs/docs/development/ROADMAP.md`
and the README "Supported RFCs" list as the plan, impl notes, findings and QA
report warrant, then writes `docs-update.md`. It must not claim a status the
code and tests do not show; "Complete" needs a passing test, and interop
claims need a passing harness assertion.

## Phase 6 — Release (`release-engineer`)

Run when the change is user-facing, touches `Cargo.toml`/`Cargo.lock`
(either workspace: root or `ui/bff`), `Dockerfile`, `ui/Dockerfile`,
`deploy/`, `examples/configs/`, `Makefile` or `.github/workflows/`. Produces
the CHANGELOG entry under `## [Unreleased]`, the suggested semver bump, and
checks deploy/CI consistency. Skip for internal refactors with no user-visible
effect; note the skip in `gate.md`.

## Phase 7 — Gate

Write `gate.md` with the gate table from
[references/report-format.md](references/report-format.md#gate-summary) and
decide:

- **PASS** — all gates green, no open BLOCKER/MAJOR, docs updated.
- **PASS WITH GAPS** — only items the user explicitly accepted, each recorded
  in RFC-COMPLIANCE.md (or the security overview) and as `// TODO(gap):` in code.
- **FAIL** — anything else. Say exactly what is open.

Then tell the user: verdict, what changed (files), test results with the actual
commands, open advisories, and any accepted gaps. Do **not** commit, push, or
open a PR unless the user asks; offer it as the next step.

## Orchestrator rules

- Give each subagent a self-contained prompt: goal, run directory, files to read,
  file to write, scope limits. They do not see this conversation.
- Reviewers are read-only. If a reviewer edits code, discard that edit and
  route the change through `radius-coder`.
- Treat agent reports as claims. Before declaring PASS, verify the key ones
  yourself (re-run the gate commands or read the cited lines). The unit tests
  in this repo drive rustls against rustls and this codebase's codec against
  itself; two real bugs were found only by the interop harness, so when the
  matrix calls for it, a PASS without the harness is not a PASS.
- Never weaken a security or conformance finding to get to PASS. Escalate.
- Keep the user's task list current: one plan step per phase that runs.
- Long-running commands (`cargo test --workspace --all-targets`, the interop
  harness, `cargo bench --no-run`) run in the background.
