# Testing

This is the canonical testing guide for the jeryu product family. It describes
jeryu-core as it exists after the repository split; the other split repositories
(jeryu-deploy, jeryu-ci-runner, jeryu-web, jeryu-tool) keep a short
`docs/testing.md` that points here and lists only their own gate.

Local CI is the source of truth. `.github/workflows/ci.yml` runs the same
`ops/ci/pr-ci.sh` on the GitHub mirror, so the two surfaces cannot diverge.

## Workspace

The Cargo workspace (`Cargo.toml`) has these members:

| Crate | Integration tests (`crates/<crate>/tests/`) |
| --- | --- |
| `jeryu-core` | account, repository lifecycle (archive, delete, rename, transfer), pull requests, branch protection, checks/statuses, deployments, webhooks, SQLite persistence, serde shapes |
| `domain` | unit tests only |
| `jeryu-gitd` | refs, protected refs, pre-receive, quarantine, merge, LFS, HTTP auth, imported repos, git oracle and differential oracle |
| `jeryu-readmodel` | read-model round trip and generated contract drift |
| `jeryu-mirror` | GitHub import, mirror drift, offline bundle, restore invariants |
| `jeryu-mirror-cli` | unit tests only |
| `jeryu-tui` | interaction, lens snapshots, terminal snapshots |
| `jeryu-bugtracker` | store CRUD |
| `jeryu-enterprise` | RBAC, SSO, tenant isolation, backup drill, upgrade rollback, red team |
| `jeryu-proof` | plan, matcher, witness, generated zones |

Database migrations and rollbacks live under `db/`; see `db/README.md`.

## Commands

`Justfile` recipes wrap the scripts in `ops/ci/`:

| Recipe | Script | What it does |
| --- | --- | --- |
| `just fast` | `ops/ci/fast.sh` | runs `check.sh` without the full compile |
| `just check` | `ops/ci/check.sh` | `cargo metadata`, `bash -n` on every script, coverage ratchet self-test; with `JERYU_SPLIT_FULL_CHECK=1` also `cargo check --workspace --all-targets` |
| `just score` | `ops/ci/score.sh` | verifies split metadata under `agent/` and runs `jankurai audit` |
| `just security` | `ops/ci/security.sh` | gitleaks, actionlint, committed `.env` check; `cargo deny` when `JERYU_SECURITY_NETWORK=1` |
| `just artifact-support` | `ops/ci/artifact_support.sh` | artifact support checks |
| `just required` | `ops/ci/pr-ci.sh` | the protected `jeryu-core/required` gate (below) |

`scripts/ci-local.sh` runs `just fast` then `just check`. `ops/ci/proof_evidence.sh`
writes jankurai audit and security evidence under `target/jankurai/`; hosted CI
runs it after `pr-ci.sh`.

Everyday loops:

```bash
JERYU_SPLIT_FULL_CHECK=1 ./ops/ci/check.sh
cargo test --offline -p jeryu-core -p jeryu-readmodel -p jeryu-gitd
cargo test --offline -p <crate> --test <file-stem>   # one integration test file
```

## Required gate

`ops/ci/pr-ci.sh` is what host-ci runs to post the `jeryu-core/required` check:

1. Resolves the worker count: `JERYU_CI_JOBS` if set, else `jeryu-ci-governor`,
   else 8. `CARGO_BUILD_JOBS` follows it.
2. Verifies the governed `jankurai` binary against the pin in `ops/ci/lib.sh`
   (`ops/ci/ensure-jankurai.sh` installs it on hosted runners). When
   `../jeryu-tool` is checked out beside this repo it also fails on pin drift.
3. Runs `fast.sh`, `check.sh` (full), `score.sh`, `security.sh`,
   `artifact_support.sh`.
4. Runs `cargo nextest run --workspace`.
5. Runs the coverage ratchet.

## Coverage ratchet

`ops/ci/coverage.sh` measures per-crate line coverage of `jeryu-core`,
`jeryu-readmodel`, and `jeryu-gitd` with `cargo llvm-cov` and compares it to
`ops/ci/coverage-baseline.tsv` (tab-separated `crate<TAB>ratio`). A crate that
falls more than `JERYU_COVERAGE_TOLERANCE` (default `0.005`) below its floor
fails.

- Exit codes: `0` ok, `1` regression, `3` PENDING (`cargo-llvm-cov` not
  installed; `pr-ci.sh` reports it and continues).
- `bash ops/ci/coverage.sh --update` rewrites the baseline from a fresh
  measurement. Raise floors when coverage improves; do not lower them to make
  a change pass.
- `bash ops/ci/coverage.sh --compare FILE` compares an existing llvm-cov JSON
  summary without re-measuring.
- `ops/ci/coverage_selftest.sh` (run by `check.sh`) exercises the ratchet logic
  against fixture summaries, so a broken ratchet fails the check rather than
  passing silently.

## Workcells

Workcell execution (jail, runner daemon, agent bridge, egress proxy, and the
`/api/v1/workcells` and `/api/v1/agent-runs` routes) lives in jeryu-deploy and
jeryu-ci-runner; run their gates there. In this repo the workcell and agent-run
dashboards are covered by:

```bash
cargo test --offline -p jeryu-readmodel -p jeryu-tui
```

## Codegraph Oracle

The codegraph crate, its MCP tools, and the
`POST /api/v1/repos/{id}/codegraph/query` route live in jeryu-deploy
(`cargo test --offline -p jeryu-api --features web codegraph`). In this repo
only the read-model contracts and TUI evidence lens touch codegraph; they are
covered by the `jeryu-readmodel` and `jeryu-tui` tests above.

## Other repositories

Each split repository keeps its own gate; its `docs/testing.md` should be a
stub like this one:

```markdown
# Testing

The family-wide testing guide lives in jeryu-core: `docs/testing.md`.

Gate for this repository: `<command>`
```

Known gates:

- jeryu-deploy: `cargo test --offline -p jeryu-api --features web` (without
  `--features web` the web tests do not run).
- jeryu-ci-runner: `JERYU_SPLIT_FULL_CHECK=1 ./ops/ci/check.sh`.
- jeryu-web: Playwright action tests plus `npm run -s test:e2e:matrix`; a new
  or removed `@action:` tag must be reflected in
  `apps/web/e2e/action-matrix.json`.
