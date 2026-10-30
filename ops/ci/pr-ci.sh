#!/usr/bin/env bash
# Canonical local PR gate for jeryu-core. host-ci prefers this script and posts the
# `jeryu-core/required` check-run from its exit status; .github/workflows/ci.yml runs
# the same lanes on the GitHub mirror so the two surfaces cannot diverge.
set -euo pipefail

# BEGIN GENERATED JANKURAI PIN — DO NOT EDIT
# The governed Jankurai identity is the binary installed on this host and its
# installation receipt: require_jankurai verifies both and exports JERYU_JANKURAI_*
# from the receipt. The one pin of record is jeryu-tool's tool-manifest.toml.
# END GENERATED JANKURAI PIN


repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

# jeryu governs the worker count from live load; never default high.
if [ -n "${JERYU_CI_JOBS:-}" ]; then
  JOBS="${JERYU_CI_JOBS}"
elif command -v jeryu-ci-governor >/dev/null 2>&1; then
  JOBS="$(jeryu-ci-governor 2>/dev/null || echo 8)"
else
  JOBS=8
fi
export JERYU_CI_JOBS="$JOBS"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$JOBS}"

# Resolve and verify the absolute governed auditor before any lane runs.
source ops/ci/lib.sh
require_jankurai

# Verify only this PR worktree against the family manifest; the post-rollout
# control-plane check verifies the complete canonical family. The renderer is
# jeryu-tool's, outside this checkout: a missing one fails closed, and one inside
# this checkout (which the pull request under test could have written) is refused.
if [ -z "${JERYU_TOOL_RENDER+x}" ]; then
JERYU_TOOL_RENDER="$repo_root/../jeryu-tool/ops/render-tool-manifest.sh"
fi
[ -n "$JERYU_TOOL_RENDER" ] || { echo "[pr-ci] missing JERYU_TOOL_RENDER" >&2; exit 1; }
[ -x "$JERYU_TOOL_RENDER" ] || { echo "[pr-ci] renderer is not executable: $JERYU_TOOL_RENDER" >&2; exit 1; }
render_real="$(realpath "$JERYU_TOOL_RENDER")"
case "$render_real/" in
"$(realpath "$repo_root")/"*) echo "[pr-ci] refusing a renderer inside this checkout: $JERYU_TOOL_RENDER" >&2; exit 1 ;;
esac
echo "[pr-ci] jankurai pin drift check" >&2
consumer_repo="$(awk -F'\"' '/^workspace =/ {print $2; exit}' agent/audit-policy.toml)"
bash "$render_real" --check --repo "$consumer_repo" \
--repo-root "$consumer_repo=$repo_root"

# Bind the candidate declaration to the installation receipt that lib.sh has
# already verified, even when this repo is reviewed without the family tree.
source ops/ci/proof_baseline.sh
proof_require_governed_declaration agent/audit-policy.toml "${JERYU_JANKURAI_SEMVER:?}"

# Ordinary compilation -- cargo check and the workspace test build -- builds in the gate runner's
# retained per-slot cache when the gate host offers one (JERYU_CI_BUILD_CACHE_DIR; jeryu-ci-runner
# ops/pr-gate/README.md, "Reusing ordinary compilation without retaining proof"). Reports this
# recipe writes (.jankurai/, target/jankurai/, target/security/, target/artifact-support/) name
# target/ literally and stay outside the cache; the TUIwright receipt test skips the cache too, and
# the coverage ratchet below builds outside it. The runner retains the cache only after a green gate
# and discards it when tools, recipe or Cargo.lock change; cargo still checks every source file's
# freshness. Unset (a laptop, another host), cargo builds into target/ as before.
# BEGIN BUILD CACHE GUARD
if [ -n "${JERYU_CI_BUILD_CACHE_DIR:-}" ]; then
  # Accept only this checkout's own physical target/build-cache, owned by this user (the layout the
  # gate runner gives), never a symlink or a path elsewhere; and never reuse incremental state.
  cache_dir="$JERYU_CI_BUILD_CACHE_DIR"
  cache_top="$repo_root"
  if [[ -L "$cache_top/target" || -L "$cache_dir" || ! -d "$cache_dir" || ! -O "$cache_dir" \
        || "$(cd "$cache_dir" && pwd -P)" != "$(cd "$cache_top" && pwd -P)/target/build-cache" ]]; then
    echo "refusing JERYU_CI_BUILD_CACHE_DIR=$cache_dir: only this checkout's physical target/build-cache is accepted" >&2
    exit 1
  fi
  CARGO_TARGET_DIR="$(cd "$cache_dir" && pwd -P)"
  # Re-export the resolved spelling too, so anything comparing the two (the TUIwright receipt
  # test keeps its receipt out of the cache that way) compares identical strings.
  JERYU_CI_BUILD_CACHE_DIR="$CARGO_TARGET_DIR"
  export CARGO_TARGET_DIR JERYU_CI_BUILD_CACHE_DIR CARGO_INCREMENTAL=0
  echo "[pr-ci] ordinary compilation in ${CARGO_TARGET_DIR} (the gate runner's build cache)" >&2
fi
# END BUILD CACHE GUARD

echo "[pr-ci] (jobs=$JOBS) standard lanes" >&2
bash ops/ci/fast.sh
JERYU_SPLIT_FULL_CHECK=1 bash ops/ci/check.sh
bash ops/ci/score.sh
bash ops/ci/security.sh
bash ops/ci/artifact_support.sh

echo "[pr-ci] workspace test suite" >&2
cargo nextest run --workspace --build-jobs "$JOBS" --test-threads "$JOBS"

# Coverage ratchet: a per-crate drop below ops/ci/coverage-baseline.tsv fails the
# required check. Exit 3 means PENDING (cargo-llvm-cov absent on this host):
# report it and continue rather than block on a missing tool.
echo "[pr-ci] coverage ratchet" >&2
coverage_rc=0
if [ -n "${JERYU_CI_BUILD_CACHE_DIR:-}" ]; then
  # Never in the shared build cache: cargo-llvm-cov builds instrumented objects in
  # $CARGO_TARGET_DIR/llvm-cov-target and reports over every profile it finds there, and
  # coverage.sh writes its summary under $CARGO_TARGET_DIR. In target/ both start fresh.
  CARGO_TARGET_DIR=target bash ops/ci/coverage.sh || coverage_rc=$?
else
  bash ops/ci/coverage.sh || coverage_rc=$?
fi
if [ "$coverage_rc" -eq 3 ]; then
  echo "[pr-ci] coverage PENDING: cargo-llvm-cov not installed" >&2
elif [ "$coverage_rc" -ne 0 ]; then
  echo "[pr-ci] coverage ratchet failed (exit $coverage_rc)" >&2
  exit "$coverage_rc"
fi
echo "[pr-ci] proof evidence" >&2
bash ops/ci/proof_evidence.sh

echo "[pr-ci] jeryu-core OK" >&2
