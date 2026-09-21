#!/usr/bin/env bash
# Exercises the coverage ratchet decision logic against fixture summaries so a
# broken ratchet fails check.sh instead of silently passing pr-ci.sh.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fixture() {
  # fixture NAME COVERED COUNT: one file in crates/jeryu-core with the given lines
  cat >"$tmp/$1.json" <<JSON
{"data":[{"files":[{"filename":"$repo_root/crates/jeryu-core/src/lib.rs",
"summary":{"lines":{"covered":$2,"count":$3}}}]}]}
JSON
}
expect() {
  local want="$1"; shift
  local got=0
  JERYU_COVERAGE_BASELINE="$tmp/baseline.tsv" bash "$repo_root/ops/ci/coverage.sh" "$@" >"$tmp/out" 2>&1 || got=$?
  if [[ "$got" != "$want" ]]; then
    printf 'coverage selftest: expected exit %s, got %s for %s\n' "$want" "$got" "$*" >&2
    cat "$tmp/out" >&2
    exit 1
  fi
}

fixture base 80 100
fixture same 80 100
fixture noise 798 1000
fixture drop 70 100
expect 0 --update --compare "$tmp/base.json"
grep -qx $'jeryu-core\t0.8000' "$tmp/baseline.tsv"
expect 0 --compare "$tmp/same.json"
expect 0 --compare "$tmp/noise.json"
expect 1 --compare "$tmp/drop.json"
printf 'jeryu-gitd\t0.5000\n' >>"$tmp/baseline.tsv"
expect 1 --compare "$tmp/same.json"
expect 2 --bogus
printf 'coverage selftest ok\n'
