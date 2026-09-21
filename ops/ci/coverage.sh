#!/usr/bin/env bash
# Line-coverage ratchet for jeryu-core. Measures per-crate line coverage with
# cargo-llvm-cov and fails when any crate drops below its recorded baseline in
# ops/ci/coverage-baseline.tsv (minus a small tolerance for measurement noise).
#
# Exit codes: 0 = at or above baseline, 1 = regression, 3 = PENDING
# (cargo-llvm-cov unavailable, so nothing was measured).
#
#   ops/ci/coverage.sh                  measure and compare
#   ops/ci/coverage.sh --update         measure and rewrite the baseline
#   ops/ci/coverage.sh --compare FILE   use an existing llvm-cov JSON summary
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

baseline="${JERYU_COVERAGE_BASELINE:-ops/ci/coverage-baseline.tsv}"
tolerance="${JERYU_COVERAGE_TOLERANCE:-0.005}"
packages=(jeryu-core jeryu-readmodel jeryu-gitd)
mode=compare
summary=""

while (($#)); do
  case "$1" in
    --update) mode=update; shift ;;
    --compare) summary="${2:?--compare needs a summary JSON path}"; shift 2 ;;
    *) printf 'usage: %s [--update] [--compare FILE]\n' "$0" >&2; exit 2 ;;
  esac
done

if [[ -z "$summary" ]]; then
  if ! cargo llvm-cov --version >/dev/null 2>&1; then
    printf '[coverage] PENDING: cargo-llvm-cov not installed; coverage not measured\n' >&2
    exit 3
  fi
  out_dir="${CARGO_TARGET_DIR:-target}/jankurai/coverage"
  mkdir -p "$out_dir"
  summary="$out_dir/llvm-cov-summary.json"
  pkg_args=()
  for p in "${packages[@]}"; do pkg_args+=(-p "$p"); done
  cargo llvm-cov --offline "${pkg_args[@]}" --summary-only --json --output-path "$summary"
fi

python3 - "$summary" "$baseline" "$tolerance" "$mode" "$repo_root" <<'PY'
import json, sys
from collections import defaultdict
from pathlib import Path

summary, baseline_path, tolerance, mode, root = sys.argv[1:]
tolerance = float(tolerance)
root = root.rstrip("/") + "/"
counts = defaultdict(lambda: [0, 0])
for f in json.loads(Path(summary).read_text())["data"][0]["files"]:
    name = f["filename"]
    rel = name[len(root):] if name.startswith(root) else name
    parts = rel.split("/")
    if len(parts) < 2 or parts[0] != "crates":
        continue
    lines = f["summary"]["lines"]
    counts[parts[1]][0] += lines["covered"]
    counts[parts[1]][1] += lines["count"]
measured = {k: c / n for k, (c, n) in counts.items() if n}

path = Path(baseline_path)
if mode == "update":
    body = "".join(f"{k}\t{v:.4f}\n" for k, v in sorted(measured.items()))
    path.write_text("# crate\tline-coverage ratio (ops/ci/coverage.sh --update)\n" + body)
    print(f"[coverage] baseline written: {path}")
    sys.exit(0)

failed = False
for raw in path.read_text().splitlines():
    if not raw.strip() or raw.startswith("#"):
        continue
    crate, floor = raw.split("\t")
    floor = float(floor)
    got = measured.get(crate)
    if got is None:
        print(f"[coverage] FAIL {crate}: no coverage data (baseline {floor:.4f})")
        failed = True
    elif got + tolerance < floor:
        print(f"[coverage] FAIL {crate}: {got:.4f} < baseline {floor:.4f}")
        failed = True
    else:
        note = "  (raise the baseline: --update)" if got - floor > 0.01 else ""
        print(f"[coverage] ok   {crate}: {got:.4f} >= {floor:.4f}{note}")
sys.exit(1 if failed else 0)
PY
