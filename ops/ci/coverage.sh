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

# BEGIN GENERATED JANKURAI PIN — DO NOT EDIT
export JERYU_JANKURAI_SOURCE_REPO="https://git.neverhuman.org/git/jeryu/jankurai.git"
export JERYU_JANKURAI_VERSION="jankurai 1.6.11"
export JERYU_JANKURAI_SHA256="9e6b8857a26f6004d4c74e510e13b06d880f2e2ae0c89502698889ed690c5d6c"
export JERYU_JANKURAI_SOURCE_REV="b88562fdb124aa86dedd70ab972e7d0d87e58be1"
export JERYU_JANKURAI_SOURCE_TAG="v1.6.11-deadlang-precision-split.3"
export JERYU_JANKURAI_SOURCE_TREE="611229e54938c0e8808896e369fd54d095d258f7"
export JERYU_JANKURAI_SOURCE_ARCHIVE_SHA256="903a231eca8f6a1f050953b603d5a278a1606abcdf47434eb1b45262d74068aa"
export JERYU_JANKURAI_CARGO_LOCK_SHA256="b9acb981c326226a687d0b6703e4f7ee303148e9e1a6dda1aa03d77988820f6a"
export JERYU_JANKURAI_RUST_TOOLCHAIN="1.95.0"
export JERYU_JANKURAI_RUSTC_VERSION="rustc 1.95.0 (59807616e 2026-04-14)"
export JERYU_JANKURAI_CARGO_VERSION="cargo 1.95.0 (f2d3ce0bd 2026-03-21)"
export JERYU_JANKURAI_TARGET_TRIPLE="x86_64-unknown-linux-gnu"
export JERYU_JANKURAI_BUILD_MODE="oci-vendor-locked-offline-workspace-member-v2"
export JERYU_JANKURAI_PACKAGE_PATH="crates/jankurai"
export JERYU_JANKURAI_BUILDER_IMAGE="rust@sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082"
export JERYU_JANKURAI_BUILDER_IMAGE_ID="sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082"
export JERYU_JANKURAI_LINKER_VERSION="GNU ld (GNU Binutils for Debian) 2.40"
export JERYU_JANKURAI_GLIBC_VERSION="ldd (Debian GLIBC 2.36-9+deb12u14) 2.36"
export JERYU_JANKURAI_VENDOR_FILES_SHA256="a7e332f4495d9748ea020ae8ee37c4240f0f035059799bd3dc74497437143d99"
export JERYU_JANKURAI_VENDOR_FILE_COUNT="14889"
export JERYU_JANKURAI_CARGO_CONFIG_SHA256="b8982c761d62e447f2d1653c199d2d58e6b2de6c5a6f8ddba3d38e47b7f863d6"
export JERYU_JANKURAI_BUILD_ENVIRONMENT="CARGO_NET_OFFLINE=true,HOME=/tmp,LANG=C,LC_ALL=C,SOURCE_DATE_EPOCH=0,TZ=UTC"
export JERYU_JANKURAI_RUSTFLAGS="--remap-path-prefix=/opt/jeryu/jankurai=/jankurai-build/source --remap-path-prefix=/opt/jeryu/vendor=/jankurai-build/vendor --remap-path-prefix=/opt/jeryu/target=/jankurai-build/target --remap-path-prefix=/usr/local/cargo=/jankurai-build/cargo"
export JERYU_JANKURAI_BUILD_COMMAND="cargo install --locked --offline --path /opt/jeryu/jankurai/crates/jankurai --root /opt/jeryu/out --bin jankurai"
export JERYU_JANKURAI_BUILD_CONTEXT_SHA256="889d19f86fc390b0f0cf0bd6ecb4d451c51a2d6fb328e5520e4310e7ee5dedd6"
# END GENERATED JANKURAI PIN

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
