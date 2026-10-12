#!/usr/bin/env bash
# Prove the complete self-test fails when a child returns the wrong status,
# even when the child prints the expected verdict. No production test hook.
set -euo pipefail
umask 077

oracle="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/leak-oracle.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

expect_failure() {
  local label=$1 script=$2 status=0
  bash "$script" --self-test >"$tmp/$label.log" 2>&1 || status=$?
  if [[ $status -ne 1 ]]; then
    echo "leak-oracle regression failed: $label exit $status want 1" >&2
    exit 1
  fi
  if grep -F -q 'leak-oracle self-test passed' "$tmp/$label.log"; then
    echo "leak-oracle regression failed: $label printed a pass verdict" >&2
    exit 1
  fi
}

# Only the clean scan child's exit changes; its absent output stays intact.
# Other probe checks retain their correct statuses, isolating parent capture.
sed '$i\if [[ ${SCAN_PATHS[0]-} == */clean ]]; then exit 7; fi' \
  "$oracle" >"$tmp/clean-wrong-exit.sh"
expect_failure clean-wrong-exit "$tmp/clean-wrong-exit.sh"

# Only the dirty scan child exits zero after printing its present output.
sed '/^if \[\[ \$found -ne 0 \]\]; then$/a\  if [[ ${SCAN_PATHS[0]-} == */dirty ]]; then exit 0; fi' \
  "$oracle" >"$tmp/dirty-wrong-exit.sh"
expect_failure dirty-wrong-exit "$tmp/dirty-wrong-exit.sh"

# Faults stay in an isolated test namespace; ordinary scans use real tools.
# A partial enumeration or failed read must never become an absent verdict.
printf 'jeryu-canary-selftest-0123456789abcdef\n' >"$tmp/canary"
mkdir -p "$tmp/clean" "$tmp/find-fault" "$tmp/read-fault" "$tmp/probe-fault"
printf 'clean bytes\n' >"$tmp/clean/log.txt"
printf 'LEAK_ORACLE_PROBE=absent\n' >"$tmp/probe.txt"

expect_incomplete() {
  local label=$1 tools=$2 status=0
  shift 2
  PATH="$tools:$PATH" bash "$oracle" --canary-file "$tmp/canary" "$@" \
    >"$tmp/$label.log" 2>&1 || status=$?
  if [[ $status -ne 5 ]]; then
    echo "leak-oracle regression failed: $label exit $status want 5" >&2
    exit 1
  fi
  if grep -F -q 'leak-oracle: absent' "$tmp/$label.log"; then
    echo "leak-oracle regression failed: $label printed an absent verdict" >&2
    exit 1
  fi
}

# Emit one clean file, then fail enumeration before the remaining entries.
printf '#!/usr/bin/env bash\nprintf "%%s\\0" "${2}/log.txt"\nexit 9\n' \
  >"$tmp/find-fault/find"
chmod 700 "$tmp/find-fault/find"
expect_incomplete partial-enumeration "$tmp/find-fault" --scan "$tmp/clean"

# Fail a byte scan with grep's read-error status, rather than its no-match status.
printf '#!/usr/bin/env bash\nexit 2\n' >"$tmp/read-fault/grep"
chmod 700 "$tmp/read-fault/grep"
expect_incomplete file-read-error "$tmp/read-fault" --scan "$tmp/clean/log.txt"

# Complete the byte scan, then fail parsing the declared probe verdict.
real_grep=$(command -v grep)
printf '#!/usr/bin/env bash\nif [[ ${1-} == -c ]]; then exit 2; fi\nexec %q "$@"\n' \
  "$real_grep" >"$tmp/probe-fault/grep"
chmod 700 "$tmp/probe-fault/grep"
expect_incomplete probe-read-error "$tmp/probe-fault" --require-probe "$tmp/probe.txt"

mkdir -p "$tmp/metadata-fault" "$tmp/disappear-fault"
real_stat=$(command -v stat)
printf '#!/usr/bin/env bash\nif [[ ${!#} == */log.txt ]]; then exit 1; fi\nexec %q "$@"\n' \
  "$real_stat" >"$tmp/metadata-fault/stat"
chmod 700 "$tmp/metadata-fault/stat"
expect_incomplete file-metadata-error "$tmp/metadata-fault" --scan "$tmp/clean/log.txt"

# Record a real file, then remove it before the parent begins the admitted scan.
printf 'clean bytes\n' >"$tmp/clean/disappears.txt"
printf '#!/usr/bin/env bash\nprintf "%%s\\0" "${2}/disappears.txt"\nrm -f -- "${2}/disappears.txt"\n' \
  >"$tmp/disappear-fault/find"
chmod 700 "$tmp/disappear-fault/find"
expect_incomplete disappearing-entry "$tmp/disappear-fault" --scan "$tmp/clean"

echo 'leak-oracle regressions passed (wrong exits and incomplete scans rejected)'
