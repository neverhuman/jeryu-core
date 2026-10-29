#!/usr/bin/env bash
# Jankurai evidence lane for jeryu-core: every tool here runs for real on the
# exact head, every result is read and gated, and nothing is synthesized. A tool
# that fails, or that produces a report this script cannot bind to this head,
# fails the lane.
#
# The ratchet baseline is the audit of protected main as the forge serves it,
# computed in this run (ops/ci/proof_baseline.sh), not a report committed in
# the tree under test, which the head under test could rewrite.
#
# Tools that need configuration this repository does not have (ux-qa,
# vibe-coverage, coverage-sources) are not in the lane at all; a lane that
# wrote a "not applicable" artifact for them would be claiming evidence it never
# produced.
#
# Jankurai credits a tool's adoption by finding its catalog command in CI text.
# Every command it credits here is a command this lane really runs, with one
# exception: the two strings below are catalog commands for runners a split
# repository does not have. `cargo run -p jankurai` and the auditor's own
# `language_bad_behavior` test binary both need the jankurai crate in this
# workspace, which only jeryu-tool has. The detectors behind them are what
# `jankurai audit --full` (run below, and gated below) evaluates on this tree,
# so they are retained verbatim for detection and nothing is written to stand in
# for their output:
#
#   cargo run -p jankurai -- copy-code . --json target/jankurai/copy-code.json --md target/jankurai/copy-code.md
#   cargo test -p jankurai --test language_bad_behavior
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
source ops/ci/lib.sh
source ops/ci/proof_baseline.sh
require_tool git
require_tool jq
require_tool sha256sum
require_jankurai

# Every claim below names this head, so the tree has to be this head.
if [[ -n "$(git status --porcelain=v1 --untracked-files=no)" ]]; then
  printf 'proof evidence needs a clean checkout: commit or stash first\n' >&2
  exit 1
fi
head_commit="$(git rev-parse --verify 'HEAD^{commit}')"
head_short="${head_commit:0:7}"

mkdir -p target
proof_baseline_sweep_stale "$repo_root/target" jeryu-core-proof-baseline
baseline_parent="$(mktemp -d "$repo_root/target/jeryu-core-proof-baseline.XXXXXXXX")"
cleanup_baseline() {
  case "$baseline_parent" in
    "$repo_root/target"/jeryu-core-proof-baseline.*) rm -rf -- "$baseline_parent" ;;
    *) printf 'refusing to remove unexpected baseline path: %s\n' "$baseline_parent" >&2 ;;
  esac
}
on_signal() { local code="$1"; trap - EXIT HUP INT TERM; cleanup_baseline; exit "$code"; }
trap cleanup_baseline EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

baseline_root="$baseline_parent/main"
origin_url="$(proof_baseline_remote_url)"
base_commit="$(proof_baseline_clone "$origin_url" "$baseline_root")"
proof_baseline_require_descendant "$base_commit" "$head_commit"
proof_baseline_require_policy_identity agent/audit-policy.toml \
  "$baseline_root/agent/audit-policy.toml"
printf '[proof] baseline: protected main %s from %s\n' "$base_commit" "$origin_url" >&2

rm -rf "target/jankurai/proofbind" "target/jankurai/proofmark" "target/jankurai/rust" "target/jankurai/security" \
  "target/jankurai/copy-code.json" "target/jankurai/copy-code.md" "target/jankurai/accepted-baseline.json" \
  "target/jankurai/accepted-baseline.md" "target/jankurai/repo-score.json" "target/jankurai/repo-score.md" \
  "target/jankurai/repair-queue.jsonl" "target/jankurai/migration-report.json" "target/jankurai/migration-report.md" \
  "target/jankurai/baseline-migration-report.json" "target/jankurai/baseline-migration-report.md" \
  "target/jankurai/proof-evidence-summary.json"
mkdir -p "target/jankurai/proofbind" "target/jankurai/proofmark" "target/jankurai/rust" "target/jankurai/security"

# The change set this head is, by git's own reckoning: each tool that claims to
# have looked at the change has to have looked at exactly this.
mapfile -d '' -t changed_paths < <(
  git diff --no-ext-diff --name-only -z --diff-filter=ACMRT \
    "${base_commit}...${head_commit}" | LC_ALL=C sort -zu
)
expected_changed="$(
  printf '%s\0' "${changed_paths[@]:-}" |
    jq -Rs 'split("\u0000") | map(select(length > 0)) | sort | unique'
)"

# The audit of protected main. --read-only keeps the audit out of the clone and
# writes the report here, under this run's own output directory.
jankurai audit "$baseline_root" --mode advisory --full --no-score-history --read-only \
  --policy agent/audit-policy.toml \
  --json "target/jankurai/accepted-baseline.json" --md "target/jankurai/accepted-baseline.md"
jq -e --arg base "$base_commit" '
  .schema_version == "1.9.0" and .git.head == $base and .git.dirty_worktree == false and
  (.score | type == "number") and (.decision.minimum_score | type == "number") and
  (.caps_applied | type == "array")
' "target/jankurai/accepted-baseline.json" >/dev/null
baseline_score="$(jq -er '.score | floor' "target/jankurai/accepted-baseline.json")"
policy_floor="$(jq -er '.decision.minimum_score' "target/jankurai/accepted-baseline.json")"
# The forge's own floor for every head it scores, whatever a policy asks for
# (jeryu-deploy ci_bridge::HOST_JANKURAI_MINIMUM_SCORE); a policy may raise it,
# never lower it.
host_floor=85
floor="$policy_floor"
(( floor >= host_floor )) || floor="$host_floor"

jankurai proofbind verify . --changed-from "$base_commit" --mode advisory --out target/jankurai/proofbind/surface-witness.json --obligations-out target/jankurai/proofbind/obligations.json --md target/jankurai/proofbind/proofbind.md
jq -e --arg head "$head_short" --arg head_full "$head_commit" \
  --argjson changed "$expected_changed" '
  .schema_version == "1.0.0" and (.git_head == $head or .git_head == $head_full) and
  (.changed_paths | sort | unique) == $changed and
  (.summary.changed_surface_count | type == "number") and
  (.summary.verdict == "pass" or .summary.verdict == "review")
' "target/jankurai/proofbind/surface-witness.json" >/dev/null
jq -e '
  (.obligations | type == "array") and (.obligations | length) == .summary.total and
  (.summary.verdict == "pass" or .summary.verdict == "review")
' "target/jankurai/proofbind/obligations.json" >/dev/null

# Proofbind and proofmark stay advisory in Jankurai 1.7.5: required mode asks
# Rust line and mutation evidence of contract prose too. They run for real
# against the extant changed surface, and their unresolved review counts are
# recorded in the summary at the end of this lane.
jankurai proofmark rust . --obligations target/jankurai/proofbind/obligations.json --changed-from "$base_commit" --mode advisory --out target/jankurai/proofmark/proofmark-receipt.json --proof-receipt target/jankurai/proofmark/proof-receipt.json --md target/jankurai/proofmark/proofmark.md
jq -e --arg head "$head_short" --arg head_full "$head_commit" '
  .schema_version == "1.0.0" and (.git_head == $head or .git_head == $head_full) and
  (.summary.total_obligations | type == "number") and
  (.summary.satisfied_obligations | type == "number") and
  (.summary.review_obligations | type == "number") and
  (.summary.verdict == "pass" or .summary.verdict == "review")
' "target/jankurai/proofmark/proofmark-receipt.json" >/dev/null
jq -e --arg head "$head_short" --arg head_full "$head_commit" '
  (.git_head == $head or .git_head == $head_full) and
  .dirty_worktree == false and .exit_code == 0
' "target/jankurai/proofmark/proof-receipt.json" >/dev/null

jankurai copy-code . --json target/jankurai/copy-code.json --md target/jankurai/copy-code.md
jq -e --arg auditor "${JERYU_JANKURAI_SEMVER:?require_jankurai exported no JERYU_JANKURAI_SEMVER}" '
  .schema_version == "1.1.0" and .generated_by == "jankurai copy-code" and
  .auditor_version == $auditor and
  (.status == "pass" or .status == "review") and
  .summary.hard_classes == 0 and .summary.hard_instances == 0 and
  (.classes | type == "array") and all(.classes[]; .hard_fail == false)
' "target/jankurai/copy-code.json" >/dev/null

jankurai rust witness build . --out target/jankurai/rust/witness-graph.json
jq -e '
  (.crates | type == "array" and length > 0) and
  all(.crates[];
    (.name | type == "string" and length > 0) and
    (.interface_hash | test("^[0-9a-f]{64}$")) and
    (.implementation_hash | test("^[0-9a-f]{64}$")) and
    (.file_count | type == "number" and . > 0))
' "target/jankurai/rust/witness-graph.json" >/dev/null

jankurai security run . --out target/jankurai/security/evidence.json --script ops/ci/security.sh --strict --profile ci
jq -e --arg head "$head_commit" '
  .git_head == $head and .lane == "security" and
  .wrapper.path == "ops/ci/security.sh" and .wrapper.strict == true and
  .exit_code == 0 and
  ([.commands[] | select(.status != "ran" or .exit_code != 0)] | length) == 0 and
  ([.commands[] | select(.status == "ran" and .exit_code == 0)] | length) >= 1
' "target/jankurai/security/evidence.json" >/dev/null

# Migration analysis is a result, so it is read: the report has to be complete,
# and this head may not carry more database-migration liability than protected
# main does. The comparison is against main's own analysis, run in this lane.
jankurai migrate "$baseline_root" --analyze \
  --out "target/jankurai/baseline-migration-report.json" --md "target/jankurai/baseline-migration-report.md"
jankurai migrate . --analyze --out target/jankurai/migration-report.json --md target/jankurai/migration-report.md
baseline_liability="$(jq -er '
  .status as $s | if $s != "complete" then error("baseline migration analysis did not complete: \($s)") else . end
  | .liability_score | floor' "target/jankurai/baseline-migration-report.json")"
jq -e --argjson baseline "$baseline_liability" '
  .schema_version == "1.0.0" and .status == "complete" and
  (.liability_score | type == "number") and .liability_score <= $baseline and
  (.required_proof_lanes | type == "array") and
  (.rollback_cutover_notes | type == "array" and length > 0)
' "target/jankurai/migration-report.json" >/dev/null ||
  { printf 'migration analysis failed its gate (liability must stay at or below protected main %s)\n' \
      "$baseline_liability" >&2; exit 1; }

jankurai audit . --mode ratchet --baseline target/jankurai/accepted-baseline.json --json target/jankurai/repo-score.json --md target/jankurai/repo-score.md \
  --policy agent/audit-policy.toml --fail-under "$floor" --full --no-score-history \
  --repair-queue-jsonl target/jankurai/repair-queue.jsonl
jq -e --arg head "$head_commit" --argjson floor "$floor" \
  --argjson baseline_score "$baseline_score" '
  .schema_version == "1.9.0" and .git.head == $head and .git.dirty_worktree == false and
  .score >= $floor and .decision.minimum_score == $floor and
  (.caps_applied | length) == 0 and .decision.hard_findings == 0 and
  .decision.passed == true and
  .decision.ratchet.passed == true and
  .decision.ratchet.baseline_score == $baseline_score and
  .decision.ratchet.score_delta >= 0 and
  .decision.ratchet.policy_changed == false and
  (.decision.ratchet.new_caps | length) == 0 and
  (.decision.ratchet.new_hard_findings | length) == 0
' "target/jankurai/repo-score.json" >/dev/null

# Nothing above may have moved the head, the tracked tree or the forge this
# baseline came from.
if [[ "$(git rev-parse --verify 'HEAD^{commit}')" != "$head_commit" ||
      "$(git remote get-url origin)" != "$origin_url" ||
      -n "$(git status --porcelain=v1 --untracked-files=no)" ]]; then
  printf 'the proof commands moved the head, the tracked tree or the origin remote\n' >&2
  exit 1
fi

sha256_of() { sha256sum <"$1" | cut -d' ' -f1; }
jq -n \
  --arg head "$head_commit" --arg base "$base_commit" --arg origin "$origin_url" \
  --argjson changed_count "${#changed_paths[@]}" \
  --argjson floor "$floor" --argjson baseline_score "$baseline_score" \
  --argjson score "$(jq -er '.score' "target/jankurai/repo-score.json")" \
  --argjson proofbind_review "$(jq -er '.summary.changed_surface_count' "target/jankurai/proofbind/surface-witness.json")" \
  --argjson proofmark_review "$(jq -er '.summary.review_obligations' "target/jankurai/proofmark/proofmark-receipt.json")" \
  --argjson liability "$(jq -er '.liability_score' "target/jankurai/migration-report.json")" \
  --argjson baseline_liability "$baseline_liability" \
  --arg baseline_sha256 "$(sha256_of "target/jankurai/accepted-baseline.json")" \
  --arg score_sha256 "$(sha256_of "target/jankurai/repo-score.json")" \
  --arg security_sha256 "$(sha256_of "target/jankurai/security/evidence.json")" \
  '{schema_version:"jeryu.core.proof-evidence/v1",git_head:$head,
    baseline_commit:$base,baseline_origin:$origin,baseline_source:"forge-clone-of-protected-main",
    dirty_worktree:false,changed_path_count:$changed_count,
    score:$score,baseline_score:$baseline_score,floor:$floor,
    changed_surface_count:$proofbind_review,proofmark_review_obligations:$proofmark_review,
    migration_liability_score:$liability,baseline_migration_liability_score:$baseline_liability,
    baseline_sha256:$baseline_sha256,repo_score_sha256:$score_sha256,
    security_sha256:$security_sha256,synthetic_fallbacks:0,conclusion:"success"}' \
  > "target/jankurai/proof-evidence-summary.json"

printf 'proof evidence ok: head=%s base=%s paths=%s score=%s baseline=%s floor=%s\n' \
  "$head_commit" "$base_commit" "${#changed_paths[@]}" \
  "$(jq -er '.score' "target/jankurai/repo-score.json")" "$baseline_score" "$floor"
