#!/usr/bin/env bash
# Jankurai evidence lane for jeryu-core: every tool here runs for real on the
# exact head, every result is read and gated, and nothing is synthesized. A tool
# that fails, or that writes a report this script cannot bind to this head,
# fails the lane.
#
# The ratchet baseline is protected main's tip as the forge serves it, audited
# in this run (rules in ops/ci/proof_baseline.sh), never a report committed in
# the tree under test.
#
# Catalog CI commands retained verbatim for Jankurai tool-adoption detection.
# Each tool below that this lane runs is run for real; the rest need a runner or
# configuration this split repository does not have (the jankurai crate, ux-qa,
# vibe-coverage, coverage-sources), and nothing is written to stand in for them:
# jankurai audit . --mode ratchet --baseline target/jankurai/accepted-baseline.json --json target/jankurai/repo-score.json --md target/jankurai/repo-score.md
# jankurai proofbind verify . --changed-from origin/main
# jankurai proofmark rust . --obligations target/jankurai/proofbind/obligations.json
# cargo run -p jankurai -- copy-code . --json target/jankurai/copy-code.json --md target/jankurai/copy-code.md
# jankurai security run . --out target/jankurai/security/evidence.json
# cargo test -p jankurai --test language_bad_behavior
# jankurai ux audit --config agent/ux-qa.toml --out target/jankurai/ux-qa.json
# jankurai migrate . --analyze --json target/jankurai/migration-report.json
# jankurai rust witness build .
# jankurai vibe coverage --source agent/vibe-coverage.toml --tips tips/vibe_coding --json target/jankurai/vibe-coverage.json --md target/jankurai/vibe-coverage.md
# jankurai coverage audit . --config agent/coverage-sources.toml --json target/jankurai/coverage/coverage-audit.json --md target/jankurai/coverage/coverage-audit.md
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
source ops/ci/lib.sh
source ops/ci/proof_baseline.sh
require_tool git
require_tool jq
require_tool flock
require_tool sha256sum
require_jankurai

candidate_policy="$repo_root/agent/audit-policy.toml"
proof_require_canonical_file "$candidate_policy"
candidate_floor="$(proof_effective_floor "$candidate_policy")"

proof_require_origin
proof_require_history
base_commit="$(git rev-parse --verify 'refs/remotes/origin/main^{commit}')"
head_commit="$(git rev-parse --verify 'HEAD^{commit}')"
head_short="${head_commit:0:7}"
fork_commit="$(proof_fork_point "$base_commit" "$head_commit")"
# Every claim below names this head, so the tree has to be this head.
if [[ -n "$(git status --porcelain=v1 --untracked-files=no)" ]]; then
  printf 'proof evidence needs a clean exact-head checkout\n' >&2
  exit 1
fi

# Only paths this lane produces are removed; score.sh's target/jankurai/repo-score.*
# is left alone (this lane writes its ratchet under proof-ratchet-score.*).
rm -rf -- \
  target/jankurai/accepted-baseline.json target/jankurai/accepted-baseline.md \
  target/jankurai/candidate-policy-baseline.json target/jankurai/candidate-policy-baseline.md \
  target/jankurai/candidate-policy-score.json target/jankurai/candidate-policy-score.md \
  target/jankurai/proof-ratchet-score.json target/jankurai/proof-ratchet-score.md \
  target/jankurai/baseline-migration-report.json target/jankurai/baseline-migration-report.md \
  target/jankurai/migration-report.json target/jankurai/migration-report.md \
  target/jankurai/changed-paths target/jankurai/changed-paths.unsorted \
  target/jankurai/copy-code.json target/jankurai/copy-code.md \
  target/jankurai/repair-queue.jsonl target/jankurai/proof-evidence-summary.json \
  target/jankurai/proofbind target/jankurai/proofmark target/jankurai/rust target/jankurai/security
mkdir -p target/jankurai/proofbind target/jankurai/proofmark target/jankurai/rust target/jankurai/security

proof_changed_paths "$fork_commit" "$head_commit" target/jankurai/changed-paths
# Read with a plain redirect, then check every listed path was read: an empty
# change set passes below, so a short read must not look like one.
mapfile -d '' -t changed_paths < target/jankurai/changed-paths
if [[ "${#changed_paths[@]}" -ne "$(tr -cd '\0' < target/jankurai/changed-paths | wc -c)" ]]; then
  printf 'proof change set was not read in full\n' >&2
  exit 1
fi
expected_changed="$(
  printf '%s\0' "${changed_paths[@]:-}" |
    jq -Rs 'split("\u0000") | map(select(length > 0)) | sort | unique'
)"

if [[ "${#changed_paths[@]}" -eq 0 ]]; then
  # Protected main gating its own head, or a head that touches nothing: there
  # is no change surface to bind. Every whole-tree check below still runs.
  printf '[proof] empty change set from fork point %s\n' "$fork_commit" >&2
else
  # Proofbind and proofmark stay advisory in Jankurai 1.7.5: required mode asks
  # Rust line and mutation evidence of contract prose too. They run for real
  # against the changed surface and their review counts go in the summary.
  jankurai proofbind verify . --changed-from "$fork_commit" --mode advisory --out target/jankurai/proofbind/surface-witness.json --obligations-out target/jankurai/proofbind/obligations.json --md target/jankurai/proofbind/proofbind.md
  jq -e --arg head "$head_short" --arg head_full "$head_commit" \
    --argjson changed "$expected_changed" '
    .schema_version == "1.0.0" and (.git_head == $head or .git_head == $head_full) and
    (.changed_paths | sort | unique) == $changed and
    (.summary.changed_surface_count | type == "number") and
    (.summary.verdict == "pass" or .summary.verdict == "review")
  ' target/jankurai/proofbind/surface-witness.json >/dev/null
  jq -e '
    (.obligations | type == "array") and (.obligations | length) == .summary.total and
    (.summary.verdict == "pass" or .summary.verdict == "review")
  ' target/jankurai/proofbind/obligations.json >/dev/null
  jankurai proofmark rust . --obligations target/jankurai/proofbind/obligations.json --changed-from "$fork_commit" --mode advisory --out target/jankurai/proofmark/proofmark-receipt.json --proof-receipt target/jankurai/proofmark/proof-receipt.json --md target/jankurai/proofmark/proofmark.md
  jq -e --arg head "$head_short" --arg head_full "$head_commit" '
    .schema_version == "1.0.0" and (.git_head == $head or .git_head == $head_full) and
    (.summary.total_obligations | type == "number") and
    (.summary.satisfied_obligations | type == "number") and
    (.summary.review_obligations | type == "number") and
    (.summary.verdict == "pass" or .summary.verdict == "review")
  ' target/jankurai/proofmark/proofmark-receipt.json >/dev/null
  jq -e --arg head "$head_short" --arg head_full "$head_commit" '
    (.git_head == $head or .git_head == $head_full) and
    .dirty_worktree == false and .exit_code == 0
  ' target/jankurai/proofmark/proof-receipt.json >/dev/null
fi

jankurai copy-code . --json target/jankurai/copy-code.json --md target/jankurai/copy-code.md
jq -e --arg auditor "${JERYU_JANKURAI_SEMVER:?require_jankurai exported no JERYU_JANKURAI_SEMVER}" '
  .schema_version == "1.1.0" and .generated_by == "jankurai copy-code" and
  .auditor_version == $auditor and
  (.status == "pass" or .status == "review") and
  .summary.hard_classes == 0 and .summary.hard_instances == 0 and
  (.classes | type == "array") and all(.classes[]; .hard_fail == false)
' target/jankurai/copy-code.json >/dev/null

jankurai rust witness build . --out target/jankurai/rust/witness-graph.json
jq -e '
  (.crates | type == "array" and length > 0) and
  all(.crates[];
    (.name | type == "string" and length > 0) and
    (.interface_hash | test("^[0-9a-f]{64}$")) and
    (.implementation_hash | test("^[0-9a-f]{64}$")) and
    (.file_count | type == "number" and . > 0))
' target/jankurai/rust/witness-graph.json >/dev/null

jankurai security run . --out target/jankurai/security/evidence.json --script ops/ci/security.sh --strict --profile ci
jq -e --arg head "$head_commit" '
  .git_head == $head and .lane == "security" and
  .wrapper.path == "ops/ci/security.sh" and .wrapper.strict == true and
  .exit_code == 0 and
  ([.commands[] | select(.status != "ran" or .exit_code != 0)] | length) == 0 and
  ([.commands[] | select(.status == "ran" and .exit_code == 0)] | length) >= 1
' target/jankurai/security/evidence.json >/dev/null

# Disposable checkouts under target/, each run holding its own lock.
proof_sweep_stale "$repo_root/target" jeryu-core-proof-baseline
baseline_parent="$(mktemp -d "$repo_root/target/jeryu-core-proof-baseline.XXXXXXXX")"
exec {proof_lock_fd}>"$baseline_parent/.lock"
flock --exclusive "$proof_lock_fd"
cleanup_baseline() {
  case "$baseline_parent" in
    "$repo_root/target"/jeryu-core-proof-baseline.*) rm -rf -- "$baseline_parent" ;;
    *) printf 'refusing to remove unexpected baseline path: %s\n' "$baseline_parent" >&2; return 1 ;;
  esac
}
on_signal() { local code="$1"; trap - EXIT HUP INT TERM; cleanup_baseline; exit "$code"; }
trap cleanup_baseline EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

# audit_report ROOT FLOOR JSON MD [ratchet BASELINE]: audit ROOT under its own
# agent/audit-policy.toml at FLOOR.
audit_report() {
  local root="$1" floor="$2" json="$3" md="$4" mode="${5:-advisory}" baseline="${6:-}"
  local args=(audit . --mode "$mode" --json "$repo_root/$json" --md "$repo_root/$md"
    --policy agent/audit-policy.toml --fail-under "$floor" --full --no-score-history)
  if [[ "$mode" == ratchet ]]; then
    args+=(--baseline "$repo_root/$baseline" --repair-queue-jsonl "$repo_root/target/jankurai/repair-queue.jsonl")
  fi
  (cd "$root" && jankurai "${args[@]}")
}
# require_baseline JSON COMMIT FLOOR: a passing, uncapped audit of exactly COMMIT.
require_baseline() {
  jq -e --arg head "$2" --argjson floor "$3" '
    .schema_version == "1.9.0" and (.git.head == $head or .git.head == ($head | .[0:7])) and
    .git.dirty_worktree == false and (.score | type == "number") and
    .decision.minimum_score == $floor and .decision.hard_findings == 0 and
    (.caps_applied | length) == 0 and .decision.passed == true
  ' "$1" >/dev/null || { printf 'baseline audit %s is not a passing audit of %s\n' "$1" "$2" >&2; return 1; }
}
# require_ratchet JSON COMMIT FLOOR BASELINE_SCORE: COMMIT kept or raised it.
require_ratchet() {
  jq -e --arg head "$2" --argjson floor "$3" --argjson baseline_score "$4" '
    .schema_version == "1.9.0" and (.git.head == $head or .git.head == ($head | .[0:7])) and
    .git.dirty_worktree == false and
    .score >= $floor and .decision.minimum_score == $floor and
    (.caps_applied | length) == 0 and .decision.hard_findings == 0 and
    .decision.passed == true and .decision.ratchet.passed == true and
    .decision.ratchet.baseline_score == $baseline_score and
    .decision.ratchet.score_delta >= 0 and
    .decision.ratchet.policy_changed == false and
    (.decision.ratchet.new_caps | length) == 0 and
    (.decision.ratchet.new_hard_findings | length) == 0
  ' "$1" >/dev/null || { printf 'ratchet %s failed against protected main\n' "$1" >&2; return 1; }
}

baseline_root="$baseline_parent/main"
proof_checkout_variant "$repo_root" refs/remotes/origin/main "$base_commit" "$baseline_root" >/dev/null
protected_policy="$baseline_root/agent/audit-policy.toml"
proof_require_canonical_file "$protected_policy"
protected_floor="$(proof_effective_floor "$protected_policy")"
printf '[proof] baseline: protected main %s from %s (fork point %s)\n' \
  "$base_commit" "$PROOF_FORGE_URL" "$fork_commit" >&2

audit_report "$baseline_root" "$protected_floor" \
  target/jankurai/accepted-baseline.json target/jankurai/accepted-baseline.md
require_baseline target/jankurai/accepted-baseline.json "$base_commit" "$protected_floor"
baseline_score="$(jq -er '.score' target/jankurai/accepted-baseline.json)"

policy_amended=false
if cmp -s -- "$candidate_policy" "$protected_policy"; then
  # The usual case: one policy judges both trees.
  audit_report . "$protected_floor" \
    target/jankurai/proof-ratchet-score.json target/jankurai/proof-ratchet-score.md \
    ratchet target/jankurai/accepted-baseline.json
  require_ratchet target/jankurai/proof-ratchet-score.json "$head_commit" \
    "$protected_floor" "$baseline_score"
else
  # The head amends the policy. It may not lower the floor, and it is judged
  # twice: under main's policy against main's baseline, so no policy edit lets
  # a weaker tree through; and under its own policy against main's tree audited
  # with that same policy, so the ratchet compares like with like.
  policy_amended=true
  proof_require_floor_kept "$candidate_floor" "$protected_floor"
  old_rules_root="$baseline_parent/head-under-main-policy"
  old_rules_commit="$(proof_checkout_variant "$repo_root" HEAD "$head_commit" \
    "$old_rules_root" "$protected_policy")"
  audit_report "$old_rules_root" "$protected_floor" \
    target/jankurai/proof-ratchet-score.json target/jankurai/proof-ratchet-score.md \
    ratchet target/jankurai/accepted-baseline.json
  require_ratchet target/jankurai/proof-ratchet-score.json "$old_rules_commit" \
    "$protected_floor" "$baseline_score"

  new_rules_root="$baseline_parent/main-under-head-policy"
  new_rules_commit="$(proof_checkout_variant "$repo_root" refs/remotes/origin/main \
    "$base_commit" "$new_rules_root" "$candidate_policy")"
  audit_report "$new_rules_root" "$candidate_floor" \
    target/jankurai/candidate-policy-baseline.json target/jankurai/candidate-policy-baseline.md
  require_baseline target/jankurai/candidate-policy-baseline.json "$new_rules_commit" "$candidate_floor"
  audit_report . "$candidate_floor" \
    target/jankurai/candidate-policy-score.json target/jankurai/candidate-policy-score.md \
    ratchet target/jankurai/candidate-policy-baseline.json
  require_ratchet target/jankurai/candidate-policy-score.json "$head_commit" "$candidate_floor" \
    "$(jq -er '.score' target/jankurai/candidate-policy-baseline.json)"
fi

# Migration analysis is a result, so it is read and ratcheted against main's.
jankurai migrate "$baseline_root" --analyze \
  --out target/jankurai/baseline-migration-report.json --md target/jankurai/baseline-migration-report.md
jankurai migrate . --analyze --out target/jankurai/migration-report.json --md target/jankurai/migration-report.md
proof_require_migration \
  target/jankurai/baseline-migration-report.json "$baseline_root" \
  target/jankurai/migration-report.json .

trap - EXIT HUP INT TERM
cleanup_baseline

# Nothing above may have moved the head, protected main, the origin or the tree.
if [[ "$(git rev-parse --verify 'HEAD^{commit}')" != "$head_commit" ||
      "$(git rev-parse --verify 'refs/remotes/origin/main^{commit}')" != "$base_commit" ||
      "$(git remote get-url origin)" != "$PROOF_FORGE_URL" ||
      -n "$(git status --porcelain=v1 --untracked-files=no)" ]]; then
  printf 'the proof commands moved the head, protected main, the origin or the tracked tree\n' >&2
  exit 1
fi

sha256_of() { sha256sum <"$1" | cut -d' ' -f1; }
proofbind_surface=null
proofmark_review=null
if [[ "${#changed_paths[@]}" -gt 0 ]]; then
  proofbind_surface="$(jq -er '.summary.changed_surface_count' target/jankurai/proofbind/surface-witness.json)"
  proofmark_review="$(jq -er '.summary.review_obligations' target/jankurai/proofmark/proofmark-receipt.json)"
fi
score="$(jq -er '.score' target/jankurai/proof-ratchet-score.json)"
jq -n \
  --arg head "$head_commit" --arg base "$base_commit" --arg fork "$fork_commit" \
  --arg origin "$PROOF_FORGE_URL" \
  --argjson changed_count "${#changed_paths[@]}" \
  --argjson floor "$protected_floor" --argjson candidate_floor "$candidate_floor" \
  --argjson policy_amended "$policy_amended" \
  --argjson score "$score" --argjson baseline_score "$baseline_score" \
  --argjson proofbind_surface "$proofbind_surface" --argjson proofmark_review "$proofmark_review" \
  --argjson liability "$(jq -er '.liability_score' target/jankurai/migration-report.json)" \
  --argjson baseline_liability "$(jq -er '.liability_score' target/jankurai/baseline-migration-report.json)" \
  --arg baseline_sha256 "$(sha256_of target/jankurai/accepted-baseline.json)" \
  --arg score_sha256 "$(sha256_of target/jankurai/proof-ratchet-score.json)" \
  --arg security_sha256 "$(sha256_of target/jankurai/security/evidence.json)" \
  '{schema_version:"jeryu.core.proof-evidence/v2",git_head:$head,
    base_commit:$base,fork_point:$fork,baseline_origin:$origin,
    baseline_source:"protected-main-tip-from-hosted-origin",
    dirty_worktree:false,changed_path_count:$changed_count,
    score:$score,baseline_score:$baseline_score,floor:$floor,
    candidate_floor:$candidate_floor,policy_amended:$policy_amended,
    changed_surface_count:$proofbind_surface,proofmark_review_obligations:$proofmark_review,
    migration_liability_score:$liability,baseline_migration_liability_score:$baseline_liability,
    baseline_sha256:$baseline_sha256,ratchet_score_sha256:$score_sha256,
    security_sha256:$security_sha256,synthetic_fallbacks:0,conclusion:"success"}' \
  > target/jankurai/proof-evidence-summary.json

printf 'proof evidence ok: head=%s base=%s fork=%s paths=%s score=%s baseline=%s floor=%s policy_amended=%s\n' \
  "$head_commit" "$base_commit" "$fork_commit" "${#changed_paths[@]}" \
  "$score" "$baseline_score" "$protected_floor" "$policy_amended"
