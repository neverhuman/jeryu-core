#!/usr/bin/env bash
# Guards for the proof-evidence lane (ops/ci/proof_evidence.sh): where its
# ratchet baseline comes from, what change set it judges, and how a head that
# amends the audit policy is judged. Sourced by the lane; each function is also
# called directly by crates/jeryu-core/tests/proof_evidence_lane.rs against
# throwaway git repositories, so the refusals run without a forge or an auditor.
#
# The rule (the same one jeryu-ci-runner and jeryu-jira follow):
# - the baseline is protected main's tip as the forge serves it at gate time,
#   fetched from the one hosted source repository and audited in this run;
# - the change set starts at the head's fork point from that tip, so a head
#   behind the tip is judged, not refused, and main's own head (or nothing
#   touched) is an empty change set, which passes;
# - the head's whole tree is still ratcheted against the tip's, so a stale head
#   that scores below the tip, adds a cap or hard finding, or raises migration
#   liability fails.
# A result therefore depends on main's tip when the gate ran: the same head can
# go red after main moves past a score it does not reach.

# The hosted source repository. Nothing else may serve the baseline.
readonly PROOF_FORGE_URL='https://git.neverhuman.org/git/jeryu/jeryu-core.git'

# Refuse any origin but the hosted source repository, before anything is
# fetched from it. Plaintext transports, mirrors, look-alike hosts and local
# paths all fail here.
proof_require_origin() {
  local url
  url="$(git remote get-url origin)" || {
    printf 'proof evidence has no origin remote\n' >&2
    return 1
  }
  if [[ "$url" != "$PROOF_FORGE_URL" ]]; then
    printf 'proof origin is not the hosted source repository: %s\n' "$url" >&2
    return 1
  fi
}

# Give this checkout the history the fork-point question needs, then refresh
# protected main from origin. A depth-1 checkout has a grafted head; a fetch
# naming only main can leave that graft, after which every ancestry question
# about the head answers "no". `--unshallow` with the remote's whole refspec
# deepens every ref the forge serves; a checkout still shallow afterwards is
# refused rather than asked a question it cannot answer.
proof_require_history() {
  local shallow
  shallow="$(git rev-parse --is-shallow-repository)" || return 1
  case "$shallow" in
    true)
      git -c http.followRedirects=false fetch --quiet --no-tags --unshallow origin || return 1
      if [[ "$(git rev-parse --is-shallow-repository)" != false ]]; then
        printf 'proof checkout is still shallow after fetching every ref the forge serves\n' >&2
        return 1
      fi
      ;;
    false) ;;
    *) printf 'cannot determine proof checkout history\n' >&2; return 1 ;;
  esac
  git -c http.followRedirects=false fetch --quiet --no-tags origin \
    '+refs/heads/main:refs/remotes/origin/main'
}

# Print the fork point of HEAD_COMMIT from protected main's tip BASE_COMMIT.
# Only a head with no shared history fails.
proof_fork_point() {
  local base="$1" head="$2" fork
  fork="$(git merge-base "$base" "$head")" && [[ "$fork" =~ ^[0-9a-f]{40}$ ]] || {
    printf 'proof head shares no history with protected base: base=%s head=%s\n' \
      "$base" "$head" >&2
    return 1
  }
  printf '%s\n' "$fork"
}

# Write the NUL-separated paths HEAD_COMMIT adds, copies, modifies, renames or
# retypes since FORK_COMMIT to OUT, sorted. The diff goes to a file first, so a
# failing git diff fails the caller instead of leaving an empty change set
# behind a process substitution. An empty OUT is a change set of nothing.
proof_changed_paths() {
  local fork="$1" head="$2" out="$3"
  git diff --no-ext-diff --name-only -z --diff-filter=ACMRT \
    "${fork}...${head}" >"$out.unsorted" || return 1
  LC_ALL=C sort -zu "$out.unsorted" >"$out" || return 1
  rm -f -- "$out.unsorted"
}

# FILE must be a canonical one-link regular file: not a symlink, not a hard
# link to something else, not reached through a symlinked directory.
proof_require_canonical_file() {
  local file="$1"
  if [[ ! -f "$file" || -L "$file" ||
        "$(stat -c '%h' -- "$file")" != 1 ||
        "$(realpath -- "$file")" != "$file" ]]; then
    printf 'must be a canonical one-link regular file: %s\n' "$file" >&2
    return 1
  fi
}

# Print the score floor POLICY asks for: its one integer `minimum_score`. No
# constant here stands in for it, and a missing, repeated or fractional value
# fails rather than falling back to some other number. The forge applies its
# own host floor in its own jankurai/proof check.
proof_effective_floor() {
  local policy="$1"
  awk -F '=' '
    /^[[:space:]]*minimum_score[[:space:]]*=/ {
      count += 1
      value = $2
      sub(/[[:space:]]*#.*/, "", value)
      gsub(/[[:space:]]/, "", value)
      if (value !~ /^[0-9]+$/) exit 2
      floor = value
    }
    END {
      if (count != 1) exit 3
      print floor
    }
  ' "$policy" || {
    printf 'audit policy must contain one integer minimum_score: %s\n' "$policy" >&2
    return 1
  }
}

# Check out COMMIT of the repository at SOURCE into the new directory DEST, and
# print the commit DEST is at. With POLICY given, commit that file over
# DEST/agent/audit-policy.toml first (the auditor reads only the audited tree's
# own policy) and print that one-file commit instead. The fetch uses the file://
# transport, so no object is shared with SOURCE, and names REF there; the fetched
# commit must be COMMIT.
proof_checkout_variant() {
  local source="$1" ref="$2" commit="$3" dest="$4" policy="${5:-}" fetched variant
  git init --quiet "$dest" || return 1
  git -C "$dest" fetch --quiet --no-tags --no-write-fetch-head \
    "file://$source" "+${ref}:refs/heads/proof-source" || {
    printf 'cannot fetch %s for the proof baseline\n' "$ref" >&2
    return 1
  }
  fetched="$(git -C "$dest" rev-parse --verify 'refs/heads/proof-source^{commit}')" || return 1
  if [[ "$fetched" != "$commit" ]]; then
    printf '%s moved during the proof lane: expected %s, fetched %s\n' \
      "$ref" "$commit" "$fetched" >&2
    return 1
  fi
  git -C "$dest" -c advice.detachedHead=false checkout --quiet --detach "$commit" || return 1
  if [[ -n "$policy" ]]; then
    cp -- "$policy" "$dest/agent/audit-policy.toml" || return 1
    git -C "$dest" -c user.name=proof-evidence -c user.email=proof-evidence@invalid \
      -c commit.gpgsign=false commit --quiet \
      -m 'proof evidence: judge this tree under the other audit policy' \
      -- agent/audit-policy.toml || return 1
    variant="$(git -C "$dest" rev-parse --verify 'HEAD^{commit}')" || return 1
    if [[ "$(git -C "$dest" rev-parse --verify 'HEAD^1^{commit}')" != "$commit" ||
          "$(git -C "$dest" diff --name-only "$commit" "$variant")" != agent/audit-policy.toml ]]; then
      printf 'proof policy variant of %s changed more than the audit policy\n' "$commit" >&2
      return 1
    fi
  fi
  if [[ -n "$(git -C "$dest" status --porcelain=v1 --untracked-files=all)" ]]; then
    printf 'proof checkout of %s is not clean\n' "$commit" >&2
    return 1
  fi
  git -C "$dest" rev-parse --verify 'HEAD^{commit}'
}

# A head may amend the audit policy, but only upward: its own floor may not be
# below protected main's. The lane also judges the head under main's policy, so
# every other loosening fails there.
proof_require_floor_kept() {
  local candidate_floor="$1" protected_floor="$2"
  if (( candidate_floor < protected_floor )); then
    printf 'the head lowers the audit floor from %s to %s\n' \
      "$protected_floor" "$candidate_floor" >&2
    return 1
  fi
}

# Ratchet this head's migration analysis against protected main's. Both reports
# must be complete analyses of the tree they name (source_root). The head may not
# raise liability, and may drop one of main's required proof lanes only when its
# liability is strictly lower.
proof_require_migration() {
  local baseline="$1" baseline_root="$2" candidate="$3" candidate_root="$4"
  local shape liability lanes
  shape='.schema_version == "1.0.0" and .command == "jankurai migrate" and
    .status == "complete" and .source_root == $root and
    (.liability_score | type == "number" and . >= 0) and
    (.required_proof_lanes | type == "array" and all(.[]; type == "string"))'
  jq -e --arg root "$baseline_root" "$shape" "$baseline" >/dev/null || {
    printf 'protected-main migration analysis is incomplete or not of %s\n' "$baseline_root" >&2
    return 1
  }
  jq -e --arg root "$candidate_root" "$shape" "$candidate" >/dev/null || {
    printf 'this head'"'"'s migration analysis is incomplete or not of %s\n' "$candidate_root" >&2
    return 1
  }
  liability="$(jq -er '.liability_score' "$baseline")" || return 1
  lanes="$(jq -c '.required_proof_lanes' "$baseline")" || return 1
  jq -e --argjson baseline "$liability" --argjson lanes "$lanes" '
    .liability_score <= $baseline and
    (.liability_score < $baseline or (($lanes - .required_proof_lanes) | length) == 0)
  ' "$candidate" >/dev/null || {
    printf 'migration liability regressed against protected main (liability %s, lanes %s)\n' \
      "$liability" "$lanes" >&2
    return 1
  }
}

# Baseline checkouts live under this repository's own target/, which nothing
# else empties, so a run killed before its cleanup trap leaves one behind.
# Each run holds an exclusive flock on DIR/<prefix>.*/.lock for its whole life;
# a directory whose lock can be taken belongs to no live run and is removed.
# One without a lock file (a run killed between mktemp and taking the lock, or
# an older layout) is removed only after two hours. A sweep that cannot remove a
# stale directory fails the lane rather than letting the pile grow unseen.
proof_sweep_stale() {
  local dir="$1" prefix="$2" entry
  if [[ ! -d "$dir" ]]; then
    return 0 # a fresh checkout has no target/ to sweep yet
  fi
  for entry in "$dir/$prefix".*; do
    [[ -d "$entry" && ! -L "$entry" ]] || continue
    if [[ -f "$entry/.lock" ]]; then
      flock --exclusive --nonblock "$entry/.lock" true 2>/dev/null || continue
    elif [[ -z "$(find "$entry" -maxdepth 0 -mmin +120)" ]]; then
      continue
    fi
    rm -rf -- "$entry" || {
      printf 'cannot sweep stale baseline checkout %s\n' "$entry" >&2
      return 1
    }
  done
}

# The candidate declaration must name the receipt-verified governed binary.
# Baseline policy variants may still be audited under main's older policy;
# this check applies to the candidate at the required-gate entry point.
proof_require_governed_declaration() {
  local policy="$1" governed="$2" declared
  declared="$(awk -F '"' '
    /^[[:space:]]*required_tool_version[[:space:]]*=/ {
      count += 1
      if ($0 !~ /^[[:space:]]*required_tool_version[[:space:]]*=[[:space:]]*"[0-9]+\.[0-9]+\.[0-9]+"[[:space:]]*(#.*)?$/) invalid = 1
      version = $2
    }
    END { if (count != 1 || invalid) exit 1; print version }
  ' "$policy")" || {
    printf 'audit policy needs one valid required_tool_version declaration\n' >&2
    return 1
  }
  if [[ ! "$governed" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ || "$declared" != "$governed" ]]; then
    printf 'audit policy version %s differs from verified governed auditor %s\n' "$declared" "$governed" >&2
    return 1
  fi
}
