#!/usr/bin/env bash
# Where the ratchet baseline of this repository comes from: the forge's copy of
# protected main, audited in this run, never a report committed in the tree
# under test. A pull request can edit any file it likes; it cannot edit what the
# forge serves for `main`, so the baseline a head is judged against stays out of
# that head's reach.
#
# Sourced by ops/ci/proof_evidence.sh. Each guard below is also called directly
# by crates/jeryu-core/tests/proof_evidence_lane.rs with a git stub on PATH, so
# the refusals are exercised without a network, a forge or an auditor.

# The fetch URL of `origin`, and only when it is a real remote URL. `origin` is
# the checkout's own configuration, which a pull request does not write; a
# filesystem path (a sibling checkout, a bundle, a worktree) could be anything,
# so it is refused rather than trusted as the forge.
proof_baseline_remote_url() {
  local url
  url="$(git remote get-url origin 2>/dev/null || true)"
  case "$url" in
    https://*|http://*|git://*|ssh://*)
      printf '%s\n' "$url"
      ;;
    *@*:*)
      printf '%s\n' "$url"
      ;;
    '')
      printf 'proof evidence has no origin remote to take the baseline from\n' >&2
      return 1
      ;;
    *)
      printf 'proof evidence refuses a baseline from a local origin: %s\n' "$url" >&2
      return 1
      ;;
  esac
}

# Clone protected main from the forge into DIR and print the commit it serves.
# --no-local/--no-hardlinks so no object is shared with anything on this host,
# and depth 1 because an audit reads the tree, not the history.
proof_baseline_clone() {
  local url="$1" dir="$2" commit
  if ! git clone --quiet --no-local --no-hardlinks --single-branch \
      --branch main --depth 1 -- "$url" "$dir"; then
    printf 'cannot clone protected main from %s\n' "$url" >&2
    return 1
  fi
  commit="$(git -C "$dir" rev-parse --verify 'HEAD^{commit}' 2>/dev/null || true)"
  if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
    printf 'protected main served no commit id: %s\n' "${commit:-none}" >&2
    return 1
  fi
  if [[ -n "$(git -C "$dir" status --porcelain=v1 --untracked-files=all)" ]]; then
    printf 'the protected-main clone is not clean\n' >&2
    return 1
  fi
  printf '%s\n' "$commit"
}

# The head under test must descend from the main its baseline was taken from.
# Saying so needs that commit, and a depth-1 CI checkout has neither it nor any
# shared history: deepen first and refuse if it is still absent, rather than
# asking git a question this checkout cannot answer.
proof_baseline_require_descendant() {
  local commit="$1" head="$2"
  if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
    printf 'protected-main baseline is not a commit id: %s\n' "$commit" >&2
    return 1
  fi
  if [[ "$(git rev-parse --is-shallow-repository 2>/dev/null || echo true)" == true ]]; then
    if ! git fetch --quiet --no-tags --unshallow origin main; then
      printf 'cannot deepen this checkout to compare it with protected main\n' >&2
      return 1
    fi
  elif ! git cat-file -e "${commit}^{commit}" 2>/dev/null; then
    if ! git fetch --quiet --no-tags origin main; then
      printf 'cannot fetch protected main to compare this head with it\n' >&2
      return 1
    fi
  fi
  if ! git cat-file -e "${commit}^{commit}" 2>/dev/null; then
    printf 'protected-main commit %s is not in this checkout after fetching it\n' \
      "$commit" >&2
    return 1
  fi
  if ! git merge-base --is-ancestor "$commit" "$head"; then
    printf 'the head under test does not descend from protected main %s: rebase and rerun\n' \
      "$commit" >&2
    return 1
  fi
}

# A ratchet compares two scores, so one policy has to produce both, and the
# auditor takes its policy from the tree it audits. The candidate's policy must
# therefore be protected main's, byte for byte: a head may not edit the rules
# that judge it. A policy change lands on its own and is read there.
proof_baseline_require_policy_identity() {
  local candidate="$1" protected="$2" file
  for file in "$candidate" "$protected"; do
    if [[ ! -f "$file" || -L "$file" ]]; then
      printf 'audit policy must be a regular file: %s\n' "$file" >&2
      return 1
    fi
  done
  if [[ "$(sha256sum <"$candidate")" != "$(sha256sum <"$protected")" ]]; then
    printf '%s differs from protected main: the ratchet refuses a head that edits the policy judging it\n' \
      "$candidate" >&2
    return 1
  fi
}

# The baseline clone lives under this repository's own output directory, which
# nothing else empties, so a run killed before its cleanup trap fires leaves a
# copy of main behind and every later run leaves another. Sweep those before
# taking a new one, and only the ones no longer in use: a directory touched in
# the last two hours may belong to a run still going, so it is left alone.
# Failing to sweep fails the lane rather than letting the pile grow unseen.
proof_baseline_sweep_stale() {
  local dir="$1" prefix="$2"
  [[ -d "$dir" ]] || return 0
  if ! find "$dir" -maxdepth 1 -type d -name "${prefix}.*" -mmin +120 \
      -prune -exec rm -rf -- '{}' +; then
    printf 'cannot sweep stale baseline clones under %s\n' "$dir" >&2
    return 1
  fi
}
