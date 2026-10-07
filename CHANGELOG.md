# Changelog

## Unreleased
- A repository's bot roster lists a general-reach Grokbot or Musebot only when
  its owner has an explicit grant on that repository; a public read no longer
  puts every general bot on every public roster. Roster rows drop the last
  action, outcome, repository, and mutation time unless they concern the
  viewed repository, so a roster never names a repository the viewer cannot
  read.
- A Grokbot or Musebot failure names its repair: purpose, reason, common
  fixes, and a repair hint. The returned error carries that text, and the
  machine code stays the prefix callers already match. The failures are a
  rejected enrollment, an invalid credential, a slug or idempotency conflict,
  a reach denial, a missing or revoked credential, and a randomness or Argon2id
  failure. The repair never includes the enrollment key or refresh token.
  `docs/errors.md` has a heading for each bot repair anchor.
- Account Grokbot and Musebot credentials record lifecycle audit rows for
  enroll, key rotation, suspend, revoke, enrollment-key exchange, refresh
  reuse, and authorization denial. Each row names the actor, bot id, and key
  id, and never the enrollment key or refresh token. Activity keeps the newest
  500 events for each bot. The same outcome is stored at most once a minute
  unless the outcome changes; a heartbeat is stored at most once a minute.
- Branch protection carries its own `strict` (head up to date with base) flag,
  separate from `required_linear_history`, and `SetBranchProtectionRequest`
  requires `required_status_checks`, `required_approving_review_count` and
  `enforce_admins`: a PUT body that omits one is rejected (422 at the edge)
  instead of silently switching those protections off.
- `ForgeCore::set_repository_default_branch` changes a repository's default
  branch after checking it exists (via `RepoBranches`); the new default branch
  gets the usual automatic protection.
- Per-repository `default_branch_protection_opt_out` (migration 0014): a global
  admin can exempt a todo queue repository's default branch from automatic
  PR-only protection. Off by default, audited, refused while any required
  status context is configured.
- Track `Repository.pushed_at` (migration 0013): jeryu-gitd records pushes that
  moved a ref and reports them through `PushObserver`; existing repositories
  backfill once from git history. `RepositorySummary.pushed_at` (RFC 3339).
- Bind pull-request reviews and merge authority to the exact PR head, including
  authenticated head/base tree identities in the read contract.
- Repair release identity forward at `jeryu-core-v5.0.0-split.5`; earlier
  immutable v5 tags retain their historical committed `VERSION` bytes.
- v5.0.0 split baseline live on the local forge; merge-to-GitHub mirror verified.

## jeryu-core-v5.0.0-split.0 - 2026-06-11
- MAJOR: first standalone split-family release; the legacy monorepo
  is deprecated and its drift fully reconciled.

## jeryu-core-v4.0.0-split.0

- Initial split-family baseline for `jeryu-core`.
