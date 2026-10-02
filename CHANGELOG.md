# Changelog

## Unreleased
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
