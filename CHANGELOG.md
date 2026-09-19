# Changelog

## Unreleased
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
  (/home/ubuntu/jeryu) is deprecated and its drift fully reconciled.

## jeryu-core-v4.0.0-split.0

- Initial split-family baseline for `jeryu-core`.
