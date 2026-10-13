# Changelog

This file is written when a release is cut: its notes are generated from the commits since the previous release. Do not add entries by hand; write a commit subject that says what changed.

## Unreleased
- Owners reach for bots: `BotReach::Owners { owners }`, wire shape
  `{"mode":"owners","owners":["acme"]}`. It covers every repository whose
  owner is listed and on which the bot's owner holds an explicit grant,
  including repositories created after enrollment; a public read without a
  grant is not enough. Enrollment trims, lowercases and deduplicates the
  names, needs 1 to 20 distinct owners, and rejects an owner that is not an
  account, user, organization or repository owner on the forge
  (`invalid_reach_owners: ...`). A repository roster shows an owners bot as
  reaching that one repository, never the other owners it lists.
- Bot kind is a free-form label (migration 0021). `BotKind` is a validated
  string, `^[a-z][a-z0-9-]{0,31}$` (`invalid_bot_kind: ...`), with
  `BotKind::AGENT` (the default), `GROK` and `MUSE`. `label()` stays `Grokbot`
  and `Musebot` for those two and is the kind itself otherwise. Migration 0021
  rebuilds `bots` to drop the 0017 `grok`/`muse` CHECK and keeps every row and
  every key, refresh token, operation, activity row and agent token. Breaking
  for Rust callers: `BotKind::Grok`/`Muse` are now `BotKind::GROK`/`MUSE`, and
  `BotKind` is `Clone`, not `Copy`.
- Scoped agent tokens (migration 0020). An account issues a `jat_` token for
  one of its bots (`issue_bot_access_token`, default 90 days, at most 365, at
  most 10 live per bot) and presents it directly as a bearer.
  `authenticate_bot_access_token` resolves it to that bot's grant: the owner's
  non-admin rights cut down by the bot's reach, checked per request by
  `authorize_bot`. Suspending or revoking the bot, or an owner account event,
  ends its tokens; rotating the enrollment key does not. Only the token's
  SHA-256 is stored. `list_bot_access_tokens` and `revoke_bot_access_token`
  manage them.
- A repository's default branch now also decides the bare repository's `HEAD`.
  `ForgeCore::set_repository_default_branch` points `HEAD` at
  `refs/heads/<branch>` through `RepoBranches`, and setting the branch the forge
  already stores repairs a `HEAD` that disagrees instead of returning early.
  `ForgeCore::reconcile_repository_heads` is the repair pass over every
  repository: it fixes each `HEAD` whose default branch exists, leaves one whose
  default branch does not and reports it, and never creates a branch.
  `RepoManager` gained `head_branch`, `set_head_branch`, `reconcile_head`,
  `branch_exists` and `create_bare_with_head`, so a created repository starts
  with `HEAD` on its default branch; an import points `HEAD` at the source's
  default branch. A repository whose `HEAD` named a branch that was never
  pushed advertised no `HEAD` at all, so `git clone` called it empty — the same
  answer as a missing read grant.
- `ForgeCore::check_provider_binding` answers whether a binding may be used
  now from metadata alone: owner and provider, a user owner that may still
  authenticate, a registered service namespace, connected, at this
  generation. These are the checks every unseal and refresh make, and it
  opens nothing. A gateway that keeps access minted from a refresh secret
  calls it before each use, so a disabled account or a revoked namespace
  stops that access at once.
- One process writes a SQLite store. `ForgeCore::open_sqlite` takes an
  exclusive lock on `<store>.lock` for as long as any handle to the store
  lives; a second process is refused with `store_locked` (after waiting up to
  two seconds for a holder that is letting go) instead of undoing
  the first one's writes (each write replaces the snapshot) or refreshing a
  provider connection the first is refreshing. Opens within one process share
  the lock. Run a blue/green pair on separate data directories, or stop one
  before starting the other.
- A `service/<name>` owner of provider connections must be registered
  (`ForgeCore::register_service_namespace`); none is by default. An
  unregistered or revoked name (`revoke_service_namespace`) cannot connect,
  bind, unseal or refresh, and its connections stay stored until it is
  registered again. The set is shared by every handle on the forge, so a
  revocation takes effect at once.
- Only a `ProviderBroker` opens or rotates a stored provider secret. A vault
  issues it once (`ForgeCore::issue_provider_broker`), and the code that
  builds the gateway takes it at startup. `ForgeCore` keeps connect, list,
  bind and disconnect; `unseal_provider_secret` and `refresh_provider_secret`
  are now only reachable through the broker (connection-v1 §1: only the
  gateway unseals).
- A provider refresh can no longer leave a spent secret marked current
  (connection-v1 §3, migration 0022). The rotation is recorded durably before
  the provider is called. `refresh_provider_secret` takes a `TokenExchange`
  outcome from the caller: `Rotated { secret, access }`, `Unchanged`,
  `Revoked` or `Unknown`. It returns the access material only after the
  rotated secret is durable, comparing generation, `secret_version` and the
  marker in the same commit. A revoked or unknown answer, a rotated secret
  that cannot be stored, a commit that fails after the provider answered, and
  a rotation found unfinished when the store is opened all set the new
  `auth_required` state. That state drops the secret and refuses bindings and
  unseal with `provider_auth_required` until the owner connects again. An
  `Unchanged` answer keeps the stored secret current and returns
  `provider_refresh_failed`.
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
- Public waitlist signups (migration 0018): `ForgeCore::join_waitlist` stores a
  normalized email, an optional name, an optional note, status `listed`, source
  `landing`, and the first request time. A repeated email keeps that row and
  does not write again. The list stops at 50,000 addresses
  (`ForgeError::WaitlistFull`). Classifying that error for a bot repair
  returns a benign value and does not abort, and `explain_bot` leaves the
  error unchanged. `docs/errors.md#waitlist` has a Waitlist heading.
  `waitlist_len` reports the count without
  cloning the forge state. Joining does not create an account or a session.
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
