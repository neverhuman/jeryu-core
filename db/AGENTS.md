# DB Agent Instructions

Owns the durable SQLite schema, migrations, constraints, and migration-analysis
evidence for Jeryu's forge truth.

Allowed edits:
- Add forward-only SQL migrations under `db/migrations/`.
- Update `db/constraints.md` when a migration changes invariants.
- Add rollback/backfill notes with every migration that changes stored shape.

Forbidden edits:
- Do not put application logic, HTTP routing, or web data access in `db/`.
- Do not bypass `jeryu-core`; product code must go through typed forge APIs.
- Do not add destructive migrations without a staged rollback and lock plan.

Proof lane:
- `jankurai migrate . --analyze --out target/jankurai/migration-report.json`
- `cargo test -p jeryu-core --jobs 40 sqlite_open_backfills_pull_request_source_repository`

Migration 0004 notes:
- `pull_requests.source_repository` is provenance metadata only; it must not
  weaken branch-protection review, status, signed-commit, or admin enforcement.
- Keep a `VACUUM INTO` copy before applying the migration to a populated store.
- The open path should guard `PRAGMA table_info(pull_requests)` so repeated
  opens and backfills stay idempotent.

Migration 0005-0007 notes:
- `repositories.family` (0005) is UI grouping data; its seed backfill runs only
  when the column is first added and must never overwrite operator edits.
- `forge_audit_log` (0006) deliberately has NO repository FK and is excluded
  from the State-owned table list in `storage::snapshot`, so delete receipts
  survive both repository deletion and every snapshot save.
- `jankurai_scores` (0007) allows NULL `score` (decision `tool-failed` records
  an unscoreable audit); any new per-repo table MUST be threaded through
  `State`, `load_state`, `stage_state`, and `storage::snapshot::OWNED_TABLES`,
  or it is never saved.

Live-readiness note:
- When migrations or constraints change, include this guidance file in the
  changed-fast audit so Jankurai can detect the local DB owner and proof lane.

Migration 0017 account bot notes:
- `bots` and its child tables are State-owned. Thread them through `State`,
  `load_state`, `stage_state`, and `storage::snapshot::OWNED_TABLES`.
- Reach checks use the account's explicit repository grants. Forge admin is
  not a grant. A public repository still allows a read.
- `bots.auth_epoch` must match the account epoch. Password change, disable,
  and lock revoke bot keys and drop refresh tokens. Self-service recovery
  (`recover_password`, which spends a secret core issued with
  `issue_password_recovery`, migration 0025) revokes the same way: it bumps
  the epoch, ends browser sessions, deletes PATs and revokes the account's own
  bot keys, refresh tokens and agent tokens (`docs/adr/0001`). Each recovery
  writes `forge_audit_log` entries.
- `password_recovery_tokens` stores only the SHA-256 of a recovery secret.
  Verify it under the forge write lock before hashing the new password, and
  verify it again under the lock before spending it. Do not add a plaintext
  column. Dead rows are pruned on issue, spend and open.
- Core answers every recovery refusal the same way and does the same durable
  work for an unknown or inactive login. It does not rate limit. The edge must
  answer forgot-password without waiting for the issue, and rate limit both
  endpoints.
- Enrollment key material is an Argon2id hash. Do not add a plaintext column.
  Verify the hash before taking the forge write lock.
- Activity rows stay secret-free. Heartbeats update `bots.last_heartbeat` and
  do not insert an activity row.

Migration 0016 review dismissal notes:
- Preserve every nullable historical target; never infer a verdict UUID.
- Persist and reload new dismissal targets through every snapshot save.
- Keep incompatible older writers stopped: their rewrite loses target bindings.
- Exercise migration_0016_preserves_unbound_dismissals and
  review_dismissal_survives_sqlite_reopen_and_unrelated_write with two Cargo jobs
  in the allocated CI window, then run the migration analysis lane above.

Migration 0018 waitlist notes:
- `waitlist_signups` is an email list, not an account. `join_waitlist` must not
  create a user or a session. A repeat keeps the original name, note, status,
  and created time.
- Number 0017 is the account-bot migration, now on main. Do not reuse it.
  0018 follows it and does not depend on the bot tables.
- Persist and reload rows through every snapshot save.
- Exercise waitlist_join_normalizes_and_keeps_the_first_signup and
  waitlist_survives_sqlite_reopen_and_unrelated_write.

Migration 0021 bot kind notes:
- `bots` is rebuilt once to drop the 0017 kind `CHECK`. Never edit 0017 or
  0020; 0017 still runs first on a fresh database and 0021 rebuilds it.
- The rebuild runs with foreign keys off in one transaction (a `DROP TABLE` with
  them on cascades into every bot child table) and checks the child tables'
  `foreign_key_check` before commit.
- Exercise migration_0021_rebuilds_bots_and_keeps_children,
  migration_0021_is_idempotent_on_the_new_shape and
  free_form_kind_survives_sqlite_reopen.
