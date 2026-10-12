-- Bot kind becomes a free-form label. 0017 limited `bots.kind` to 'grok' and
-- 'muse'; the kind grants nothing, so any value matching
-- ^[a-z][a-z0-9-]{0,31}$ is now allowed ('agent' is the enroll default).
-- SQLite cannot drop a CHECK in place, so the table is rebuilt: create the new
-- shape, copy every row unchanged, drop the old table, rename, recreate the
-- index. Existing 'grok' and 'muse' rows keep their values.
--
-- The child tables bot_keys, bot_refresh_tokens, bot_operations, bot_activity
-- and bot_access_tokens reference bots(id) ON DELETE CASCADE by name. The
-- caller (apply_migration_0021) runs this script with PRAGMA foreign_keys OFF
-- inside one transaction, so DROP TABLE bots does not cascade into them, and
-- checks PRAGMA foreign_key_check before commit. Their references resolve to
-- the renamed table afterwards. It runs only while the 0017 CHECK is present.
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'

CREATE TABLE bots_0021 (
  id TEXT PRIMARY KEY,
  owner TEXT NOT NULL REFERENCES user_accounts(login) ON DELETE CASCADE,
  slug TEXT NOT NULL CHECK (length(trim(slug)) > 0),
  display_name TEXT NOT NULL CHECK (length(trim(display_name)) > 0),
  kind TEXT NOT NULL CHECK (
    length(kind) BETWEEN 1 AND 32
    AND kind GLOB '[a-z]*'
    AND kind NOT GLOB '*[^a-z0-9-]*'
  ),
  status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
  reach_json TEXT NOT NULL CHECK (json_valid(reach_json)),
  auth_epoch INTEGER NOT NULL CHECK (auth_epoch >= 0),
  credential_generation INTEGER NOT NULL CHECK (credential_generation >= 1),
  last_successful_access TEXT,
  last_auth TEXT,
  last_mutation TEXT,
  last_heartbeat TEXT,
  last_action TEXT,
  last_outcome TEXT,
  last_repo TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (owner, slug)
);

INSERT INTO bots_0021 (
  id, owner, slug, display_name, kind, status, reach_json, auth_epoch,
  credential_generation, last_successful_access, last_auth, last_mutation,
  last_heartbeat, last_action, last_outcome, last_repo, created_at, updated_at
)
SELECT
  id, owner, slug, display_name, kind, status, reach_json, auth_epoch,
  credential_generation, last_successful_access, last_auth, last_mutation,
  last_heartbeat, last_action, last_outcome, last_repo, created_at, updated_at
FROM bots;

DROP TABLE bots;

ALTER TABLE bots_0021 RENAME TO bots;

CREATE INDEX IF NOT EXISTS idx_bots_owner ON bots(owner);
