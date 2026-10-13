-- Team bots (records 0008, 0009). A bot is owned by a person, as before, or by
-- an organization. A team bot holds its own repository grants, is stewarded by
-- one team of its organization, and acts as `<organization>.<slug>[bot]`.
--
-- `bots` is rebuilt because SQLite cannot drop a foreign key in place: `owner`
-- referenced `user_accounts(login)`, and an organization is not an account.
-- `owner_kind` says which it names; Core keeps the two namespaces apart (an
-- account cannot take an organization's login, nor an organization an
-- account's). Accounts and organizations are never deleted, so no cascade is
-- lost in practice; a bot whose person or organization is missing never
-- authenticates. `steward_team` is set exactly for an organization's bot.
-- Every existing row is copied as a person's bot with no steward team.
--
-- The child tables bot_keys, bot_refresh_tokens, bot_operations, bot_activity
-- and bot_access_tokens reference bots(id) ON DELETE CASCADE by name. The
-- caller (apply_migration_0023) runs this script with PRAGMA foreign_keys OFF
-- inside one transaction, so DROP TABLE bots does not cascade into them, and
-- refuses to commit if their foreign_key_check grows. It runs only while
-- `bots` has no `owner_kind` column.
--
-- bot_repo_grants is new and starts empty. bot_access_tokens gains issued_by,
-- NULL on every token issued before this migration.
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'

CREATE TABLE bots_0023 (
  id TEXT PRIMARY KEY,
  owner TEXT NOT NULL CHECK (length(trim(owner)) > 0),
  owner_kind TEXT NOT NULL DEFAULT 'user' CHECK (owner_kind IN ('user', 'organization')),
  steward_team TEXT CHECK (steward_team IS NULL OR length(trim(steward_team)) > 0),
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
  CHECK ((owner_kind = 'organization') = (steward_team IS NOT NULL)),
  UNIQUE (owner, slug)
);

INSERT INTO bots_0023 (
  id, owner, owner_kind, steward_team, slug, display_name, kind, status,
  reach_json, auth_epoch, credential_generation, last_successful_access,
  last_auth, last_mutation, last_heartbeat, last_action, last_outcome,
  last_repo, created_at, updated_at
)
SELECT
  id, owner, 'user', NULL, slug, display_name, kind, status,
  reach_json, auth_epoch, credential_generation, last_successful_access,
  last_auth, last_mutation, last_heartbeat, last_action, last_outcome,
  last_repo, created_at, updated_at
FROM bots;

DROP TABLE bots;

ALTER TABLE bots_0023 RENAME TO bots;

CREATE INDEX IF NOT EXISTS idx_bots_owner ON bots(owner);

CREATE TABLE IF NOT EXISTS bot_repo_grants (
  bot_id TEXT NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
  repo_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
  access TEXT NOT NULL CHECK (access IN ('read', 'write')),
  granted_by TEXT NOT NULL CHECK (length(trim(granted_by)) > 0),
  granted_at TEXT NOT NULL,
  PRIMARY KEY (bot_id, repo_id)
);

CREATE INDEX IF NOT EXISTS idx_bot_repo_grants_repo ON bot_repo_grants(repo_id);

ALTER TABLE bot_access_tokens ADD COLUMN issued_by TEXT
  CHECK (issued_by IS NULL OR length(trim(issued_by)) > 0);
