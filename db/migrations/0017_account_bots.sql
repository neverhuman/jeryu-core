-- Account-owned Grok and Muse bots. Reach narrows the owner's existing
-- repository rights; it never grants a repository the account cannot access.
-- Enrollment secrets are Argon2id PHC strings. Refresh tokens are SHA-256 of
-- 32 random bytes. Activity rows are secret-free.
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS bots (
  id TEXT PRIMARY KEY,
  owner TEXT NOT NULL REFERENCES user_accounts(login) ON DELETE CASCADE,
  slug TEXT NOT NULL CHECK (length(trim(slug)) > 0),
  display_name TEXT NOT NULL CHECK (length(trim(display_name)) > 0),
  kind TEXT NOT NULL CHECK (kind IN ('grok', 'muse')),
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

CREATE INDEX IF NOT EXISTS idx_bots_owner ON bots(owner);

CREATE TABLE IF NOT EXISTS bot_keys (
  key_id TEXT PRIMARY KEY,
  bot_id TEXT NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
  secret_hash TEXT NOT NULL CHECK (secret_hash LIKE '$argon2id$%'),
  env TEXT NOT NULL CHECK (env IN ('live', 'test')),
  created_at TEXT NOT NULL,
  retired_at TEXT,
  revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_bot_keys_bot ON bot_keys(bot_id);

CREATE TABLE IF NOT EXISTS bot_refresh_tokens (
  token_hash TEXT PRIMARY KEY CHECK (length(token_hash) = 64),
  bot_id TEXT NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
  key_id TEXT NOT NULL,
  generation INTEGER NOT NULL CHECK (generation >= 1),
  expires_at TEXT NOT NULL,
  used_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_bot_refresh_bot ON bot_refresh_tokens(bot_id);

CREATE TABLE IF NOT EXISTS bot_operations (
  bot_id TEXT NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
  operation TEXT NOT NULL CHECK (length(trim(operation)) > 0),
  request_key TEXT NOT NULL CHECK (length(trim(request_key)) > 0),
  body_digest TEXT NOT NULL CHECK (length(body_digest) = 64),
  result_json TEXT CHECK (result_json IS NULL OR json_valid(result_json)),
  created_at TEXT NOT NULL,
  PRIMARY KEY (bot_id, operation, request_key)
);

CREATE TABLE IF NOT EXISTS bot_activity (
  id TEXT PRIMARY KEY,
  bot_id TEXT NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
  key_id TEXT NOT NULL,
  repo TEXT,
  session_id TEXT,
  action TEXT NOT NULL CHECK (length(trim(action)) > 0),
  outcome TEXT NOT NULL,
  scope TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_bot_activity_bot ON bot_activity(bot_id, created_at);
CREATE INDEX IF NOT EXISTS idx_bot_activity_repo ON bot_activity(repo, created_at);
