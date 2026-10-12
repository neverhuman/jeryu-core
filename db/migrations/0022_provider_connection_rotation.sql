-- connection-v1 §3: a refresh records its rotation before the provider sees
-- the stored secret, and a rotation that never finished leaves the
-- connection auth_required (the provider may have consumed the secret).
-- rotation_secret_version / rotation_started_at hold that marker; the new
-- auth_required state holds no secret. SQLite cannot change a CHECK
-- constraint in place, so the table is rebuilt with the same rows, inside
-- the transaction the migration runner opens.
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'

CREATE TABLE provider_connections_0022 (
  id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
  owner_id TEXT NOT NULL CHECK (owner_id LIKE 'user/_%' OR owner_id LIKE 'service/_%'),
  provider TEXT NOT NULL CHECK (provider IN ('claude', 'codex', 'grok')),
  provider_account TEXT NOT NULL CHECK (length(trim(provider_account)) > 0),
  credential_kind TEXT NOT NULL CHECK (credential_kind IN ('oauth_refresh', 'api_key')),
  state TEXT NOT NULL CHECK (state IN ('pending', 'connected', 'auth_required', 'disconnected')),
  connection_generation INTEGER NOT NULL CHECK (connection_generation >= 1),
  secret_version INTEGER NOT NULL CHECK (secret_version >= 0),
  sealed_secret TEXT CHECK (sealed_secret IS NULL OR json_valid(sealed_secret)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  refreshed_at TEXT,
  rotation_secret_version INTEGER
    CHECK (rotation_secret_version IS NULL OR rotation_secret_version >= 0),
  rotation_started_at TEXT,
  CHECK ((state = 'connected') = (sealed_secret IS NOT NULL)),
  CHECK ((rotation_secret_version IS NULL) = (rotation_started_at IS NULL)),
  CHECK (rotation_secret_version IS NULL OR state = 'connected'),
  UNIQUE (owner_id, provider, provider_account)
);

INSERT INTO provider_connections_0022 (
  id, owner_id, provider, provider_account, credential_kind, state,
  connection_generation, secret_version, sealed_secret, created_at, updated_at,
  refreshed_at
)
SELECT
  id, owner_id, provider, provider_account, credential_kind, state,
  connection_generation, secret_version, sealed_secret, created_at, updated_at,
  refreshed_at
FROM provider_connections;

DROP TABLE provider_connections;
ALTER TABLE provider_connections_0022 RENAME TO provider_connections;

CREATE INDEX IF NOT EXISTS idx_provider_connections_owner
  ON provider_connections(owner_id, provider);
