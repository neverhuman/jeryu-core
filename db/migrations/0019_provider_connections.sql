-- Connect-once provider connections (contracts connection-v1 §1). A user or a
-- service account connects Claude, Codex, or Grok once; managed sessions bind
-- the connection id and generation, never the credential.
-- sealed_secret is an AES-256-GCM envelope: a per-record data key wrapped by
-- the deployment vault key, both with associated data naming the connection,
-- owner, provider, and generation, so a sealed value cannot be replayed onto
-- another row. Plaintext refresh tokens and API keys are never stored.
-- owner_id carries its kind as a prefix (user/ or service/) and has no foreign
-- key: service accounts are not user_accounts rows.
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'

CREATE TABLE IF NOT EXISTS provider_connections (
  id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
  owner_id TEXT NOT NULL CHECK (owner_id LIKE 'user/_%' OR owner_id LIKE 'service/_%'),
  provider TEXT NOT NULL CHECK (provider IN ('claude', 'codex', 'grok')),
  provider_account TEXT NOT NULL CHECK (length(trim(provider_account)) > 0),
  credential_kind TEXT NOT NULL CHECK (credential_kind IN ('oauth_refresh', 'api_key')),
  state TEXT NOT NULL CHECK (state IN ('pending', 'connected', 'disconnected')),
  connection_generation INTEGER NOT NULL CHECK (connection_generation >= 1),
  secret_version INTEGER NOT NULL CHECK (secret_version >= 0),
  sealed_secret TEXT CHECK (sealed_secret IS NULL OR json_valid(sealed_secret)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  refreshed_at TEXT,
  CHECK ((state = 'connected') = (sealed_secret IS NOT NULL)),
  UNIQUE (owner_id, provider, provider_account)
);

CREATE INDEX IF NOT EXISTS idx_provider_connections_owner
  ON provider_connections(owner_id, provider);
