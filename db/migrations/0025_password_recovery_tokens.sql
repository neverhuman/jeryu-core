-- Self-service password recovery tokens. Core issues one for an active
-- account; the edge mails it to the account's verified address and spends it
-- with the new password. Only the SHA-256 of the secret is stored. A token is
-- single use, expires, is bound to the account's auth epoch at issue, and dies
-- after `attempt_count` reaches the cap of wrong secrets presented for it.
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'

CREATE TABLE IF NOT EXISTS password_recovery_tokens (
  token_id TEXT PRIMARY KEY CHECK (length(token_id) = 12),
  login TEXT NOT NULL CHECK (length(trim(login)) > 0),
  secret_hash TEXT NOT NULL UNIQUE CHECK (length(secret_hash) = 64),
  auth_epoch INTEGER NOT NULL CHECK (auth_epoch >= 0),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0)
);

CREATE INDEX IF NOT EXISTS idx_password_recovery_tokens_login
ON password_recovery_tokens(login);
