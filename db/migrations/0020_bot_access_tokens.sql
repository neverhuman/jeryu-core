-- Scoped agent tokens. A token belongs to one account bot and is presented
-- directly as a bearer on REST, git and MCP. It carries the bot's grant (the
-- owner's non-admin rights cut down by the bot's reach); it adds no rights.
-- Only the SHA-256 of the token is stored. A token is valid while its bot's
-- credential_generation still equals `generation`, so suspending or revoking
-- the bot, or any owner account event that bumps the generation, ends every
-- token of that bot. `key_id` records the key live at issue, for audit only;
-- rotating the enrollment key does not end a token.
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'

CREATE TABLE IF NOT EXISTS bot_access_tokens (
  token_hash TEXT PRIMARY KEY CHECK (length(token_hash) = 64),
  token_id TEXT NOT NULL UNIQUE CHECK (length(token_id) = 12),
  bot_id TEXT NOT NULL REFERENCES bots(id) ON DELETE CASCADE,
  key_id TEXT NOT NULL,
  generation INTEGER NOT NULL CHECK (generation >= 1),
  label TEXT CHECK (label IS NULL OR length(label) BETWEEN 1 AND 80),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_bot_access_tokens_bot ON bot_access_tokens(bot_id);
