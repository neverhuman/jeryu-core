-- Public waitlist addresses. A row is an email, not an account.
--
-- The table is State-owned: SqliteStore loads it, stages it, and reconciles it
-- with every other snapshot table. Joining does not create a user or a session.
--
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'
CREATE TABLE IF NOT EXISTS waitlist_signups (
  email TEXT PRIMARY KEY CHECK (
    length(email) BETWEEN 3 AND 254
    AND email = lower(email)
    AND instr(email, ' ') = 0
    AND instr(email, '@') > 1
  ),
  name TEXT CHECK (name IS NULL OR (length(trim(name)) > 0 AND length(name) <= 80)),
  note TEXT CHECK (note IS NULL OR (length(trim(note)) > 0 AND length(note) <= 280)),
  status TEXT NOT NULL DEFAULT 'listed' CHECK (status IN ('listed', 'invited', 'declined')),
  source TEXT NOT NULL DEFAULT 'landing' CHECK (source = 'landing'),
  request_count INTEGER NOT NULL DEFAULT 1 CHECK (request_count >= 1),
  created_at TEXT NOT NULL,
  last_requested_at TEXT NOT NULL
);
