-- Additive last-push timestamp for repositories (RFC 3339 UTC text).
-- NULL means no push has been observed and no git history backfilled yet.
ALTER TABLE repositories ADD COLUMN pushed_at TEXT;
