-- Rollback for 0025_password_recovery_tokens: drop the recovery tokens.
--
-- Dropping the table ends every outstanding recovery link; people ask for a
-- new one after the roll forward. No password, session or token changes.
--
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'
DROP TABLE IF EXISTS password_recovery_tokens;
