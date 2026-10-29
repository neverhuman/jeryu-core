-- Rollback for 0026_review_dismissal_authority: drop the recorded authority.
--
-- Dropping the column makes every administrator dismissal of another
-- reviewer's verdict withdraw nothing again: the dismissed verdict counts as
-- before. That is stricter, never looser. Re-applying the migration does not
-- restore the dropped authority; an administrator dismisses again.
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'
ALTER TABLE reviews DROP COLUMN dismissal_authority;
