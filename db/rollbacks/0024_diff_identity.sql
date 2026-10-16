-- Rollback for 0024_diff_identity: drop the recorded diff identities.
--
-- Dropping the columns loses only the patch ids a pusher recorded; every head
-- and verdict then binds its exact sha, the behaviour before 0024. Re-applying
-- the migration starts recording again on the next push.
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'
ALTER TABLE pull_requests DROP COLUMN head_patch_ids_json;
ALTER TABLE reviews DROP COLUMN head_patch_ids_json;
