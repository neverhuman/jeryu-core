-- Retain the new bot tables. They hold enrollment hashes and activity.
-- An older writer that snapshots State without these tables deletes the rows
-- on its next save: never run that writer against a migrated database.
-- Before any bot row is accepted, restore a verified pre-0017 VACUUM INTO copy
-- only when no accepted post-migration mutation would be lost. Afterwards
-- recover forward.
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'
SELECT '0017 rollback retains bot credentials; restore the pre-migration snapshot or recover forward' AS rollback_notice;
