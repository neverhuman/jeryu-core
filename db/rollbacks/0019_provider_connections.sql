-- Retain provider_connections. Its rows are sealed credentials users connected
-- once; dropping them forces every user and service account to reconnect.
-- An older writer that snapshots State without this table deletes the rows on
-- its next save: never run that writer against a migrated database. Restore a
-- verified pre-0019 VACUUM INTO copy only when no connection has been made
-- since; otherwise recover forward.
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'
SELECT '0019 rollback retains sealed provider connections; restore the pre-migration snapshot or recover forward' AS rollback_notice;
