-- Rollback for 0027_check_run_creation_sequence: drop the recorded order.
--
-- The loader renumbers every run from insertion order on the next open, so
-- the order survives the rollback; only the stored value is lost.
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'
ALTER TABLE check_runs DROP COLUMN creation_sequence;
