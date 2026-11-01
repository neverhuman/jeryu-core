-- The immutable per-repository creation order of a check run. Written once
-- when the run is created, never rewritten by completion, so the newest proof
-- is the highest sequence rather than the latest of mixed start/finish times.
--
-- Additive; existing rows hold 0, and the loader numbers them in insertion
-- (rowid) order on the next open, so no backfill statement can half-apply.
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'
ALTER TABLE check_runs ADD COLUMN creation_sequence INTEGER NOT NULL DEFAULT 0
  CHECK (creation_sequence >= 0);
