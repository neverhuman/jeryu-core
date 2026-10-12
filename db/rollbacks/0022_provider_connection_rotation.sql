-- Retain provider_connections as 0022 left it. Narrowing the state CHECK
-- back would fail on any auth_required row, and dropping the rotation
-- columns would forget a rotation in flight, whose secret the provider may
-- already have consumed. A binary from before 0022 cannot load an
-- auth_required row: recover forward, or restore a verified pre-0022
-- VACUUM INTO copy only when no refresh has run since.
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'
SELECT '0022 rollback retains provider_connections; recover forward or restore the pre-migration snapshot' AS rollback_notice;
