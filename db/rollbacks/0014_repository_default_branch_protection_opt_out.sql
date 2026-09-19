-- Rollback for 0014_repository_default_branch_protection_opt_out is intentionally non-destructive.
--
-- An application built before 0014 ignores the column and re-applies
-- automatic default-branch protection on open, which is the safe direction.
-- Retain the additive column and roll forward after repair.
--
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'
SELECT '0014_repository_default_branch_protection_opt_out rollback is non-destructive; retain the additive column and roll forward after repair' AS rollback_notice;
