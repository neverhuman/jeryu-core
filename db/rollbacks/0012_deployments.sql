-- Rollback for 0012_deployments: drop the deployment history.
--
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'
DROP INDEX IF EXISTS idx_deployment_statuses_deployment;
DROP TABLE IF EXISTS deployment_statuses;
DROP INDEX IF EXISTS idx_deployments_repo_environment;
DROP TABLE IF EXISTS deployments;
