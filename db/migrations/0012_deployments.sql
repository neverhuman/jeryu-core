-- Deployments and their append-only status trail (GitHub Deployments API shape).
--
-- A deployment records that one commit of one repository was sent to one
-- environment (prod, canary, dev, ...). Each change in its outcome is a NEW
-- deployment_statuses row; rows are never updated or deleted, so the table is
-- the deploy history.
--
-- Like forge_audit_log (0006), neither table has a foreign key to
-- repositories: the deploy history must not depend on the repository row's
-- lifetime at all. Neither table is in the State-owned table list that
-- SqliteStore::persist reconciles. Rows carry the repository's stable id and a
-- denormalized owner/name, and are written only through the dedicated append
-- path.
--
-- timeout-guard:
--   lock_timeout = '5s'
--   statement_timeout = '60s'
CREATE TABLE IF NOT EXISTS deployments (
  id INTEGER PRIMARY KEY CHECK (id > 0),
  repo_id TEXT NOT NULL CHECK (length(trim(repo_id)) > 0),
  owner TEXT NOT NULL CHECK (length(trim(owner)) > 0),
  repo TEXT NOT NULL CHECK (length(trim(repo)) > 0),
  environment TEXT NOT NULL CHECK (length(trim(environment)) > 0),
  sha TEXT NOT NULL CHECK (length(sha) = 40 AND sha NOT GLOB '*[^0-9a-f]*'),
  deployment_json TEXT NOT NULL CHECK (json_valid(deployment_json)),
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_deployments_repo_environment
  ON deployments(repo_id, environment, id);

CREATE TABLE IF NOT EXISTS deployment_statuses (
  id INTEGER PRIMARY KEY CHECK (id > 0),
  deployment_id INTEGER NOT NULL CHECK (deployment_id > 0),
  state TEXT NOT NULL CHECK (
    state IN ('error', 'failure', 'inactive', 'in_progress', 'queued', 'pending', 'success')
  ),
  status_json TEXT NOT NULL CHECK (json_valid(status_json)),
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_deployment_statuses_deployment
  ON deployment_statuses(deployment_id, id);
