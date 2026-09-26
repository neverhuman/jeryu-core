//! Durable deployment history: atomic append batches outside the State-owned
//! snapshot.
//!
//! `SqliteStore::persist` reconciles only the State-owned tables listed in
//! `storage::snapshot`. `deployments` and `deployment_statuses` are
//! deliberately not in that list, exactly like `forge_audit_log`, so an
//! unrelated forge write can never touch the deploy history. They are read back
//! into memory on open by [`load_deployments`].

use rusqlite::{Connection, params};

use super::codec::{json, parse_json, time};
use super::{SqliteStore, State, storage_error};
use crate::errors::Result;
use crate::model::{Deployment, DeploymentStatus};

impl SqliteStore {
    pub(in super::super) fn append_deployment(
        &self,
        repo_id: &str,
        deployment: &Deployment,
    ) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            r#"
            INSERT INTO deployments (
              id, repo_id, owner, repo, environment, sha, deployment_json, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                deployment.id,
                repo_id,
                deployment.owner,
                deployment.repo,
                deployment.environment,
                deployment.sha,
                json(deployment)?,
                time(deployment.created_at),
            ],
        )
        .map_err(storage_error)?;
        Ok(())
    }

    pub(in super::super) fn append_deployment_statuses(
        &self,
        statuses: &[DeploymentStatus],
    ) -> Result<()> {
        let mut conn = self.connect()?;
        let transaction = conn.transaction().map_err(storage_error)?;
        for status in statuses {
            transaction
                .execute(
                    r#"
                INSERT INTO deployment_statuses (id, deployment_id, state, status_json, created_at)
                VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                    params![
                        status.id,
                        status.deployment_id,
                        status.state.as_str(),
                        json(status)?,
                        time(status.created_at)
                    ],
                )
                .map_err(storage_error)?;
        }
        transaction.commit().map_err(storage_error)?;
        Ok(())
    }
}

pub(super) fn load_deployments(conn: &Connection, state: &mut State) -> Result<()> {
    let mut stmt = conn
        .prepare("SELECT repo_id, deployment_json FROM deployments ORDER BY id")
        .map_err(storage_error)?;
    let mut rows = stmt.query([]).map_err(storage_error)?;
    while let Some(row) = rows.next().map_err(storage_error)? {
        let mut deployment: Deployment = parse_json(row.get(1).map_err(storage_error)?)?;
        let repository_id: String = row.get(0).map_err(storage_error)?;
        deployment.repository_id = uuid::Uuid::parse_str(&repository_id).map_err(storage_error)?;
        state.deployments.insert(deployment.id, deployment);
    }

    let mut stmt = conn
        .prepare("SELECT status_json FROM deployment_statuses ORDER BY id")
        .map_err(storage_error)?;
    let mut rows = stmt.query([]).map_err(storage_error)?;
    while let Some(row) = rows.next().map_err(storage_error)? {
        let status: DeploymentStatus = parse_json(row.get(0).map_err(storage_error)?)?;
        state
            .deployment_statuses
            .entry(status.deployment_id)
            .or_default()
            .push(status);
    }
    Ok(())
}
