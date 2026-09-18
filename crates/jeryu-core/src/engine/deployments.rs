//! Deployments and their append-only status trail.
//!
//! Deployments live in memory like every other forge resource, but they are
//! made durable through their own append path (see `SqliteStore::
//! append_deployment`), never through the full-state rewrite: that rewrite
//! deletes and reinserts every state table on each mutation, and the deploy
//! history must not depend on it. Each write is therefore exactly one durable
//! append, done before memory is updated, under the state write lock so ids stay
//! in order.
//!
//! Nothing here updates or deletes. A deployment's outcome changes only by
//! appending a status, and GitHub's `auto_inactive` is implemented the same way:
//! by appending an `inactive` status to the deployments a success replaces.
//!
//! Deployments emit no webhook events yet: an event would need the full-state
//! persist, and a failure there would roll memory back past a row that is
//! already durable.

use std::collections::BTreeSet;

use chrono::Utc;

use super::{ForgeCore, State, require_name};
use crate::errors::{ForgeError, Result};
use crate::model::*;

impl ForgeCore {
    pub fn create_deployment(
        &self,
        owner: &str,
        repo: &str,
        creator: &str,
        request: CreateDeploymentRequest,
    ) -> Result<Deployment> {
        let repository = self.get_repository(owner, repo)?;
        require_sha(&request.sha)?;
        require_name("environment", &request.environment)?;
        require_name("task", &request.task)?;
        let ref_name = match request.ref_name {
            Some(value) => {
                require_name("ref", &value)?;
                value
            }
            None => request.sha.clone(),
        };
        let payload = request.payload.unwrap_or_else(|| serde_json::json!({}));
        let production_environment = request
            .production_environment
            .unwrap_or(request.environment == "production");

        let mut state = self.state.write();
        let deployment = Deployment {
            id: next_deployment_id(&state),
            owner: owner.to_string(),
            repo: repo.to_string(),
            sha: request.sha,
            ref_name,
            task: request.task,
            environment: request.environment,
            description: request.description,
            payload,
            production_environment,
            transient_environment: request.transient_environment,
            creator: creator.to_string(),
            created_at: Utc::now(),
        };
        if let Some(storage) = &self.storage {
            storage.append_deployment(&repository.id.to_string(), &deployment)?;
        }
        state.deployments.insert(deployment.id, deployment.clone());
        Ok(deployment)
    }

    pub fn get_deployment(&self, owner: &str, repo: &str, id: u64) -> Result<Deployment> {
        self.ensure_repo_exists(owner, repo)?;
        let state = self.state.read();
        find_deployment(&state, owner, repo, id).cloned()
    }

    /// A repository's deployments, newest first.
    pub fn list_deployments(
        &self,
        owner: &str,
        repo: &str,
        filter: &DeploymentFilter,
    ) -> Result<Vec<Deployment>> {
        self.ensure_repo_exists(owner, repo)?;
        let state = self.state.read();
        Ok(state
            .deployments
            .values()
            .rev()
            .filter(|d| d.owner == owner && d.repo == repo)
            .filter(|d| {
                filter
                    .environment
                    .as_ref()
                    .is_none_or(|e| &d.environment == e)
            })
            .filter(|d| filter.sha.as_ref().is_none_or(|s| &d.sha == s))
            .filter(|d| filter.ref_name.as_ref().is_none_or(|r| &d.ref_name == r))
            .cloned()
            .collect())
    }

    /// Append a status. On `success` with `auto_inactive`, also append an
    /// `inactive` status to every earlier, non-transient deployment of the same
    /// environment whose newest status is still `success`.
    pub fn create_deployment_status(
        &self,
        owner: &str,
        repo: &str,
        deployment_id: u64,
        creator: &str,
        request: CreateDeploymentStatusRequest,
    ) -> Result<DeploymentStatus> {
        self.ensure_repo_exists(owner, repo)?;
        let mut state = self.state.write();
        let deployment = find_deployment(&state, owner, repo, deployment_id)?.clone();
        let now = Utc::now();
        let status = DeploymentStatus {
            id: next_deployment_status_id(&state),
            deployment_id,
            state: request.state,
            description: request.description,
            environment_url: request.environment_url,
            log_url: request.log_url,
            creator: creator.to_string(),
            created_at: now,
        };
        self.append_status(&mut state, status.clone())?;

        if request.state == DeploymentState::Success && request.auto_inactive {
            let superseded: Vec<u64> = state
                .deployments
                .values()
                .filter(|d| {
                    d.id < deployment_id
                        && d.owner == owner
                        && d.repo == repo
                        && d.environment == deployment.environment
                        && !d.transient_environment
                })
                .filter(|d| {
                    latest_status(&state, d.id).map(|s| s.state) == Some(DeploymentState::Success)
                })
                .map(|d| d.id)
                .collect();
            for id in superseded {
                let inactive = DeploymentStatus {
                    id: next_deployment_status_id(&state),
                    deployment_id: id,
                    state: DeploymentState::Inactive,
                    description: Some(format!("superseded by deployment {deployment_id}")),
                    environment_url: None,
                    log_url: None,
                    creator: creator.to_string(),
                    created_at: now,
                };
                self.append_status(&mut state, inactive)?;
            }
        }
        Ok(status)
    }

    /// A deployment's statuses, newest first (GitHub's order).
    pub fn list_deployment_statuses(
        &self,
        owner: &str,
        repo: &str,
        deployment_id: u64,
    ) -> Result<Vec<DeploymentStatus>> {
        self.ensure_repo_exists(owner, repo)?;
        let state = self.state.read();
        find_deployment(&state, owner, repo, deployment_id)?;
        Ok(state
            .deployment_statuses
            .get(&deployment_id)
            .map(|statuses| statuses.iter().rev().cloned().collect())
            .unwrap_or_default())
    }

    /// Every environment the repository has deployed to, alphabetically, with
    /// what it runs now and what it ran before.
    pub fn deployment_environments(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<Vec<EnvironmentSummary>> {
        self.ensure_repo_exists(owner, repo)?;
        let state = self.state.read();
        let names: BTreeSet<&str> = state
            .deployments
            .values()
            .filter(|d| d.owner == owner && d.repo == repo)
            .map(|d| d.environment.as_str())
            .collect();
        Ok(names
            .into_iter()
            .map(|environment| summarize_environment(&state, owner, repo, environment))
            .collect())
    }

    fn append_status(&self, state: &mut State, status: DeploymentStatus) -> Result<()> {
        if let Some(storage) = &self.storage {
            storage.append_deployment_status(&status)?;
        }
        state
            .deployment_statuses
            .entry(status.deployment_id)
            .or_default()
            .push(status);
        Ok(())
    }
}

fn summarize_environment(
    state: &State,
    owner: &str,
    repo: &str,
    environment: &str,
) -> EnvironmentSummary {
    let newest_first: Vec<DeploymentWithStatus> = state
        .deployments
        .values()
        .rev()
        .filter(|d| d.owner == owner && d.repo == repo && d.environment == environment)
        .map(|d| with_status(state, d))
        .collect();
    let mut succeeded = newest_first.iter().filter(|d| d.succeeded);
    let current = succeeded.next().cloned();
    let previous = succeeded.next().cloned();
    EnvironmentSummary {
        environment: environment.to_string(),
        latest: newest_first.first().cloned(),
        current,
        previous,
    }
}

fn with_status(state: &State, deployment: &Deployment) -> DeploymentWithStatus {
    let statuses = state.deployment_statuses.get(&deployment.id);
    DeploymentWithStatus {
        deployment: deployment.clone(),
        status: statuses.and_then(|s| s.last()).cloned(),
        succeeded: statuses.is_some_and(|s| {
            s.iter()
                .any(|status| status.state == DeploymentState::Success)
        }),
    }
}

fn latest_status(state: &State, deployment_id: u64) -> Option<&DeploymentStatus> {
    state
        .deployment_statuses
        .get(&deployment_id)
        .and_then(|statuses| statuses.last())
}

fn find_deployment<'a>(
    state: &'a State,
    owner: &str,
    repo: &str,
    id: u64,
) -> Result<&'a Deployment> {
    state
        .deployments
        .get(&id)
        .filter(|d| d.owner == owner && d.repo == repo)
        .ok_or_else(|| ForgeError::NotFound(format!("deployment {id} in {owner}/{repo}")))
}

fn next_deployment_id(state: &State) -> u64 {
    state.deployments.keys().next_back().map_or(1, |id| id + 1)
}

fn next_deployment_status_id(state: &State) -> u64 {
    state
        .deployment_statuses
        .values()
        .flatten()
        .map(|status| status.id)
        .max()
        .map_or(1, |id| id + 1)
}

fn require_sha(sha: &str) -> Result<()> {
    if sha.len() == 40
        && sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(ForgeError::Validation(
            "sha must be a full 40-character lowercase hex commit id".to_string(),
        ))
    }
}
