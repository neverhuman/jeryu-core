//! Deployments and their append-only status trail.
//!
//! Deployments live in memory like every other forge resource, but they are
//! made durable through their own append path (see `SqliteStore::
//! append_deployment`), never through the State-owned snapshot: that snapshot
//! reconciles only the tables Core owns, and the deploy history must not
//! depend on it. Each transition commits its durable appends
//! atomically before memory is updated, under the state write lock so ids stay
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
use uuid::Uuid;

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
        let repository_id = find_repository_id(&state, owner, repo)?;
        let deployment = Deployment {
            id: next_deployment_id(&state),
            repository_id,
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
            storage.append_deployment(&repository_id.to_string(), &deployment)?;
        }
        state.deployments.insert(deployment.id, deployment.clone());
        Ok(deployment)
    }

    pub fn get_deployment(&self, owner: &str, repo: &str, id: u64) -> Result<Deployment> {
        let state = self.state.read();
        let repository_id = find_repository_id(&state, owner, repo)?;
        find_deployment(&state, repository_id, id).cloned()
    }

    /// A repository's deployments, newest first.
    pub fn list_deployments(
        &self,
        owner: &str,
        repo: &str,
        filter: &DeploymentFilter,
    ) -> Result<Vec<Deployment>> {
        let state = self.state.read();
        let repository_id = find_repository_id(&state, owner, repo)?;
        Ok(state
            .deployments
            .values()
            .rev()
            .filter(|d| d.repository_id == repository_id)
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
    /// `inactive` status to every other non-transient deployment of the same
    /// environment whose newest status is still `success`.
    pub fn create_deployment_status(
        &self,
        owner: &str,
        repo: &str,
        deployment_id: u64,
        creator: &str,
        request: CreateDeploymentStatusRequest,
    ) -> Result<DeploymentStatus> {
        let mut state = self.state.write();
        let repository_id = find_repository_id(&state, owner, repo)?;
        let deployment = find_deployment(&state, repository_id, deployment_id)?.clone();
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
        let mut pending = vec![status.clone()];

        if request.state == DeploymentState::Success && request.auto_inactive {
            let superseded: Vec<u64> = state
                .deployments
                .values()
                .filter(|d| {
                    d.id != deployment_id
                        && d.repository_id == repository_id
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
                    id: status.id + pending.len() as u64,
                    deployment_id: id,
                    state: DeploymentState::Inactive,
                    description: Some(format!("superseded by deployment {deployment_id}")),
                    environment_url: None,
                    log_url: None,
                    creator: creator.to_string(),
                    created_at: now,
                };
                pending.push(inactive);
            }
        }
        self.append_statuses(&mut state, &pending)?;
        Ok(status)
    }

    /// A deployment's statuses, newest first (GitHub's order).
    pub fn list_deployment_statuses(
        &self,
        owner: &str,
        repo: &str,
        deployment_id: u64,
    ) -> Result<Vec<DeploymentStatus>> {
        let state = self.state.read();
        let repository_id = find_repository_id(&state, owner, repo)?;
        find_deployment(&state, repository_id, deployment_id)?;
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
        let state = self.state.read();
        let repository_id = find_repository_id(&state, owner, repo)?;
        let names: BTreeSet<&str> = state
            .deployments
            .values()
            .filter(|d| d.repository_id == repository_id)
            .map(|d| d.environment.as_str())
            .collect();
        Ok(names
            .into_iter()
            .map(|environment| summarize_environment(&state, repository_id, environment))
            .collect())
    }

    fn append_statuses(&self, state: &mut State, statuses: &[DeploymentStatus]) -> Result<()> {
        if let Some(storage) = &self.storage {
            storage.append_deployment_statuses(statuses)?;
        }
        for status in statuses {
            state
                .deployment_statuses
                .entry(status.deployment_id)
                .or_default()
                .push(status.clone());
        }
        Ok(())
    }
}

fn find_repository_id(state: &State, owner: &str, repo: &str) -> Result<Uuid> {
    state
        .repos
        .get(&(owner.to_string(), repo.to_string()))
        .map(|repository| repository.id)
        .ok_or_else(|| ForgeError::NotFound(format!("repository {owner}/{repo}")))
}

fn summarize_environment(
    state: &State,
    repository_id: Uuid,
    environment: &str,
) -> EnvironmentSummary {
    let newest_first: Vec<DeploymentWithStatus> = state
        .deployments
        .values()
        .rev()
        .filter(|d| d.repository_id == repository_id && d.environment == environment)
        .map(|d| with_status(state, d))
        .collect();
    let current = newest_first
        .iter()
        .filter(|d| {
            d.status
                .as_ref()
                .is_some_and(|s| s.state == DeploymentState::Success)
        })
        .max_by_key(|d| d.status.as_ref().map(|s| s.id))
        .cloned();
    let previous = current.as_ref().and_then(|live| {
        newest_first
            .iter()
            .filter(|d| d.deployment.id != live.deployment.id && d.succeeded)
            .max_by_key(|d| {
                state
                    .deployment_statuses
                    .get(&d.deployment.id)
                    .and_then(|statuses| {
                        statuses
                            .iter()
                            .rev()
                            .find(|s| s.state == DeploymentState::Success)
                            .map(|s| s.id)
                    })
            })
            .cloned()
    });
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

fn find_deployment(state: &State, repository_id: Uuid, id: u64) -> Result<&Deployment> {
    state
        .deployments
        .get(&id)
        .filter(|d| d.repository_id == repository_id)
        .ok_or_else(|| {
            ForgeError::NotFound(format!("deployment {id} in repository {repository_id}"))
        })
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
