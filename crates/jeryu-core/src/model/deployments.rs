//! Deployments and their append-only status trail, in the GitHub Deployments
//! API shape.
//!
//! A [`Deployment`] records that one commit was sent to one environment. Its
//! outcome is never edited in place: every change is a new
//! [`DeploymentStatus`], so the statuses of a deployment are its history and the
//! deployments of an environment are that environment's history.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// GitHub's deployment status states, in wire spelling.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentState {
    Error,
    Failure,
    Inactive,
    InProgress,
    Queued,
    Pending,
    Success,
}

impl DeploymentState {
    /// The wire spelling, which is also the value the SQL CHECK accepts.
    pub fn as_str(self) -> &'static str {
        match self {
            DeploymentState::Error => "error",
            DeploymentState::Failure => "failure",
            DeploymentState::Inactive => "inactive",
            DeploymentState::InProgress => "in_progress",
            DeploymentState::Queued => "queued",
            DeploymentState::Pending => "pending",
            DeploymentState::Success => "success",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Deployment {
    /// Forge-wide, monotonically increasing (GitHub deployment ids are integers).
    pub id: u64,
    /// Immutable repository identity; restored from SQL for earlier stored rows.
    #[serde(default)]
    pub repository_id: Uuid,
    pub owner: String,
    pub repo: String,
    /// The exact 40-hex commit deployed.
    pub sha: String,
    /// The ref the caller named (branch, tag or the sha itself).
    #[serde(rename = "ref")]
    pub ref_name: String,
    pub task: String,
    pub environment: String,
    pub description: Option<String>,
    /// Free-form deploy detail (release id, artifact digests, host, ...).
    pub payload: Value,
    pub production_environment: bool,
    pub transient_environment: bool,
    pub creator: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeploymentStatus {
    /// Forge-wide, monotonically increasing.
    pub id: u64,
    pub deployment_id: u64,
    pub state: DeploymentState,
    pub description: Option<String>,
    /// Where the deployed thing can be reached.
    pub environment_url: Option<String>,
    /// Where the deploy's own log can be read.
    pub log_url: Option<String>,
    pub creator: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateDeploymentRequest {
    /// Required: the forge records exactly what ran, so the caller names the
    /// commit rather than asking the forge to resolve a moving ref.
    pub sha: String,
    /// Defaults to the sha.
    #[serde(default, rename = "ref")]
    pub ref_name: Option<String>,
    #[serde(default = "default_deployment_task")]
    pub task: String,
    #[serde(default = "default_deployment_environment")]
    pub environment: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub payload: Option<Value>,
    /// Defaults to `environment == "production"`, as on GitHub.
    #[serde(default)]
    pub production_environment: Option<bool>,
    #[serde(default)]
    pub transient_environment: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateDeploymentStatusRequest {
    pub state: DeploymentState,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub environment_url: Option<String>,
    #[serde(default)]
    pub log_url: Option<String>,
    /// On `success`, append an `inactive` status to every earlier deployment of
    /// the same environment that is still live, as GitHub does. Defaults true.
    #[serde(default = "default_auto_inactive")]
    pub auto_inactive: bool,
}

/// Filters for listing a repository's deployments; `None` matches anything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeploymentFilter {
    pub environment: Option<String>,
    pub sha: Option<String>,
    pub ref_name: Option<String>,
}

/// What an environment is running now and what it ran before.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvironmentSummary {
    pub environment: String,
    /// The newest deployment of the environment, whatever its outcome.
    pub latest: Option<DeploymentWithStatus>,
    /// The deployment with the newest still-effective success: what is live.
    pub current: Option<DeploymentWithStatus>,
    /// The successful deployment `current` replaced: the rollback target.
    pub previous: Option<DeploymentWithStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeploymentWithStatus {
    pub deployment: Deployment,
    /// The deployment's newest status; `None` until one is posted.
    pub status: Option<DeploymentStatus>,
    /// True when the deployment ever reached `success`, even if a later
    /// `inactive` status has since superseded it.
    pub succeeded: bool,
}

pub fn default_deployment_task() -> String {
    "deploy".to_string()
}

pub fn default_deployment_environment() -> String {
    "production".to_string()
}

fn default_auto_inactive() -> bool {
    true
}
