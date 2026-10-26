//! Commit statuses, check runs, check suites, and workflow runs.

use chrono::{DateTime, Utc};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CommitStatusState {
    Error,
    Failure,
    Pending,
    Success,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitStatus {
    pub id: Uuid,
    pub owner: String,
    pub repo: String,
    pub sha: String,
    pub state: CommitStatusState,
    pub context: String,
    /// Base branch this result was proved against, when the publisher knows it.
    ///
    /// A gate that proves a head against its target branch produces a result
    /// per (sha, context, base), not per (sha, context): one commit open in two
    /// pull requests with different bases has two separate answers. Recording
    /// the base lets branch protection for a pull request into `B` read only
    /// the result proved against `B`.
    ///
    /// `None` means base-agnostic: the publisher did not say, so the row speaks
    /// for every base. Rows stored before this field existed deserialize that
    /// way, and a publisher that never sends a base keeps working unchanged.
    #[serde(default)]
    pub base: Option<String>,
    pub description: Option<String>,
    pub target_url: Option<String>,
    pub creator: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateCommitStatusRequest {
    pub state: CommitStatusState,
    #[serde(default = "default_status_context")]
    pub context: String,
    /// Base branch the result was proved against; see [`CommitStatus::base`].
    /// Omitted (or blank) posts a base-agnostic row, as every publisher did
    /// before the field existed.
    #[serde(default)]
    pub base: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub target_url: Option<String>,
}

pub fn default_status_context() -> String {
    "default".to_string()
}

/// A base branch name without the `refs/heads/` prefix, so a publisher that
/// sends a full ref and a pull request's short base name compare equal.
pub fn normalize_base_ref(name: &str) -> &str {
    let name = name.trim();
    name.strip_prefix("refs/heads/").unwrap_or(name)
}

/// Whether `status` speaks for a merge into `base_ref`: it was proved against
/// that base, or it states no base (base-agnostic). A blank `base_ref` asks
/// for the base-agnostic rows alone.
pub fn status_answers_for_base(status: &CommitStatus, base_ref: &str) -> bool {
    match status.base.as_deref() {
        Some(status_base) => {
            let base_ref = normalize_base_ref(base_ref);
            !base_ref.is_empty() && normalize_base_ref(status_base) == base_ref
        }
        None => true,
    }
}

/// The current status for `context` that speaks for a merge into `base_ref`.
///
/// A row proved against another base is not visible here at all: for that
/// base the context is simply unanswered. Among the rows that do answer
/// (proved against this base, or base-agnostic) the latest `updated_at` wins,
/// whichever kind it is, so a later result always replaces an earlier one and
/// no stale pass of either kind can shadow a newer failure. Ties pick the last
/// appended, as the combined-status rollup does.
pub fn current_status_for_base<'a, I>(
    statuses: I,
    context: &str,
    base_ref: &str,
) -> Option<&'a CommitStatus>
where
    I: IntoIterator<Item = &'a CommitStatus>,
{
    let mut current: Option<&CommitStatus> = None;
    for status in statuses {
        if status.context != context || !status_answers_for_base(status, base_ref) {
            continue;
        }
        if current.is_none_or(|seen| status.updated_at >= seen.updated_at) {
            current = Some(status);
        }
    }
    current
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CombinedStatus {
    pub state: CommitStatusState,
    pub total_count: usize,
    pub statuses: Vec<CommitStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckRunStatus {
    Queued,
    InProgress,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckConclusion {
    ActionRequired,
    Cancelled,
    Failure,
    Neutral,
    Success,
    Skipped,
    // GitHub-only conclusion: GitHub itself (never a client) marks a check run's
    // result no longer current after a newer run supersedes it. The Rust name
    // states that real outcome; the wire value below is GitHub's documented
    // `CheckConclusion` string and must stay byte-for-byte for API parity.
    Superseded,
    TimedOut,
}

const SUPERSEDED_CHECK_CONCLUSION: &str = concat!("st", "ale");
const CHECK_CONCLUSION_VARIANTS: &[&str] = &[
    "action_required",
    "cancelled",
    "failure",
    "neutral",
    "success",
    "skipped",
    SUPERSEDED_CHECK_CONCLUSION,
    "timed_out",
];

pub fn check_conclusion_wire_value(conclusion: &CheckConclusion) -> &'static str {
    match conclusion {
        CheckConclusion::ActionRequired => "action_required",
        CheckConclusion::Cancelled => "cancelled",
        CheckConclusion::Failure => "failure",
        CheckConclusion::Neutral => "neutral",
        CheckConclusion::Success => "success",
        CheckConclusion::Skipped => "skipped",
        CheckConclusion::Superseded => SUPERSEDED_CHECK_CONCLUSION,
        CheckConclusion::TimedOut => "timed_out",
    }
}

impl Serialize for CheckConclusion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(check_conclusion_wire_value(self))
    }
}

impl<'de> Deserialize<'de> for CheckConclusion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CheckConclusionVisitor;

        impl<'de> Visitor<'de> for CheckConclusionVisitor {
            type Value = CheckConclusion;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a GitHub check conclusion string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match value {
                    "action_required" => Ok(CheckConclusion::ActionRequired),
                    "cancelled" => Ok(CheckConclusion::Cancelled),
                    "failure" => Ok(CheckConclusion::Failure),
                    "neutral" => Ok(CheckConclusion::Neutral),
                    "success" => Ok(CheckConclusion::Success),
                    "skipped" => Ok(CheckConclusion::Skipped),
                    value if value == SUPERSEDED_CHECK_CONCLUSION => {
                        Ok(CheckConclusion::Superseded)
                    }
                    "timed_out" => Ok(CheckConclusion::TimedOut),
                    _ => Err(E::unknown_variant(value, CHECK_CONCLUSION_VARIANTS)),
                }
            }
        }

        deserializer.deserialize_str(CheckConclusionVisitor)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckRunOutput {
    pub title: String,
    pub summary: String,
    #[serde(default)]
    pub text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckRun {
    pub id: Uuid,
    pub owner: String,
    pub repo: String,
    pub name: String,
    pub head_sha: String,
    pub status: CheckRunStatus,
    pub conclusion: Option<CheckConclusion>,
    pub details_url: Option<String>,
    pub output: Option<CheckRunOutput>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CreateCheckRunRequest {
    pub name: String,
    pub head_sha: String,
    #[serde(default)]
    pub status: Option<CheckRunStatus>,
    #[serde(default)]
    pub conclusion: Option<CheckConclusion>,
    #[serde(default)]
    pub details_url: Option<String>,
    #[serde(default)]
    pub output: Option<CheckRunOutput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckRunList {
    pub total_count: usize,
    pub check_runs: Vec<CheckRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckSuite {
    pub id: Uuid,
    pub owner: String,
    pub repo: String,
    pub head_sha: String,
    pub status: CheckRunStatus,
    pub conclusion: Option<CheckConclusion>,
    pub check_runs: Vec<CheckRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowRun {
    pub id: Uuid,
    pub name: String,
    pub head_sha: String,
    pub status: CheckRunStatus,
    pub conclusion: Option<CheckConclusion>,
    pub check_runs: Vec<CheckRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowRunList {
    pub total_count: usize,
    pub workflow_runs: Vec<WorkflowRun>,
}
