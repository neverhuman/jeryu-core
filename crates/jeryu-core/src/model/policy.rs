//! Branch protection rules.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BranchProtectionRule {
    pub owner: String,
    pub repo: String,
    pub branch: String,
    pub required_status_checks: Vec<String>,
    /// GitHub's `required_status_checks.strict`: the head must be up to date
    /// with the base before merging. Independent of `required_linear_history`.
    /// Defaulted on read so rules stored before this field existed still load.
    #[serde(default)]
    pub strict: bool,
    pub required_approving_review_count: u64,
    pub enforce_admins: bool,
    pub required_linear_history: bool,
    pub allow_force_pushes: bool,
    pub allow_deletions: bool,
    pub require_signed_commits: bool,
    pub require_jankurai_proof: bool,
    pub updated_at: DateTime<Utc>,
}

/// A branch-protection PUT body. GitHub replaces the whole rule on every PUT,
/// so a field left out is turned off — which makes the top-level fields
/// mandatory: a body missing one is rejected (the edge answers 422) instead of
/// quietly defaulting it and disabling protections the caller never mentioned.
/// The optional fields below are the ones GitHub also treats as optional.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SetBranchProtectionRequest {
    pub required_status_checks: Vec<String>,
    pub required_approving_review_count: u64,
    pub enforce_admins: bool,
    #[serde(default)]
    pub strict: bool,
    #[serde(default)]
    pub required_linear_history: bool,
    #[serde(default)]
    pub allow_force_pushes: bool,
    #[serde(default)]
    pub allow_deletions: bool,
    #[serde(default)]
    pub require_signed_commits: bool,
    #[serde(default)]
    pub require_jankurai_proof: bool,
}
