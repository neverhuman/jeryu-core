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
    /// Explicit opt-in for independently recorded administrator decisions.
    #[serde(default)]
    pub allow_merge_override: bool,
    /// Explicit opt-in for an administrator dismissing another reviewer's
    /// verdict. Separate from `allow_merge_override`: a status-check override
    /// must not also make reviewer holds dismissable. Defaulted off so rules
    /// stored before this field existed, and wire payloads that omit it, read
    /// as off.
    #[serde(default)]
    pub allow_admin_review_dismissal: bool,
    /// Exact failed status contexts eligible for an audited decision. Empty denies all.
    #[serde(default)]
    pub merge_override_status_checks: Vec<String>,
    /// Authenticated CI status creators trusted for those contexts. Empty denies all.
    #[serde(default)]
    pub merge_override_status_creators: Vec<String>,
    pub required_linear_history: bool,
    pub allow_force_pushes: bool,
    pub allow_deletions: bool,
    pub require_signed_commits: bool,
    pub require_jankurai_proof: bool,
    /// Whether a push dismisses the approvals of the previous head. When off,
    /// an approval survives a push that leaves the diff unchanged (equal
    /// per-commit content digests, whitespace included -- a pure rebase or
    /// reword); any content change still invalidates it, and a range holding a
    /// merge or an empty commit has no identity, so nothing carries over it. Defaulted ON so a rule stored before this field
    /// existed keeps the exact-head behaviour it was written with.
    #[serde(default = "default_true")]
    pub dismiss_stale_approvals: bool,
    /// Whether a verdict counts only on the exact head it was written against,
    /// even when `dismiss_stale_approvals` is off. Defaulted ON for the same
    /// reason.
    #[serde(default = "default_true")]
    pub require_exact_sha_approval: bool,
    pub updated_at: DateTime<Utc>,
}

fn default_true() -> bool {
    true
}

/// A branch-protection PUT body. GitHub replaces the whole rule on every PUT,
/// so a field left out is turned off — which makes the top-level fields
/// mandatory: a body missing one is rejected (the edge answers 422) instead of
/// quietly defaulting it and disabling protections the caller never mentioned.
/// The optional fields below are the ones GitHub also treats as optional.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetBranchProtectionRequest {
    pub required_status_checks: Vec<String>,
    pub required_approving_review_count: u64,
    pub enforce_admins: bool,
    /// Explicit opt-in for independently recorded administrator decisions.
    #[serde(default)]
    pub allow_merge_override: bool,
    /// Explicit opt-in for an administrator dismissing another reviewer's
    /// verdict. Omitted means off: a body that turns on status-check overrides
    /// does not also make reviewer holds dismissable.
    #[serde(default)]
    pub allow_admin_review_dismissal: bool,
    /// Exact failed status contexts eligible for an audited decision. Empty denies all.
    #[serde(default)]
    pub merge_override_status_checks: Vec<String>,
    /// Authenticated CI status creators trusted for those contexts. Empty denies all.
    #[serde(default)]
    pub merge_override_status_creators: Vec<String>,
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
    /// Omitted means on: a caller that does not mention it keeps the
    /// exact-head behaviour rather than silently loosening approvals.
    #[serde(default = "default_true")]
    pub dismiss_stale_approvals: bool,
    #[serde(default = "default_true")]
    pub require_exact_sha_approval: bool,
}

/// The default request is the strict one: every protection off except the
/// exact-head approval rules, which stay on so a default never loosens them.
impl Default for SetBranchProtectionRequest {
    fn default() -> Self {
        Self {
            required_status_checks: Vec::new(),
            required_approving_review_count: 0,
            enforce_admins: false,
            allow_merge_override: false,
            allow_admin_review_dismissal: false,
            merge_override_status_checks: Vec::new(),
            merge_override_status_creators: Vec::new(),
            strict: false,
            required_linear_history: false,
            allow_force_pushes: false,
            allow_deletions: false,
            require_signed_commits: false,
            require_jankurai_proof: false,
            dismiss_stale_approvals: true,
            require_exact_sha_approval: true,
        }
    }
}
