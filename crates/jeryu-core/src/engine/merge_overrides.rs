//! Audited, explicitly enabled administrator decisions. Intrinsic gates bind every actor.
use super::{ForgeCore, MergeReadiness, evaluate_locked};
use crate::errors::{ForgeError, Result};
use crate::model::*;
use chrono::Utc;
use serde_json::json;

/// Explicit decision supplied by an authenticated API edge. The edge owns
/// passport evaluation; this hash is recorded only as a caller assertion.
#[derive(Debug, Clone)]
pub struct MergeOverrideRequest {
    pub actor: String,
    pub reason: String,
    pub expected_head_sha: String,
    pub asserted_passport_hash: String,
}

/// Opaque authorization bound to one PR and its core gate snapshot. Callers
/// cannot construct a permit or alter its recorded actor, reason or blockers.
#[derive(Debug)]
pub struct MergeOverridePermit {
    pub(super) owner: String,
    pub(super) repo: String,
    pub(super) number: u64,
    pub(super) actor: String,
    pub(super) reason: String,
    pub(super) head_sha: String,
    pub(super) base_sha: String,
    pub(super) passport_hash: String,
    pub(super) expires_at: i64,
    pub(super) status_evidence: Vec<CommitStatus>,
    pub(super) evaluation: crate::BranchProtectionEvaluation,
    pub(super) protection: BranchProtectionRule,
}

impl MergeOverridePermit {
    pub(super) fn subject(&self) -> String {
        format!("{}/{}#{}", self.owner, self.repo, self.number)
    }

    pub(super) fn audit_detail(&self, merge_sha: Option<&str>) -> serde_json::Value {
        json!({
            "pr_number": self.number,
            "reason": self.reason,
            "head_sha": self.head_sha,
            "caller_passport_hash": self.passport_hash,
            "blockers": self.evaluation.blockers,
            "status_evidence": self.status_evidence,
            "merge_sha": merge_sha,
        })
    }
}

pub(super) fn validate_override(state: &super::State, pr: &PullRequest, actor: &str) -> Result<()> {
    let active = state
        .accounts
        .get(actor)
        .filter(|account| account.status.permits_authentication());
    let admin = active.is_some_and(|account| account.role == UserRole::Admin)
        || (active.is_some()
            && state
                .repo_grants
                .get(&(actor.to_string(), pr.owner.clone(), pr.repo.clone()))
                .is_some_and(|grant| grant.access.allows_admin()));
    if !admin {
        return Err(ForgeError::Forbidden(
            "merge override requires an active repository administrator".to_string(),
        ));
    }
    let protection = state.branch_protections.get(&(
        pr.owner.clone(),
        pr.repo.clone(),
        pr.base.ref_name.clone(),
    ));
    if protection.is_none_or(|rule| !rule.allow_merge_override) {
        return Err(ForgeError::Forbidden(
            "merge override requires explicit allow_merge_override=true".to_string(),
        ));
    }
    if actor == pr.author {
        return Err(ForgeError::Forbidden(
            "a pull request author cannot authorize its override".into(),
        ));
    }
    if pr.draft
        || matches!(
            pr.state,
            PullRequestState::Closed | PullRequestState::Merged
        )
        || pr.merged
    {
        return Err(ForgeError::Validation(
            "merge override requires an open pull request ready for review".to_string(),
        ));
    }
    Ok(())
}

/// All normal blockers remain binding except explicitly named failed commit
/// statuses. A pending/missing context, reviewer hold, proof, signature,
/// CODEOWNERS, approval or history blocker cannot be authorized here.
pub(super) fn validate_override_evaluation(
    state: &super::State,
    pr: &PullRequest,
    protection: &BranchProtectionRule,
    evaluation: &crate::BranchProtectionEvaluation,
) -> Result<Vec<CommitStatus>> {
    let mut evidence = Vec::new();
    for blocker in &evaluation.blockers {
        if let crate::MergeBlocker::FailedStatusCheck { context } = blocker {
            let status = state
                .statuses
                .get(&(pr.owner.clone(), pr.repo.clone(), pr.head.sha.clone()))
                .into_iter()
                .flatten()
                .filter(|status| status.context == *context)
                .max_by_key(|status| status.updated_at);
            let running = state
                .check_runs
                .get(&(pr.owner.clone(), pr.repo.clone()))
                .into_iter()
                .flatten()
                .any(|run| {
                    run.head_sha == pr.head.sha
                        && run.name == *context
                        && run.status != CheckRunStatus::Completed
                });
            if protection.merge_override_status_checks.contains(context)
                && !running
                && let Some(status) = status
                && protection
                    .merge_override_status_creators
                    .contains(&status.creator)
                && matches!(
                    status.state,
                    CommitStatusState::Failure | CommitStatusState::Error
                )
            {
                evidence.push(status.clone());
                continue;
            }
        }
        return Err(ForgeError::BranchProtection(format!(
            "override cannot clear {blocker:?}"
        )));
    }
    Ok(evidence)
}

impl ForgeCore {
    /// Prepare an explicitly enabled administrator decision for allowlisted failed
    /// commit status contexts. Every other normal merge blocker remains binding. The API edge
    /// still owns Git conflict checks. Durable storage is required before a
    /// requested receipt can authorize the Git phase.
    pub fn prepare_merge_override(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
        request: MergeOverrideRequest,
    ) -> Result<(MergeReadiness, MergeOverridePermit)> {
        self.ensure_repository_writable(owner, repo)?;
        if self.storage.is_none() {
            return Err(ForgeError::Validation(
                "merge override requires durable audit storage".into(),
            ));
        }
        if request.reason.trim().is_empty()
            || !request
                .asserted_passport_hash
                .strip_prefix("passport:")
                .is_some_and(|hash| {
                    hash.len() == 64
                        && hash
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
        {
            return Err(ForgeError::Validation(
                "merge override requires a reason and caller passport assertion".to_string(),
            ));
        }
        let state = self.state.read();
        let pr = state
            .pulls
            .get(&(owner.to_string(), repo.to_string(), number))
            .ok_or_else(|| ForgeError::NotFound(format!("pull request {owner}/{repo}#{number}")))?;
        validate_override(&state, pr, &request.actor)?;
        if request.expected_head_sha != pr.head.sha {
            return Err(ForgeError::Conflict(
                "merge override head changed; refresh before deciding".to_string(),
            ));
        }
        let protection = state
            .branch_protections
            .get(&(
                owner.to_string(),
                repo.to_string(),
                pr.base.ref_name.clone(),
            ))
            .ok_or_else(|| ForgeError::Conflict("override protection disappeared".into()))?
            .clone();
        let evaluation = evaluate_locked(&state, pr, Some(&pr.head.sha));
        let status_evidence = validate_override_evaluation(&state, pr, &protection, &evaluation)?;
        let permit = MergeOverridePermit {
            owner: owner.to_string(),
            repo: repo.to_string(),
            number,
            actor: request.actor,
            reason: request.reason.trim().to_string(),
            head_sha: pr.head.sha.clone(),
            base_sha: pr.base.sha.clone(),
            passport_hash: request.asserted_passport_hash,
            expires_at: Utc::now().timestamp() + 600,
            status_evidence,
            evaluation,
            protection,
        };
        let ready = MergeReadiness::Ready {
            base_ref: pr.base.ref_name.clone(),
            base_sha: pr.base.sha.clone(),
            head_ref: pr.head.ref_name.clone(),
            head_sha: pr.head.sha.clone(),
            require_linear_history: permit.protection.required_linear_history,
        };
        drop(state);
        self.append_audit_as(
            &permit.actor,
            "pull.merge_override",
            &permit.subject(),
            "requested",
            permit.audit_detail(None),
        )?;
        Ok((ready, permit))
    }
}
