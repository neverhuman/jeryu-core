//! Branch protection rules, CODEOWNERS, and ref-operation enforcement.

use chrono::Utc;

use super::{ForgeCore, RepoBranches, State, evaluate_locked, require_name};
use crate::branch_protection::{
    BranchProtectionEvaluation, EvaluationContext, RefOperation, RefOperationEvaluation,
    evaluate_ref_operation,
};
use crate::errors::{ForgeError, Result};
use crate::model::*;

impl ForgeCore {
    pub fn set_branch_protection(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
        request: SetBranchProtectionRequest,
    ) -> Result<BranchProtectionRule> {
        self.ensure_repo_exists(owner, repo)?;
        require_name("branch", branch)?;
        let rule = BranchProtectionRule {
            owner: owner.to_string(),
            repo: repo.to_string(),
            branch: branch.to_string(),
            required_status_checks: request.required_status_checks,
            strict: request.strict,
            required_approving_review_count: request.required_approving_review_count,
            allow_merge_override: request.allow_merge_override,
            merge_override_status_checks: request.merge_override_status_checks,
            merge_override_status_creators: request.merge_override_status_creators,
            enforce_admins: request.enforce_admins,
            required_linear_history: request.required_linear_history,
            allow_force_pushes: request.allow_force_pushes,
            allow_deletions: request.allow_deletions,
            require_signed_commits: request.require_signed_commits,
            require_jankurai_proof: request.require_jankurai_proof,
            dismiss_stale_approvals: request.dismiss_stale_approvals,
            require_exact_sha_approval: request.require_exact_sha_approval,
            updated_at: Utc::now(),
        };
        let mut state = self.state.write();
        let previous = state.clone();
        state.branch_protections.insert(
            (owner.to_string(), repo.to_string(), branch.to_string()),
            rule.clone(),
        );
        self.persist_after_mutation(&mut state, previous)?;
        Ok(rule)
    }

    /// Lists every branch protection rule of `owner/repo`, ordered by branch.
    pub fn list_branch_protections(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<Vec<BranchProtectionRule>> {
        self.ensure_repo_exists(owner, repo)?;
        let mut rules: Vec<_> = self
            .state
            .read()
            .branch_protections
            .iter()
            .filter(|((o, r, _), _)| o == owner && r == repo)
            .map(|(_, rule)| rule.clone())
            .collect();
        rules.sort_by(|a, b| a.branch.cmp(&b.branch));
        Ok(rules)
    }

    /// Removes and persists the rule on one branch, returning it.
    ///
    /// The caller authorizes (the HTTP route is admin only); `actor` is
    /// recorded in the audit trail as `branch_protection.deleted` with the
    /// removed rule, `failed` on a refusal and `completed` on success.
    /// Archived repositories are refused (`RepositoryArchived`). The default
    /// branch's rule is refused with `Validation` under the same invariant the
    /// store enforces on open: unless the repository opted out of default
    /// branch protection *and* none of its rules requires a status context,
    /// the rule is mandatory (see `set_default_branch_protection_opt_out`).
    /// The guard reads the repository under the same write lock that removes
    /// the rule, so a concurrent opt-out change cannot slip between them.
    pub fn delete_branch_protection(
        &self,
        actor: &str,
        owner: &str,
        repo: &str,
        branch: &str,
    ) -> Result<BranchProtectionRule> {
        let current = self.canonical_repository(owner, repo)?;
        let (owner, repo) = (current.owner.as_str(), current.name.as_str());
        self.ensure_repository_writable(owner, repo)?;
        let subject = format!("{owner}/{repo}");
        let action = "branch_protection.deleted";
        let mut state = self.state.write();
        let repo_key = (owner.to_string(), repo.to_string());
        let Some(live) = state.repos.get(&repo_key).cloned() else {
            return Err(ForgeError::NotFound(format!("repository {owner}/{repo}")));
        };
        if live.archived {
            return Err(ForgeError::RepositoryArchived(subject));
        }
        if live.default_branch == branch && default_rule_is_mandatory(&state, &live) {
            drop(state);
            let detail = serde_json::json!({ "branch": branch, "reason": "default_branch" });
            self.append_audit_as(actor, action, &subject, "failed", detail)?;
            return Err(ForgeError::Validation(format!(
                "{branch} is the default branch of {owner}/{repo} and its protection is mandatory; opt the repository out of default branch protection first (refused while any rule requires a status context)"
            )));
        }
        let key = (owner.to_string(), repo.to_string(), branch.to_string());
        if !state.branch_protections.contains_key(&key) {
            return Err(ForgeError::NotFound(format!(
                "branch protection {owner}/{repo}:{branch}"
            )));
        }
        let previous = state.clone();
        let removed = state
            .branch_protections
            .remove(&key)
            .expect("presence checked above");
        self.persist_after_mutation(&mut state, previous)?;
        drop(state);
        let detail = serde_json::json!({ "branch": branch, "rule": removed });
        self.append_audit_as(actor, action, &subject, "completed", detail)?;
        Ok(removed)
    }

    /// One-shot repair of rules stored under a percent-encoded branch name
    /// (`%2F`), run by a global admin (`BranchProtection("global admin
    /// required")` otherwise).
    ///
    /// This is not a startup migration like `backfill_default_branch_protections`:
    /// it needs git storage (`branches`) to tell real branches from junk, which
    /// `open_sqlite` does not have, so it is an admin-actor-only operation.
    ///
    /// A rule is changed only when no git branch carries its encoded name:
    /// - re-keyed to the decoded name when that branch exists and has no rule;
    /// - removed when the decoded branch exists and already has a rule (that
    ///   rule wins), unless the encoded rule requires status checks.
    ///
    /// Everything else is kept and reported in `kept` with the reason: a real
    /// branch with a literal `%2F` name, a rule armed before its decoded branch
    /// exists, the default branch's rule, a rule requiring status checks that
    /// would be dropped, an archived repository, or a rule changed since the
    /// git lookups. Git lookups run without the state lock; every decision is
    /// re-validated under the write lock against the rule seen then. Each
    /// change is audited as `branch_protection.encoded_rekey`. Idempotent. A git
    /// lookup error aborts before anything is changed.
    pub fn rekey_encoded_branch_protections(
        &self,
        actor: &str,
        branches: &dyn RepoBranches,
    ) -> Result<EncodedProtectionReport> {
        if !self.is_global_admin(actor) {
            return Err(ForgeError::BranchProtection(
                "global admin required".to_string(),
            ));
        }
        let encoded: Vec<_> = self
            .state
            .read()
            .branch_protections
            .iter()
            .filter(|((_, _, branch), _)| has_encoded_slash(branch))
            .map(|(key, rule)| (key.clone(), rule.clone()))
            .collect();
        let mut plan = Vec::new();
        for (key, seen) in encoded {
            let decoded = decode_slashes(&key.2);
            let encoded_exists = branches.branch_exists(&key.0, &key.1, &key.2)?;
            let decoded_exists = branches.branch_exists(&key.0, &key.1, &decoded)?;
            plan.push(PlannedRekey {
                key,
                seen,
                decoded,
                encoded_exists,
                decoded_exists,
            });
        }
        let mut report = EncodedProtectionReport::default();
        if plan.is_empty() {
            return Ok(report);
        }
        let mut state = self.state.write();
        let previous = state.clone();
        let mut changes = Vec::new();
        for step in plan {
            match decide_rekey(&state, &step) {
                RekeyDecision::Keep(reason) => report.kept.push((step.key, reason.to_string())),
                RekeyDecision::Remove => {
                    state.branch_protections.remove(&step.key);
                    changes.push((step.key.clone(), "removed", step.decoded));
                    report.removed.push(step.key);
                }
                RekeyDecision::Rekey => {
                    let mut rule = state
                        .branch_protections
                        .remove(&step.key)
                        .expect("decide_rekey checked presence");
                    rule.branch.clone_from(&step.decoded);
                    let target = (step.key.0.clone(), step.key.1.clone(), step.decoded.clone());
                    state.branch_protections.insert(target, rule);
                    changes.push((step.key.clone(), "rekeyed", step.decoded));
                    report.rekeyed.push(step.key);
                }
            }
        }
        if changes.is_empty() {
            return Ok(report);
        }
        self.persist_after_mutation(&mut state, previous)?;
        drop(state);
        for ((owner, repo, from), outcome, to) in changes {
            let detail = serde_json::json!({
                "actor": actor,
                "from": from,
                "to": to,
                "outcome": outcome,
            });
            self.append_audit_as(
                actor,
                "branch_protection.encoded_rekey",
                &format!("{owner}/{repo}"),
                "completed",
                detail,
            )?;
        }
        Ok(report)
    }

    pub fn get_branch_protection(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
    ) -> Result<BranchProtectionRule> {
        match self
            .state
            .read()
            .branch_protections
            .get(&(owner.to_string(), repo.to_string(), branch.to_string()))
            .cloned()
        {
            Some(rule) => Ok(rule),
            None => Err(ForgeError::NotFound(format!(
                "branch protection {owner}/{repo}:{branch}"
            ))),
        }
    }

    /// Stores the repository's CODEOWNERS file contents. Used by branch
    /// protection to require code-owner approval of changed paths.
    pub fn set_codeowners(&self, owner: &str, repo: &str, contents: &str) -> Result<()> {
        self.ensure_repo_exists(owner, repo)?;
        let mut state = self.state.write();
        let previous = state.clone();
        state
            .codeowners
            .insert((owner.to_string(), repo.to_string()), contents.to_string());
        self.persist_after_mutation(&mut state, previous)?;
        Ok(())
    }

    pub fn get_codeowners(&self, owner: &str, repo: &str) -> Result<String> {
        self.ensure_repo_exists(owner, repo)?;
        match self
            .state
            .read()
            .codeowners
            .get(&(owner.to_string(), repo.to_string()))
            .cloned()
        {
            Some(codeowners) => Ok(codeowners),
            None => Err(ForgeError::NotFound(format!("CODEOWNERS {owner}/{repo}"))),
        }
    }

    pub fn evaluate_pull_request(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
        sha: Option<&str>,
    ) -> Result<BranchProtectionEvaluation> {
        let state = self.state.read();
        let pr = match state
            .pulls
            .get(&(owner.to_string(), repo.to_string(), number))
        {
            Some(pr) => pr,
            None => {
                return Err(ForgeError::NotFound(format!(
                    "pull request {owner}/{repo}#{number}"
                )));
            }
        };
        Ok(evaluate_locked(&state, pr, sha))
    }

    /// Evaluates a force-push or branch-deletion against the branch's
    /// protection rule. `actor_is_admin` lets an admin bypass when the rule's
    /// `enforce_admins` is off (GitHub's "Include administrators" toggle).
    pub fn evaluate_ref_operation(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
        operation: RefOperation,
        actor_is_admin: bool,
    ) -> Result<RefOperationEvaluation> {
        self.ensure_repository_writable(owner, repo)?;
        let state = self.state.read();
        let protection = state.branch_protections.get(&(
            owner.to_string(),
            repo.to_string(),
            branch.to_string(),
        ));
        Ok(evaluate_ref_operation(
            operation,
            protection,
            EvaluationContext {
                codeowners: None,
                actor_is_admin,
                jankurai_proof_mandatory: false,
            },
        ))
    }

    /// Attempts to force-push the branch, honoring `allow_force_pushes`.
    pub fn force_push(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
        actor_is_admin: bool,
    ) -> Result<()> {
        let evaluation = self.evaluate_ref_operation(
            owner,
            repo,
            branch,
            RefOperation::ForcePush,
            actor_is_admin,
        )?;
        if evaluation.allowed {
            Ok(())
        } else {
            Err(ForgeError::BranchProtection(format!(
                "{:?}",
                evaluation.blockers
            )))
        }
    }

    /// Attempts to delete the branch ref, honoring `allow_deletions`.
    pub fn delete_ref(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
        actor_is_admin: bool,
    ) -> Result<()> {
        let evaluation =
            self.evaluate_ref_operation(owner, repo, branch, RefOperation::Delete, actor_is_admin)?;
        if evaluation.allowed {
            Ok(())
        } else {
            Err(ForgeError::BranchProtection(format!(
                "{:?}",
                evaluation.blockers
            )))
        }
    }
}

/// What [`ForgeCore::rekey_encoded_branch_protections`] did; each entry is
/// the old `(owner, repo, branch)` key.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EncodedProtectionReport {
    /// Rules moved to the decoded branch name.
    pub rekeyed: Vec<(String, String, String)>,
    /// Rules dropped because the decoded branch already had a rule.
    pub removed: Vec<(String, String, String)>,
    /// Rules left untouched, with the reason, for an admin to review.
    pub kept: Vec<((String, String, String), String)>,
}

struct PlannedRekey {
    key: (String, String, String),
    seen: BranchProtectionRule,
    decoded: String,
    encoded_exists: bool,
    decoded_exists: bool,
}

enum RekeyDecision {
    Rekey,
    Remove,
    Keep(&'static str),
}

/// Decides one planned re-key against the live state (write lock held).
fn decide_rekey(state: &State, step: &PlannedRekey) -> RekeyDecision {
    let (owner, repo, branch) = &step.key;
    if state.branch_protections.get(&step.key) != Some(&step.seen) {
        return RekeyDecision::Keep("rule changed since planning");
    }
    let Some(repository) = state.repos.get(&(owner.clone(), repo.clone())) else {
        return RekeyDecision::Keep("repository not found");
    };
    if repository.archived {
        return RekeyDecision::Keep("repository archived");
    }
    if &repository.default_branch == branch {
        return RekeyDecision::Keep("default branch");
    }
    if step.encoded_exists {
        return RekeyDecision::Keep("encoded name is a real branch");
    }
    if !step.decoded_exists {
        return RekeyDecision::Keep("decoded branch does not exist");
    }
    let target = (owner.clone(), repo.clone(), step.decoded.clone());
    if !state.branch_protections.contains_key(&target) {
        return RekeyDecision::Rekey;
    }
    if !step.seen.required_status_checks.is_empty() {
        return RekeyDecision::Keep("duplicate requires status checks");
    }
    RekeyDecision::Remove
}

/// The default branch's rule may be removed only when the repository opted
/// out and no rule requires a status context: the invariant
/// `ensure_default_branch_protection` re-establishes on open.
fn default_rule_is_mandatory(state: &State, repo: &Repository) -> bool {
    !repo.default_branch_protection_opt_out
        || super::repo_requires_status_context(state, &repo.owner, &repo.name)
}

fn has_encoded_slash(branch: &str) -> bool {
    branch.to_ascii_lowercase().contains("%2f")
}

fn decode_slashes(branch: &str) -> String {
    let mut out = String::with_capacity(branch.len());
    let mut rest = branch;
    while let Some(at) = rest.to_ascii_lowercase().find("%2f") {
        out.push_str(&rest[..at]);
        out.push('/');
        rest = &rest[at + 3..];
    }
    out.push_str(rest);
    out
}
