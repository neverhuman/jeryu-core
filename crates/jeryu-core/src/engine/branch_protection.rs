//! Branch protection rules, CODEOWNERS, and ref-operation enforcement.

use chrono::Utc;

use super::{ForgeCore, RepoBranches, evaluate_locked, require_name};
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
    /// The caller authorizes (the HTTP route is admin only). The default
    /// branch's rule is refused: the store re-creates it on open unless the
    /// repository opted out, so deleting it would not stick; use
    /// `set_default_branch_protection_opt_out` for that.
    pub fn delete_branch_protection(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
    ) -> Result<BranchProtectionRule> {
        let current = self.canonical_repository(owner, repo)?;
        let (owner, repo) = (current.owner.as_str(), current.name.as_str());
        if current.default_branch == branch && !current.default_branch_protection_opt_out {
            return Err(ForgeError::Validation(format!(
                "{branch} is the default branch of {owner}/{repo}; opt the repository out of default branch protection instead"
            )));
        }
        let mut state = self.state.write();
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
        Ok(removed)
    }

    /// Repairs rules stored under a percent-encoded branch name (`%2F`).
    ///
    /// A rule whose branch contains `%2F` is re-keyed to the decoded name when
    /// that branch exists in git storage, and removed otherwise. When a rule
    /// already exists under the decoded name it wins and the encoded one is
    /// dropped. Idempotent: a second pass finds nothing. A git lookup error
    /// aborts before anything is changed.
    pub fn rekey_encoded_branch_protections(
        &self,
        branches: &dyn RepoBranches,
    ) -> Result<EncodedProtectionReport> {
        let encoded: Vec<_> = self
            .state
            .read()
            .branch_protections
            .keys()
            .filter(|(_, _, branch)| has_encoded_slash(branch))
            .cloned()
            .collect();
        let mut plan = Vec::new();
        for key in encoded {
            let decoded = decode_slashes(&key.2);
            let exists = branches.branch_exists(&key.0, &key.1, &decoded)?;
            plan.push((key, decoded, exists));
        }
        if plan.is_empty() {
            return Ok(EncodedProtectionReport::default());
        }
        let mut state = self.state.write();
        let previous = state.clone();
        let mut report = EncodedProtectionReport::default();
        for (key, decoded, exists) in plan {
            let Some(mut rule) = state.branch_protections.remove(&key) else {
                continue;
            };
            let target = (key.0.clone(), key.1.clone(), decoded.clone());
            if exists && !state.branch_protections.contains_key(&target) {
                rule.branch = decoded;
                state.branch_protections.insert(target, rule);
                report.rekeyed.push(key);
            } else {
                report.removed.push(key);
            }
        }
        self.persist_after_mutation(&mut state, previous)?;
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

/// What [`ForgeCore::rekey_encoded_branch_protections`] changed; each entry is
/// the old `(owner, repo, branch)` key.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EncodedProtectionReport {
    /// Rules moved to the decoded branch name.
    pub rekeyed: Vec<(String, String, String)>,
    /// Rules dropped: no such branch, or the decoded name already had a rule.
    pub removed: Vec<(String, String, String)>,
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
