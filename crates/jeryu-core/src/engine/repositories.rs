//! Repositories and labels.

use std::collections::HashMap;
use std::hash::Hash;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::{Counters, ForgeCore, RepoBranches, RepoPushHistory, require_name};
use crate::errors::{ForgeError, Result};
use crate::model::*;

/// Receipt for one [`ForgeCore::delete_repository`]: the removed repository
/// plus how many entries each repo-scoped collection lost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryDeletion {
    pub repo: Repository,
    pub labels: u32,
    pub issues: u32,
    pub issue_comments: u32,
    pub pulls: u32,
    pub reviews: u32,
    pub review_comments: u32,
    pub branch_protections: u32,
    pub codeowners: u32,
    pub readmes: u32,
    pub commit_statuses: u32,
    pub check_runs: u32,
    pub webhooks: u32,
    pub webhook_deliveries: u32,
    pub counters: u32,
    pub jankurai_scores: u32,
    pub repo_grants: u32,
}

impl RepositoryDeletion {
    /// `(collection, removed)` pairs in stable order for operator receipts.
    #[must_use]
    pub fn removed_counts(&self) -> Vec<(&'static str, u32)> {
        vec![
            ("labels", self.labels),
            ("issues", self.issues),
            ("issue_comments", self.issue_comments),
            ("pulls", self.pulls),
            ("reviews", self.reviews),
            ("review_comments", self.review_comments),
            ("branch_protections", self.branch_protections),
            ("codeowners", self.codeowners),
            ("readmes", self.readmes),
            ("commit_statuses", self.commit_statuses),
            ("check_runs", self.check_runs),
            ("webhooks", self.webhooks),
            ("webhook_deliveries", self.webhook_deliveries),
            ("counters", self.counters),
            ("jankurai_scores", self.jankurai_scores),
            ("repo_grants", self.repo_grants),
        ]
    }
}

/// Remove every `(owner, repo, _)`-keyed entry, counting removed entries.
fn drain_scoped<K: Eq + Hash + Clone, V>(
    map: &mut HashMap<(String, String, K), V>,
    owner: &str,
    repo: &str,
) -> u32 {
    let keys: Vec<_> = map
        .keys()
        .filter(|(key_owner, key_repo, _)| key_owner == owner && key_repo == repo)
        .cloned()
        .collect();
    let removed = keys.len() as u32;
    for key in keys {
        map.remove(&key);
    }
    removed
}

/// Remove every `(owner, repo, _)`-keyed bucket, counting removed ELEMENTS.
fn drain_scoped_vecs<K: Eq + Hash + Clone, V>(
    map: &mut HashMap<(String, String, K), Vec<V>>,
    owner: &str,
    repo: &str,
) -> u32 {
    let keys: Vec<_> = map
        .keys()
        .filter(|(key_owner, key_repo, _)| key_owner == owner && key_repo == repo)
        .cloned()
        .collect();
    let mut removed = 0u32;
    for key in keys {
        if let Some(bucket) = map.remove(&key) {
            removed += bucket.len() as u32;
        }
    }
    removed
}

impl ForgeCore {
    pub fn create_repository(
        &self,
        owner: &str,
        request: CreateRepositoryRequest,
    ) -> Result<Repository> {
        require_name("repository name", &request.name)?;
        let mut state = self.state.write();
        let key = (owner.to_string(), request.name.clone());
        if state.repos.contains_key(&key) {
            return Err(ForgeError::Conflict(format!(
                "repository {owner}/{}",
                request.name
            )));
        }
        let previous = state.clone();
        let now = Utc::now();
        let repo = Repository {
            id: Uuid::new_v4(),
            owner: owner.to_string(),
            name: request.name.clone(),
            full_name: format!("{owner}/{}", request.name),
            private: request.private,
            description: request.description,
            default_branch: request.default_branch.unwrap_or_else(|| "main".to_string()),
            family: None,
            archived: false,
            disabled: false,
            created_at: now,
            updated_at: now,
            pushed_at: None,
            default_branch_protection_opt_out: false,
        };
        state.counters.insert(key.clone(), Counters::default());
        state.repos.insert(key, repo.clone());
        super::ensure_default_branch_protection(&mut state, &repo);
        self.persist_after_mutation(&mut state, previous)?;
        drop(state);
        if let Some(materializer) = &self.repo_materializer {
            materializer.materialize(owner, &repo.name, &repo.default_branch)?;
        }
        Ok(repo)
    }

    pub fn list_repositories(&self, owner: Option<&str>) -> Vec<Repository> {
        let mut repos: Vec<_> = self
            .state
            .read()
            .repos
            .values()
            .filter(|repo| owner.is_none_or(|owner| repo.owner == owner))
            .cloned()
            .collect();
        repos.sort_by(|a, b| a.full_name.cmp(&b.full_name));
        repos
    }

    pub fn get_repository(&self, owner: &str, repo: &str) -> Result<Repository> {
        self.state
            .read()
            .repos
            .get(&(owner.to_string(), repo.to_string()))
            .cloned()
            .ok_or_else(|| ForgeError::NotFound(format!("repository {owner}/{repo}")))
    }

    /// Set or clear the repository's UI grouping family.
    pub fn set_repository_family(
        &self,
        owner: &str,
        repo: &str,
        family: Option<String>,
    ) -> Result<Repository> {
        let family = match family {
            Some(value) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    return Err(ForgeError::Validation(
                        "family must not be blank; send null to clear it".to_string(),
                    ));
                }
                Some(trimmed.to_string())
            }
            None => None,
        };
        let mut state = self.state.write();
        let key = (owner.to_string(), repo.to_string());
        if !state.repos.contains_key(&key) {
            return Err(ForgeError::NotFound(format!("repository {owner}/{repo}")));
        }
        let previous = state.clone();
        let entry = state.repos.get_mut(&key).expect("presence checked above");
        entry.family = family;
        entry.updated_at = Utc::now();
        let updated = entry.clone();
        self.persist_after_mutation(&mut state, previous)?;
        Ok(updated)
    }

    /// Change the repository's default branch to an existing `branch`.
    ///
    /// The branch must exist in git storage (`branches`); a missing branch is
    /// `NotFound`, a blank or unchanged one is `Validation`. The new default
    /// branch receives the same automatic protection as on create (unless the
    /// repository has opted out); rules on the previous default stay as-is.
    pub fn set_repository_default_branch(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
        branches: &dyn RepoBranches,
    ) -> Result<Repository> {
        require_name("branch", branch)?;
        if branch.trim() != branch {
            return Err(ForgeError::Validation(
                "branch must not have surrounding whitespace".to_string(),
            ));
        }
        let current = self.get_repository(owner, repo)?;
        if current.default_branch == branch {
            return Ok(current);
        }
        if !branches.branch_exists(owner, repo, branch)? {
            return Err(ForgeError::NotFound(format!(
                "branch {branch} in repository {owner}/{repo}"
            )));
        }
        let mut state = self.state.write();
        let key = (owner.to_string(), repo.to_string());
        if !state.repos.contains_key(&key) {
            return Err(ForgeError::NotFound(format!("repository {owner}/{repo}")));
        }
        let previous = state.clone();
        let entry = state.repos.get_mut(&key).expect("presence checked above");
        entry.default_branch = branch.to_string();
        entry.updated_at = Utc::now();
        let updated = entry.clone();
        super::ensure_default_branch_protection(&mut state, &updated);
        self.persist_after_mutation(&mut state, previous)?;
        Ok(updated)
    }

    /// Opt `owner/repo` in or out of automatic default-branch protection.
    ///
    /// Only an active global admin (`actor`) may change it; anyone else gets
    /// `BranchProtection("global admin required")`. Opting out is refused
    /// with `Validation` while any branch protection rule of the repository
    /// requires a status context. Opting out removes the default branch's
    /// rule only when it is still exactly the automatic one; a rule an admin
    /// customised stays. Opting back in restores the automatic rule. Every
    /// change is audited as `repository.default_branch_protection_opt_out`.
    pub fn set_default_branch_protection_opt_out(
        &self,
        actor: &str,
        owner: &str,
        repo: &str,
        opt_out: bool,
    ) -> Result<Repository> {
        let current = self.get_repository(owner, repo)?;
        if !self.is_global_admin(actor) {
            return Err(ForgeError::BranchProtection(
                "global admin required".to_string(),
            ));
        }
        let subject = format!("{owner}/{repo}");
        let action = "repository.default_branch_protection_opt_out";
        let detail = serde_json::json!({
            "actor": actor,
            "opt_out": opt_out,
            "default_branch": current.default_branch,
        });
        let mut state = self.state.write();
        let key = (owner.to_string(), repo.to_string());
        if opt_out && super::repo_requires_status_context(&state, owner, repo) {
            drop(state);
            self.append_audit(action, &subject, "failed", detail)?;
            return Err(ForgeError::Validation(format!(
                "repository {owner}/{repo} requires a status context; its default branch cannot opt out of protection"
            )));
        }
        let Some(entry) = state.repos.get(&key) else {
            return Err(ForgeError::NotFound(format!("repository {owner}/{repo}")));
        };
        if entry.default_branch_protection_opt_out == opt_out {
            return Ok(entry.clone());
        }
        let previous = state.clone();
        let entry = state.repos.get_mut(&key).expect("presence checked above");
        entry.default_branch_protection_opt_out = opt_out;
        entry.updated_at = Utc::now();
        let updated = entry.clone();
        let rule_key = (
            owner.to_string(),
            repo.to_string(),
            updated.default_branch.clone(),
        );
        if opt_out {
            let automatic =
                super::default_branch_protection_rule(owner, repo, &updated.default_branch);
            if state
                .branch_protections
                .get(&rule_key)
                .is_some_and(|rule| is_automatic_rule(rule, &automatic))
            {
                state.branch_protections.remove(&rule_key);
            }
        } else {
            super::ensure_default_branch_protection(&mut state, &updated);
        }
        self.persist_after_mutation(&mut state, previous)?;
        drop(state);
        self.append_audit(action, &subject, "completed", detail)?;
        Ok(updated)
    }

    /// Record a successful push at `at`. Called by the git edge only after a
    /// receive-pack or ref update actually moved a ref; rejected pushes never
    /// reach here. `pushed_at` never moves backwards, so a late-arriving
    /// notification for an older push is a no-op.
    pub fn record_repository_push(
        &self,
        owner: &str,
        repo: &str,
        at: DateTime<Utc>,
    ) -> Result<Repository> {
        let mut state = self.state.write();
        let key = (owner.to_string(), repo.to_string());
        let Some(current) = state.repos.get(&key) else {
            return Err(ForgeError::NotFound(format!("repository {owner}/{repo}")));
        };
        if current.pushed_at.is_some_and(|pushed_at| pushed_at >= at) {
            return Ok(current.clone());
        }
        let previous = state.clone();
        let entry = state.repos.get_mut(&key).expect("presence checked above");
        entry.pushed_at = Some(at);
        let updated = entry.clone();
        self.persist_after_mutation(&mut state, previous)?;
        Ok(updated)
    }

    /// Fill `pushed_at` for repositories that have none from their git
    /// history (newest committer date across refs). Rows that already carry a
    /// value are never overwritten, so running this on every open is a
    /// one-time backfill per repository. Returns how many rows were filled.
    pub fn backfill_repository_pushed_at(&self, history: &dyn RepoPushHistory) -> Result<usize> {
        let pending: Vec<(String, String)> = self
            .state
            .read()
            .repos
            .iter()
            .filter(|(_, repo)| repo.pushed_at.is_none())
            .map(|(key, _)| key.clone())
            .collect();
        let mut found = Vec::new();
        for (owner, name) in pending {
            if let Some(at) = history.newest_commit_time(&owner, &name)? {
                found.push(((owner, name), at));
            }
        }
        if found.is_empty() {
            return Ok(0);
        }
        let mut state = self.state.write();
        let previous = state.clone();
        let mut filled = 0;
        for (key, at) in found {
            if let Some(entry) = state.repos.get_mut(&key)
                && entry.pushed_at.is_none()
            {
                entry.pushed_at = Some(at);
                filled += 1;
            }
        }
        if filled > 0 {
            self.persist_after_mutation(&mut state, previous)?;
        }
        Ok(filled)
    }

    /// Delete a repository and everything scoped to it from the live state.
    ///
    /// Persistence is a full-state rewrite (`SqliteStore::persist` deletes and
    /// reinserts every table), so removing the repo from EVERY `State` map and
    /// persisting once is the complete, transactional registry deletion: the
    /// rewrite simply never re-inserts the removed rows. Account-level state
    /// (users, organizations, teams) is not repo-scoped and stays untouched;
    /// the `forge_audit_log` table lives outside the rewrite by design and
    /// keeps its trail for the deleted subject.
    pub fn delete_repository(&self, owner: &str, repo: &str) -> Result<RepositoryDeletion> {
        let mut state = self.state.write();
        let key = (owner.to_string(), repo.to_string());
        let Some(removed_repo) = state.repos.get(&key).cloned() else {
            return Err(ForgeError::NotFound(format!("repository {owner}/{repo}")));
        };
        let previous = state.clone();

        state.repos.remove(&key);
        let labels = drain_scoped(&mut state.labels, owner, repo);
        let issues = drain_scoped(&mut state.issues, owner, repo);
        let issue_comments = drain_scoped_vecs(&mut state.issue_comments, owner, repo);
        let pulls = drain_scoped(&mut state.pulls, owner, repo);
        let reviews = drain_scoped_vecs(&mut state.reviews, owner, repo);
        let review_comments = drain_scoped_vecs(&mut state.review_comments, owner, repo);
        let branch_protections = drain_scoped(&mut state.branch_protections, owner, repo);
        let codeowners = u32::from(state.codeowners.remove(&key).is_some());
        let readmes = u32::from(state.readmes.remove(&key).is_some());
        let commit_statuses = drain_scoped_vecs(&mut state.statuses, owner, repo);
        let check_runs = state
            .check_runs
            .remove(&key)
            .map_or(0, |runs| runs.len() as u32);
        let webhooks = state
            .webhooks
            .remove(&key)
            .map_or(0, |hooks| hooks.len() as u32);
        let deliveries_before = state.webhook_deliveries.len();
        state
            .webhook_deliveries
            .retain(|delivery| !(delivery.owner == owner && delivery.repo == repo));
        let webhook_deliveries = (deliveries_before - state.webhook_deliveries.len()) as u32;
        let counters = u32::from(state.counters.remove(&key).is_some());
        let jankurai_scores = state
            .jankurai_scores
            .remove(&key)
            .map_or(0, |scores| scores.len() as u32);
        let grant_keys: Vec<_> = state
            .repo_grants
            .keys()
            .filter(|(_, grant_owner, grant_repo)| grant_owner == owner && grant_repo == repo)
            .cloned()
            .collect();
        let repo_grants = grant_keys.len() as u32;
        for grant_key in grant_keys {
            state.repo_grants.remove(&grant_key);
        }

        self.persist_after_mutation(&mut state, previous)?;
        Ok(RepositoryDeletion {
            repo: removed_repo,
            labels,
            issues,
            issue_comments,
            pulls,
            reviews,
            review_comments,
            branch_protections,
            codeowners,
            readmes,
            commit_statuses,
            check_runs,
            webhooks,
            webhook_deliveries,
            counters,
            jankurai_scores,
            repo_grants,
        })
    }

    pub fn create_label(
        &self,
        owner: &str,
        repo: &str,
        request: CreateLabelRequest,
    ) -> Result<Label> {
        require_name("label name", &request.name)?;
        self.ensure_repo_exists(owner, repo)?;
        let mut state = self.state.write();
        let key = (owner.to_string(), repo.to_string(), request.name.clone());
        if state.labels.contains_key(&key) {
            return Err(ForgeError::Conflict(format!(
                "label {owner}/{repo}/{}",
                request.name
            )));
        }
        let previous = state.clone();
        let label = Label {
            id: Uuid::new_v4(),
            name: request.name,
            color: request.color,
            description: request.description,
        };
        state.labels.insert(key, label.clone());
        self.persist_after_mutation(&mut state, previous)?;
        Ok(label)
    }

    pub fn list_labels(&self, owner: &str, repo: &str) -> Result<Vec<Label>> {
        self.ensure_repo_exists(owner, repo)?;
        let state = self.state.read();
        let mut labels: Vec<_> = state
            .labels
            .iter()
            .filter(|((label_owner, label_repo, _), _)| label_owner == owner && label_repo == repo)
            .map(|(_, label)| label.clone())
            .collect();
        labels.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(labels)
    }
}

/// `rule` equals the automatic default-branch rule, ignoring `updated_at`.
fn is_automatic_rule(rule: &BranchProtectionRule, automatic: &BranchProtectionRule) -> bool {
    let mut rule = rule.clone();
    rule.updated_at = automatic.updated_at;
    &rule == automatic
}
