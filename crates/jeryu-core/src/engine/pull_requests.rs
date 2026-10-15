//! Pull requests, reviews, and merges.

use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

pub use super::merge_overrides::{MergeOverridePermit, MergeOverrideRequest};
use super::merge_overrides::{validate_override, validate_override_evaluation};
use super::{
    ForgeCore, apply_evaluation, emit_event_locked, evaluate_locked, next_record_number,
    require_name,
};
use crate::AuditEntry;
use crate::errors::{ForgeError, Result};
use crate::model::*;
use crate::webhooks::event_payload;

fn normalize_source_repository(
    owner: &str,
    repo: &str,
    source_repository: Option<String>,
) -> String {
    source_repository
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("{owner}/{repo}"))
}

/// Outcome of the read-only merge-gate phase ([`ForgeCore::evaluate_merge_readiness`]).
///
/// This is the seam that lets `jeryu-api` run a real git merge after the gate
/// passes without `jeryu-core` ever depending on the git backend: core
/// discloses the base/head shas to merge, and the handler computes the real
/// merge sha and feeds it back through [`ForgeCore::finalize_merge`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeReadiness {
    /// The PR passed branch protection and is ready to merge.
    Ready {
        /// Base branch name (e.g. `main`).
        base_ref: String,
        /// Current base tip sha to merge into.
        base_sha: String,
        /// Head branch name (e.g. `feature`). The caller resolves this live
        /// against the git backend so a stale stored head sha cannot stop a
        /// merge whose code is already on the branch.
        head_ref: String,
        /// Head sha to merge.
        head_sha: String,
        /// Whether the base requires linear history; the caller must refuse a
        /// non-fast-forward merge when this is set.
        require_linear_history: bool,
    },
    /// The PR is already merged; the recorded merge sha is returned for idempotency.
    AlreadyMerged {
        /// The recorded (or fallback head) sha.
        sha: String,
    },
}

impl ForgeCore {
    pub fn create_pull_request(
        &self,
        owner: &str,
        repo: &str,
        author: &str,
        request: CreatePullRequestRequest,
    ) -> Result<PullRequest> {
        require_name("pull request title", &request.title)?;
        require_name("head", &request.head)?;
        require_name("base", &request.base)?;
        self.ensure_repository_writable(owner, repo)?;
        self.ensure_user(author);
        let mut state = self.state.write();
        let previous = state.clone();
        // A PR is an issue: one number, one record pair.
        let pull_number = next_record_number(&mut state, owner, repo);
        let issue_number = pull_number;
        let now = Utc::now();
        let issue = Issue {
            id: Uuid::new_v4(),
            owner: owner.to_string(),
            repo: repo.to_string(),
            number: issue_number,
            title: request.title.clone(),
            body: request.body.clone(),
            state: IssueState::Open,
            author: author.to_string(),
            labels: Vec::new(),
            assignees: Vec::new(),
            milestone: None,
            comments: 0,
            pull_request: Some(PullRequestMarker {
                url: format!("/repos/{owner}/{repo}/pulls/{pull_number}"),
                html_url: format!("/{owner}/{repo}/pull/{pull_number}"),
            }),
            created_at: now,
            updated_at: now,
            closed_at: None,
        };
        let mut pr = PullRequest {
            id: Uuid::new_v4(),
            owner: owner.to_string(),
            repo: repo.to_string(),
            number: pull_number,
            issue_number,
            title: request.title,
            body: request.body,
            state: if request.draft {
                PullRequestState::Draft
            } else {
                PullRequestState::Open
            },
            draft: request.draft,
            author: author.to_string(),
            source_repository: normalize_source_repository(owner, repo, request.source_repository),
            head: GitBranchRef::new(
                request.head,
                request
                    .head_sha
                    .unwrap_or_else(|| format!("head-{pull_number}")),
            ),
            base: GitBranchRef::new(
                request.base,
                request.base_sha.unwrap_or_else(|| "base".to_string()),
            ),
            mergeable: false,
            mergeable_state: "unknown".to_string(),
            merged: false,
            merged_at: None,
            merge_commit_sha: None,
            commits: request.commits,
            changed_files: request.changed_files,
            created_at: now,
            updated_at: now,
        };
        let evaluation = evaluate_locked(&state, &pr, None);
        apply_evaluation(&mut pr, evaluation);
        state
            .issues
            .insert((owner.to_string(), repo.to_string(), issue_number), issue);
        state.pulls.insert(
            (owner.to_string(), repo.to_string(), pull_number),
            pr.clone(),
        );
        emit_event_locked(
            &mut state,
            owner,
            repo,
            "pull_request",
            event_payload("opened", "pull_request", json!(pr.clone())),
        );
        self.persist_after_mutation(&mut state, previous)?;
        Ok(pr)
    }

    pub fn list_pull_requests(
        &self,
        owner: &str,
        repo: &str,
        state_filter: Option<PullRequestState>,
    ) -> Result<Vec<PullRequest>> {
        self.ensure_repo_exists(owner, repo)?;
        let state = self.state.read();
        let mut pulls: Vec<_> = state
            .pulls
            .values()
            .filter(|pr| pr.owner == owner && pr.repo == repo)
            .filter(|pr| {
                state_filter
                    .as_ref()
                    .is_none_or(|filter| &pr.state == filter)
            })
            .map(|pr| {
                let mut pr = pr.clone();
                let evaluation = evaluate_locked(&state, &pr, None);
                apply_evaluation(&mut pr, evaluation);
                pr
            })
            .collect();
        pulls.sort_by_key(|pr| pr.number);
        Ok(pulls)
    }

    pub fn get_pull_request(&self, owner: &str, repo: &str, number: u64) -> Result<PullRequest> {
        let state = self.state.read();
        let mut pr = match state
            .pulls
            .get(&(owner.to_string(), repo.to_string(), number))
            .cloned()
        {
            Some(pr) => pr,
            None => {
                return Err(ForgeError::NotFound(format!(
                    "pull request {owner}/{repo}#{number}"
                )));
            }
        };
        let evaluation = evaluate_locked(&state, &pr, None);
        apply_evaluation(&mut pr, evaluation);
        Ok(pr)
    }

    pub fn update_pull_request(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
        request: UpdatePullRequestRequest,
    ) -> Result<PullRequest> {
        self.ensure_repository_writable(owner, repo)?;
        let mut state = self.state.write();
        let previous = state.clone();
        let key = (owner.to_string(), repo.to_string(), number);
        let pr = match state.pulls.get_mut(&key) {
            Some(pr) => pr,
            None => {
                return Err(ForgeError::NotFound(format!(
                    "pull request {owner}/{repo}#{number}"
                )));
            }
        };
        if let Some(title) = request.title {
            require_name("pull request title", &title)?;
            pr.title = title;
        }
        if request.body.is_some() {
            pr.body = request.body;
        }
        if let Some(draft) = request.draft {
            pr.draft = draft;
            pr.state = if draft {
                PullRequestState::Draft
            } else {
                PullRequestState::Open
            };
        }
        if let Some(state_update) = request.state {
            pr.state = state_update;
            pr.draft = pr.state == PullRequestState::Draft;
        }
        if let Some(commits) = request.commits {
            pr.commits = commits;
        }
        if let Some(changed_files) = request.changed_files {
            pr.changed_files = changed_files;
        }
        pr.updated_at = Utc::now();
        let mut updated = pr.clone();
        let evaluation = evaluate_locked(&state, &updated, None);
        apply_evaluation(&mut updated, evaluation);
        state.pulls.insert(key, updated.clone());
        emit_event_locked(
            &mut state,
            owner,
            repo,
            "pull_request",
            event_payload("edited", "pull_request", json!(updated.clone())),
        );
        self.persist_after_mutation(&mut state, previous)?;
        Ok(updated)
    }

    pub fn refresh_pull_request_heads_for_ref(
        &self,
        owner: &str,
        repo: &str,
        ref_name: &str,
        head_sha: &str,
    ) -> Result<Vec<PullRequest>> {
        self.ensure_repo_exists(owner, repo)?;
        let mut state = self.state.write();
        let previous = state.clone();
        let now = Utc::now();
        let keys: Vec<_> = state
            .pulls
            .iter()
            .filter_map(|(key, pr)| {
                let open = !pr.merged
                    && !matches!(
                        pr.state,
                        PullRequestState::Closed | PullRequestState::Merged
                    );
                if pr.owner == owner && pr.repo == repo && pr.head.ref_name == ref_name && open {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();
        if keys.is_empty() {
            return Ok(Vec::new());
        }

        let mut updated = Vec::new();
        for key in keys {
            if let Some(pr) = state.pulls.get_mut(&key) {
                pr.head.sha = head_sha.to_string();
                pr.updated_at = now;
            }
            let Some(mut pr) = state.pulls.get(&key).cloned() else {
                continue;
            };
            let evaluation = evaluate_locked(&state, &pr, None);
            apply_evaluation(&mut pr, evaluation);
            state.pulls.insert(key, pr.clone());
            emit_event_locked(
                &mut state,
                owner,
                repo,
                "pull_request",
                event_payload("synchronize", "pull_request", json!(pr.clone())),
            );
            updated.push(pr);
        }
        self.persist_after_mutation(&mut state, previous)?;
        Ok(updated)
    }

    /// Record `base_sha` as the base of open pull request `number`, whose head
    /// is still `head_sha`. The base is otherwise the tip seen when the pull
    /// request was opened, so after the author rebases onto a newer base its
    /// diff, and every review of that diff, would include commits that are
    /// already on the base.
    ///
    /// Core holds no git objects, so it cannot compute or check a merge base:
    /// the caller passes the merge base of `head_sha` with the base branch,
    /// computed from the repository (`jeryu_gitd::merge_base`). Core refuses
    /// what it can check: a head that moved on, a pull request that is not
    /// open, an archived repository, a value that is not a full object id,
    /// and a base equal to the head (an empty diff). The move is announced as
    /// an `edited` pull_request event and appended to the audit log as
    /// `pull_request.base_recorded` by `actor`.
    pub fn record_pull_request_base(
        &self,
        actor: &str,
        owner: &str,
        repo: &str,
        number: u64,
        head_sha: &str,
        base_sha: &str,
    ) -> Result<PullRequest> {
        if !(matches!(base_sha.len(), 40 | 64) && base_sha.bytes().all(|b| b.is_ascii_hexdigit())) {
            return Err(ForgeError::Validation(
                "base sha must be 40 or 64 hex digits".to_string(),
            ));
        }
        if base_sha.eq_ignore_ascii_case(head_sha) {
            return Err(ForgeError::Validation(
                "base sha must not be the head: that diff is empty".to_string(),
            ));
        }
        self.ensure_repo_exists(owner, repo)?;
        self.ensure_repository_writable(owner, repo)?;
        let (previous_base, updated) = {
            let mut state = self.state.write();
            let previous = state.clone();
            let key = (owner.to_string(), repo.to_string(), number);
            let Some(pr) = state.pulls.get(&key) else {
                return Err(ForgeError::NotFound(format!(
                    "pull request {owner}/{repo}#{number}"
                )));
            };
            if pr.merged
                || matches!(
                    pr.state,
                    PullRequestState::Closed | PullRequestState::Merged
                )
            {
                return Err(ForgeError::Conflict(format!(
                    "pull request {owner}/{repo}#{number} is not open"
                )));
            }
            if pr.head.sha != head_sha {
                return Err(ForgeError::Conflict(format!(
                    "pull request {owner}/{repo}#{number} head changed"
                )));
            }
            if pr.base.sha == base_sha {
                return Ok(pr.clone());
            }
            let previous_base = pr.base.sha.clone();
            let mut updated = pr.clone();
            updated.base.sha = base_sha.to_string();
            updated.updated_at = Utc::now();
            let evaluation = evaluate_locked(&state, &updated, None);
            apply_evaluation(&mut updated, evaluation);
            state.pulls.insert(key, updated.clone());
            emit_event_locked(
                &mut state,
                owner,
                repo,
                "pull_request",
                event_payload("edited", "pull_request", json!(updated.clone())),
            );
            self.persist_after_mutation(&mut state, previous)?;
            (previous_base, updated)
        };
        self.append_audit_as(
            actor,
            "pull_request.base_recorded",
            &format!("{owner}/{repo}"),
            "completed",
            json!({
                "number": number,
                "head_sha": head_sha,
                "from": previous_base,
                "to": base_sha,
            }),
        )?;
        Ok(updated)
    }

    /// Read-only merge-gate phase: evaluate branch protection and, on success,
    /// disclose the base/head shas the caller should merge.
    ///
    /// This is the FIRST half of the two-phase merge. It performs NO state
    /// mutation and never touches git. On an unmergeable PR it returns
    /// `Err(BranchProtection)` so the caller short-circuits before constructing
    /// any git ref move. The caller then computes the real merge sha and feeds
    /// it back through [`ForgeCore::finalize_merge`].
    pub fn evaluate_merge_readiness(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
        requested_sha: Option<&str>,
    ) -> Result<MergeReadiness> {
        let state = self.state.read();
        let key = (owner.to_string(), repo.to_string(), number);
        let pr = match state.pulls.get(&key).cloned() {
            Some(pr) => pr,
            None => {
                return Err(ForgeError::NotFound(format!(
                    "pull request {owner}/{repo}#{number}"
                )));
            }
        };
        if pr.merged {
            return Ok(MergeReadiness::AlreadyMerged {
                sha: match pr.merge_commit_sha.clone() {
                    Some(sha) => sha,
                    None => pr.head.sha.clone(),
                },
            });
        }
        if pr.state == PullRequestState::Closed {
            return Err(ForgeError::Validation(
                "closed pull requests cannot be merged".to_string(),
            ));
        }
        let evaluation = evaluate_locked(&state, &pr, requested_sha);
        if !evaluation.mergeable {
            return Err(ForgeError::BranchProtection(format!(
                "{:?}",
                evaluation.blockers
            )));
        }
        let require_linear_history = state
            .branch_protections
            .get(&(
                owner.to_string(),
                repo.to_string(),
                pr.base.ref_name.clone(),
            ))
            .is_some_and(|rule| rule.required_linear_history);
        Ok(MergeReadiness::Ready {
            base_ref: pr.base.ref_name.clone(),
            base_sha: pr.base.sha.clone(),
            head_ref: pr.head.ref_name.clone(),
            head_sha: pr.head.sha.clone(),
            require_linear_history,
        })
    }

    /// Commit phase: persist `merge_sha` as the PR's real merge commit.
    ///
    /// This is the SECOND half of the two-phase merge. It re-acquires the write
    /// lock, re-looks-up the PR, RE-EVALUATES the gate (TOCTOU defense), then
    /// applies the merge state mutation with the PASSED-IN `merge_sha` (the real
    /// git oid the caller produced), closes the backing issue, emits the
    /// `pull_request` closed webhook, and persists.
    ///
    /// On a TOCTOU re-eval failure after a ref already moved, this returns the
    /// error WITHOUT rolling back the ref; the divergence (git ahead of
    /// metadata) is detectable by a reconciler comparing `merge_commit_sha`
    /// against the live ref.
    pub fn finalize_merge(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
        merge_sha: String,
        requested_sha: Option<&str>,
    ) -> Result<MergeResult> {
        self.finalize_merge_checked(owner, repo, number, merge_sha, requested_sha, None)
    }

    /// Finalize a real Git merge authorized by an exact-state override permit.
    /// The API must authenticate the actor and validate its own passport hash
    /// before preparing the permit. Core rechecks grants, protection and its
    /// full gate snapshot here; no protection settings are changed.
    pub fn finalize_merge_with_override(
        &self,
        permit: MergeOverridePermit,
        merge_sha: String,
    ) -> Result<MergeResult> {
        let result = self.finalize_merge_checked(
            &permit.owner,
            &permit.repo,
            permit.number,
            merge_sha,
            Some(&permit.head_sha),
            Some(&permit),
        );
        if let Err(error) = &result {
            let mut detail = permit.audit_detail(None);
            detail["error"] = serde_json::Value::String(error.to_string());
            self.append_audit_as(
                &permit.actor,
                "pull.merge_override",
                &permit.subject(),
                "failed",
                detail,
            )?;
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn finalize_merge_checked(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
        merge_sha: String,
        requested_sha: Option<&str>,
        override_permit: Option<&MergeOverridePermit>,
    ) -> Result<MergeResult> {
        self.ensure_repository_writable(owner, repo)?;
        let mut state = self.state.write();
        let previous = state.clone();
        let key = (owner.to_string(), repo.to_string(), number);
        let pr_snapshot = match state.pulls.get(&key).cloned() {
            Some(pr) => pr,
            None => {
                return Err(ForgeError::NotFound(format!(
                    "pull request {owner}/{repo}#{number}"
                )));
            }
        };
        if pr_snapshot.merged {
            if override_permit.is_some() {
                return Err(ForgeError::Conflict(
                    "override target already merged".into(),
                ));
            }
            return Ok(MergeResult {
                sha: match pr_snapshot.merge_commit_sha.clone() {
                    Some(sha) => sha,
                    None => merge_sha.clone(),
                },
                merged: true,
                message: "Pull Request already merged".to_string(),
            });
        }
        if pr_snapshot.state == PullRequestState::Closed {
            return Err(ForgeError::Validation(
                "closed pull requests cannot be merged".to_string(),
            ));
        }
        // Re-evaluate under the write lock to close the readiness->finalize
        // TOCTOU window.
        let evaluation = evaluate_locked(&state, &pr_snapshot, requested_sha);
        if let Some(permit) = override_permit {
            validate_override(&state, &pr_snapshot, &permit.actor)?;
            if Utc::now().timestamp() > permit.expires_at {
                return Err(ForgeError::Conflict("merge override permit expired".into()));
            }
            let evidence = validate_override_evaluation(
                &state,
                &pr_snapshot,
                &permit.protection,
                &evaluation,
            )?;
            if evidence != permit.status_evidence {
                return Err(ForgeError::Conflict(
                    "override status evidence changed".into(),
                ));
            }
            if pr_snapshot.head.sha != permit.head_sha
                || pr_snapshot.base.sha != permit.base_sha
                || evaluation != permit.evaluation
                || state.branch_protections.get(&(
                    owner.to_string(),
                    repo.to_string(),
                    pr_snapshot.base.ref_name.clone(),
                )) != Some(&permit.protection)
            {
                return Err(ForgeError::Conflict(
                    "merge override gate changed; refresh and record a new decision".to_string(),
                ));
            }
        } else if !evaluation.mergeable {
            return Err(ForgeError::BranchProtection(format!(
                "{:?}",
                evaluation.blockers
            )));
        }
        let mut pr = pr_snapshot;
        pr.merged = true;
        pr.state = PullRequestState::Merged;
        pr.mergeable = false;
        pr.mergeable_state = "merged".to_string();
        pr.merged_at = Some(Utc::now());
        pr.merge_commit_sha = Some(merge_sha.clone());
        pr.updated_at = Utc::now();
        state.pulls.insert(key, pr.clone());
        if let Some(issue) =
            state
                .issues
                .get_mut(&(owner.to_string(), repo.to_string(), pr.issue_number))
        {
            issue.state = IssueState::Closed;
            issue.closed_at = Some(Utc::now());
            issue.updated_at = Utc::now();
        }
        emit_event_locked(
            &mut state,
            owner,
            repo,
            "pull_request",
            event_payload("closed", "pull_request", json!(pr)),
        );
        if let Some(permit) = override_permit {
            let entry = AuditEntry {
                id: Uuid::new_v4().to_string(),
                occurred_at: Utc::now().to_rfc3339(),
                actor: permit.actor.clone(),
                action: "pull.merge_override".into(),
                subject: permit.subject(),
                phase: "completed".into(),
                detail: permit.audit_detail(Some(&merge_sha)),
            };
            let persisted = self
                .storage
                .as_ref()
                .ok_or_else(|| {
                    ForgeError::Validation("merge override requires durable audit storage".into())
                })
                .and_then(|storage| storage.persist_with_audit(&state, &entry));
            if let Err(error) = persisted {
                *state = previous;
                return Err(error);
            }
        } else {
            self.persist_after_mutation(&mut state, previous)?;
        }
        Ok(MergeResult {
            sha: merge_sha,
            merged: true,
            message: "Pull Request successfully merged".to_string(),
        })
    }

    /// Git-less merge: evaluate readiness, then finalize with a synthetic
    /// merge sha. Preserved for callers without a git backend (unit tests, the
    /// `repo_manager`-less handler fallback). Real, ref-advancing merges go
    /// through the [`ForgeCore::evaluate_merge_readiness`] +
    /// [`ForgeCore::finalize_merge`] pair driven by the API handler.
    pub fn merge_pull_request(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
        request: MergePullRequestRequest,
    ) -> Result<MergeResult> {
        self.ensure_repository_writable(owner, repo)?;
        match self.evaluate_merge_readiness(owner, repo, number, request.sha.as_deref())? {
            MergeReadiness::AlreadyMerged { sha } => Ok(MergeResult {
                sha,
                merged: true,
                message: "Pull Request already merged".to_string(),
            }),
            MergeReadiness::Ready { head_sha, .. } => {
                let merge_sha = format!("merge-{head_sha}-{number}");
                self.finalize_merge(owner, repo, number, merge_sha, request.sha.as_deref())
            }
        }
    }
}
