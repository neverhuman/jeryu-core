//! Pull requests, reviews, and merges.

use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

pub use super::merge_overrides::{MergeOverridePermit, MergeOverrideRequest, MergeOverrideTarget};
use super::merge_overrides::{validate_override, validate_override_evaluation};
use super::{
    ForgeCore, apply_evaluation, emit_event_locked, evaluate_locked, next_record_number,
    require_name,
};
use crate::AuditEntry;
use crate::branch_protection::effective_reviews_for_head;
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

/// Most commits a pull request's recorded diff identity may cover. A digest
/// list is attacker-influenced in size (a pusher chooses how many commits it
/// sends), so the stored list is bounded rather than growing with the branch.
const MAX_HEAD_PATCH_IDS: usize = jeryu_gitd::patch_id::MAX_COMMITS;

/// Bound and validate digests computed from repository objects.
fn validate_patch_ids(patch_ids: &[String]) -> Result<()> {
    if patch_ids.len() > MAX_HEAD_PATCH_IDS {
        return Err(ForgeError::Validation(format!(
            "a diff identity covers at most {MAX_HEAD_PATCH_IDS} commits"
        )));
    }
    for id in patch_ids {
        if !jeryu_gitd::patch_id::is_review_patch_id(id) {
            return Err(ForgeError::Validation(
                "patch ids must be v2-tagged SHA-256 digests".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_diff_base(base_sha: &str) -> Result<()> {
    if matches!(base_sha.len(), 40 | 64) && base_sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ForgeError::Validation(
            "base sha must be 40 or 64 hex digits".to_string(),
        ))
    }
}

/// Whether any approval on the pull request still stands at a head it was
/// given at: not withdrawn by its author and not replaced by a later verdict
/// of the same reviewer at that head. Such an approval counts again whenever
/// the head returns there, whatever the base is then.
fn standing_approval(reviews: &[Review]) -> bool {
    let heads: std::collections::BTreeSet<&str> = reviews
        .iter()
        .filter(|review| review.state == ReviewState::Approved)
        .filter_map(|review| review.head_sha.as_deref())
        .collect();
    heads.into_iter().any(|head| {
        effective_reviews_for_head(reviews, head)
            .iter()
            .any(|review| review.state == ReviewState::Approved)
    })
}

struct HeadEvidence<'a> {
    base_sha: &'a str,
    patch_ids: &'a [String],
    commits: Option<&'a [PullRequestCommit]>,
}

/// Outcome of the read-only merge-gate phase ([`ForgeCore::evaluate_merge_readiness`]).
///
/// This is the seam that lets `jeryu-api` run a real git merge after the gate
/// passes while keeping merge execution in the adapter: Core
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

/// The base a two-phase merge was evaluated and performed against: the
/// `base_ref` and `base_sha` of [`MergeReadiness::Ready`], handed back to
/// [`ForgeCore::finalize_merge`]. Finalizing refuses when the pull request's
/// base has moved since (a retarget or a recorded base), so a merge into one
/// branch is never authorized by another branch's protection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeBase {
    pub base_ref: String,
    pub base_sha: String,
}

impl MergeReadiness {
    /// The base to hand back to [`ForgeCore::finalize_merge`]: exactly what
    /// this readiness disclosed. `None` for an already merged pull request.
    /// Never rebuild it from a fresh read of the pull request; that would
    /// compare the base with itself and void the check.
    pub fn merge_base(&self) -> Option<MergeBase> {
        match self {
            Self::Ready {
                base_ref, base_sha, ..
            } => Some(MergeBase {
                base_ref: base_ref.clone(),
                base_sha: base_sha.clone(),
            }),
            Self::AlreadyMerged { .. } => None,
        }
    }
}

/// What one finalize call binds: the merge sha it records, the head it was
/// asked for, and the base it was evaluated against.
pub(super) struct FinalizeBinding<'a> {
    merge_sha: String,
    requested_sha: Option<&'a str>,
    base: &'a MergeBase,
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
        // Validated as stored: `refs/heads/` alone normalizes to nothing.
        require_name("base", normalize_base_ref(&request.base))?;
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
            // Stored without a `refs/heads/` prefix, the form branch
            // protection and per-base statuses are keyed by.
            base: GitBranchRef::new(
                normalize_base_ref(&request.base),
                request.base_sha.unwrap_or_else(|| "base".to_string()),
            ),
            mergeable: false,
            mergeable_state: "unknown".to_string(),
            merged: false,
            merged_at: None,
            merge_commit_sha: None,
            commits: request.commits,
            changed_files: request.changed_files,
            head_patch_ids: Vec::new(),
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
        // Validated before the first mutation: this function edits the stored
        // pull request in place, so a refusal after a field was already set
        // would leave the in-memory record ahead of the store it is never
        // persisted to.
        if let Some(title) = request.title.as_deref() {
            require_name("pull request title", title)?;
        }
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
        self.refresh_pull_request_heads_with_identity(
            owner,
            repo,
            ref_name,
            head_sha,
            HeadEvidence {
                base_sha: "",
                patch_ids: &[],
                commits: None,
            },
        )
    }

    /// Refresh without trusting caller-supplied diff identities. Nonempty lists
    /// are refused; use `refresh_pull_request_heads_from_git` to compute one.
    pub fn refresh_pull_request_heads_for_ref_with_diff(
        &self,
        owner: &str,
        repo: &str,
        ref_name: &str,
        head_sha: &str,
        base_sha: &str,
        head_patch_ids: &[String],
    ) -> Result<Vec<PullRequest>> {
        validate_patch_ids(head_patch_ids)?;
        validate_diff_base(base_sha)?;
        if !head_patch_ids.is_empty() {
            return Err(ForgeError::Validation(
                "diff identities must be computed from repository objects".to_string(),
            ));
        }
        self.refresh_pull_request_heads_with_identity(
            owner,
            repo,
            ref_name,
            head_sha,
            HeadEvidence {
                base_sha,
                patch_ids: &[],
                commits: None,
            },
        )
    }

    /// Compute the identity from git objects, then atomically refresh heads and
    /// protection. The path must come from the forge's git store. Accept a path
    /// rather than a gitd type so consumers can pin the two split tags separately.
    /// Callers cannot supply digest lists or select a command to compute them.
    pub fn refresh_pull_request_heads_from_git(
        &self,
        owner: &str,
        repo: &str,
        repository_path: &std::path::Path,
        ref_name: &str,
        head_sha: &str,
        base_sha: &str,
    ) -> Result<Vec<PullRequest>> {
        validate_diff_base(base_sha)?;
        let repository = jeryu_gitd::repo::Repository {
            id: jeryu_gitd::RepoId::new(owner, repo)
                .map_err(|error| ForgeError::Validation(error.to_string()))?,
            path: repository_path.to_path_buf(),
        };
        let ids =
            jeryu_gitd::patch_ids("git", &repository, base_sha, head_sha).map_err(|error| {
                ForgeError::Validation(format!("cannot compute diff identity: {error}"))
            })?;
        validate_patch_ids(&ids)?;
        let commits = jeryu_gitd::patch_id::review_commits("git", &repository, base_sha, head_sha)
            .map_err(|error| ForgeError::Validation(format!("cannot refresh commits: {error}")))?
            .into_iter()
            .map(|(sha, parents, verified)| PullRequestCommit {
                sha,
                parents,
                verified,
            })
            .collect::<Vec<_>>();
        self.refresh_pull_request_heads_with_identity(
            &repository.id.owner,
            &repository.id.name,
            ref_name,
            head_sha,
            HeadEvidence {
                base_sha,
                patch_ids: &ids,
                commits: Some(&commits),
            },
        )
    }

    fn refresh_pull_request_heads_with_identity(
        &self,
        owner: &str,
        repo: &str,
        ref_name: &str,
        head_sha: &str,
        evidence: HeadEvidence<'_>,
    ) -> Result<Vec<PullRequest>> {
        let HeadEvidence {
            base_sha,
            patch_ids: head_patch_ids,
            commits,
        } = evidence;
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
                if let Some(commits) =
                    commits.filter(|_| pr.base.sha.eq_ignore_ascii_case(base_sha))
                {
                    pr.commits = commits.to_vec();
                } else if commits.is_some() && pr.head.sha != head_sha {
                    // A computed range for another base cannot establish
                    // signatures or linear history for this pull request.
                    pr.commits = vec![PullRequestCommit {
                        sha: head_sha.to_string(),
                        verified: false,
                        parents: 2,
                    }];
                }
                pr.head.sha = head_sha.to_string();
                // The identity is a diff against `base_sha`: it describes only
                // a pull request recorded on that base. Any other pull request
                // from this branch gets an unknown identity, never a wrong one.
                pr.head_patch_ids = if pr.base.sha.eq_ignore_ascii_case(base_sha) {
                    head_patch_ids.to_vec()
                } else {
                    Vec::new()
                };
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

    /// Move open pull request `number` onto another base branch.
    ///
    /// The base decides which protection rule and which per-base results
    /// apply, so a retarget is held to what [`Self::record_pull_request_base`]
    /// enforces and more. Refused: an archived repository; a pull request that
    /// is not open, or whose head moved on from `head_sha`; a base that is
    /// blank, is the pull request's own head branch, or does not exist in git
    /// (`branches`); a `base_sha` that is not a full object id or equals the
    /// head; an empty commit range or changed-path list; and any approval that
    /// still counts (`Conflict`): an approval judged the diff against the old
    /// base, so its author dismisses it first and reviews the new diff. The
    /// caller's range for the new base replaces `commits` and `changed_files`,
    /// and the diff identity (`head_patch_ids`) is cleared because it was
    /// computed against the old base. The merge gate is re-evaluated at once,
    /// so results proved against the old base stop counting immediately, and
    /// an in-flight two-phase merge fails to finalize ([`MergeBase`]).
    /// Announced as an `edited` pull_request event and audited as
    /// `pull_request.retargeted` by `actor` in the same store transaction.
    pub fn retarget_pull_request(
        &self,
        actor: &str,
        owner: &str,
        repo: &str,
        number: u64,
        request: RetargetPullRequestRequest,
        branches: &dyn super::RepoBranches,
    ) -> Result<PullRequest> {
        let base = normalize_base_ref(&request.base).to_string();
        require_name("base", &base)?;
        validate_diff_base(&request.base_sha)?;
        if request.base_sha.eq_ignore_ascii_case(&request.head_sha) {
            return Err(ForgeError::Validation(
                "base sha must not be the head: that diff is empty".to_string(),
            ));
        }
        if request.commits.is_empty() || request.changed_files.is_empty() {
            return Err(ForgeError::Validation(
                "a retarget must carry the commit range and changed paths for its new base"
                    .to_string(),
            ));
        }
        if actor.trim().is_empty() {
            return Err(ForgeError::Validation(
                "audit actor cannot be empty".to_string(),
            ));
        }
        self.ensure_repository_writable(owner, repo)?;
        if !branches.branch_exists(owner, repo, &base)? {
            return Err(ForgeError::Validation(format!(
                "base branch {base} does not exist in {owner}/{repo}"
            )));
        }
        let updated = {
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
            if pr.head.sha != request.head_sha {
                return Err(ForgeError::Conflict(format!(
                    "pull request {owner}/{repo}#{number} head changed"
                )));
            }
            let same_repository = pr.source_repository.is_empty()
                || pr.source_repository == format!("{owner}/{repo}");
            if same_repository && pr.head.ref_name == base {
                return Err(ForgeError::Validation(format!(
                    "{base} is the head branch of pull request {owner}/{repo}#{number}"
                )));
            }
            // An approval is a verdict on the diff against the base it was
            // given for; it must not authorize a merge into another branch.
            // Nothing binds a verdict to a base, and a head can be rewound to
            // the one an approval was given at, so the check is not "counts
            // now" but "counts at any head it was given at": every approval
            // not withdrawn via `dismiss_review` holds the
            // retarget. Rejections may carry: they can only block.
            let reviews = state.reviews.get(&key).map(Vec::as_slice).unwrap_or(&[]);
            if standing_approval(reviews) {
                return Err(ForgeError::Conflict(format!(
                    "pull request {owner}/{repo}#{number} has approvals given against its current base; its reviewers must dismiss them before a retarget, or open a new pull request against the new base"
                )));
            }
            let previous_base = pr.base.clone();
            let mut updated = pr.clone();
            updated.base = GitBranchRef::new(base, request.base_sha);
            updated.commits = request.commits;
            updated.changed_files = request.changed_files;
            // The recorded identity was computed against the old base.
            updated.head_patch_ids = Vec::new();
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
            // The audit row is written in the same transaction as the move, so
            // a retarget never stands without its receipt.
            let entry = AuditEntry {
                id: Uuid::new_v4().to_string(),
                occurred_at: Utc::now().to_rfc3339(),
                actor: actor.to_string(),
                action: "pull_request.retargeted".into(),
                subject: format!("{owner}/{repo}"),
                phase: "completed".into(),
                detail: json!({
                    "number": number,
                    "head_sha": updated.head.sha,
                    "from_base": previous_base.ref_name,
                    "from_base_sha": previous_base.sha,
                    "to_base": updated.base.ref_name,
                    "to_base_sha": updated.base.sha,
                }),
            };
            if let Some(storage) = &self.storage
                && let Err(error) = storage.persist_with_audit(&state, &entry)
            {
                *state = previous;
                return Err(error);
            }
            updated
        };
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
            // The recorded identity was computed against the old base.
            updated.head_patch_ids = Vec::new();
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
    /// `base` must be the [`MergeReadiness::merge_base`] of the readiness the
    /// caller merged against; a base that moved since (a retarget or a
    /// recorded base) is refused with `Conflict`.
    ///
    /// On a TOCTOU re-eval failure or a moved base after a ref already moved,
    /// this returns the error WITHOUT rolling back the ref; the divergence
    /// (git ahead of metadata) is detectable by a reconciler comparing
    /// `merge_commit_sha` against the live ref. A retarget racing a merge is
    /// one more way to reach it, and is preferred over recording a merge
    /// judged by another branch's rule.
    pub fn finalize_merge(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
        merge_sha: String,
        requested_sha: Option<&str>,
        base: &MergeBase,
    ) -> Result<MergeResult> {
        let binding = FinalizeBinding {
            merge_sha,
            requested_sha,
            base,
        };
        self.finalize_merge_checked(owner, repo, number, binding, None)
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
        // The permit binds the base twice over: its sha here, and its ref
        // through the protection rule (whose `branch` is the base it guards).
        let base = MergeBase {
            base_ref: permit.protection.branch.clone(),
            base_sha: permit.base_sha.clone(),
        };
        let binding = FinalizeBinding {
            merge_sha,
            requested_sha: Some(&permit.head_sha),
            base: &base,
        };
        let result = self.finalize_merge_checked(
            &permit.owner,
            &permit.repo,
            permit.number,
            binding,
            Some(&permit),
        );
        if let Err(error) = &result {
            let mut detail = permit.audit_detail(None);
            detail["error"] = serde_json::Value::String(error.to_string());
            // The refusal reason is the diagnostic the edge needs to decide
            // whether to recover the Git ref, so a failure to append the
            // receipt never replaces it; the append error is recorded in a
            // best-effort second receipt instead.
            if let Err(audit_error) = self.append_audit_as(
                &permit.actor,
                "pull.merge_override",
                &permit.subject(),
                "failed",
                detail,
            ) {
                let _ = self.append_audit_as(
                    &permit.actor,
                    "pull.merge_override",
                    &permit.subject(),
                    "failed",
                    json!({
                        "pr_number": permit.number,
                        "stage": "finalize",
                        "error": error.to_string(),
                        "audit_error": audit_error.to_string(),
                    }),
                );
            }
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn finalize_merge_checked(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
        binding: FinalizeBinding<'_>,
        override_permit: Option<&MergeOverridePermit>,
    ) -> Result<MergeResult> {
        let FinalizeBinding {
            merge_sha,
            requested_sha,
            base,
        } = binding;
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
        // The caller merged into the base it was told about at readiness; a
        // retarget or recorded base since then means the gate below would
        // judge a different merge than the one git performed.
        if pr_snapshot.base.ref_name != base.base_ref || pr_snapshot.base.sha != base.base_sha {
            return Err(ForgeError::Conflict(format!(
                "pull request {owner}/{repo}#{number} base changed since readiness; re-evaluate"
            )));
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
                &permit.actor,
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
            MergeReadiness::Ready {
                head_sha,
                base_ref,
                base_sha,
                ..
            } => {
                let merge_sha = format!("merge-{head_sha}-{number}");
                let base = MergeBase { base_ref, base_sha };
                self.finalize_merge(
                    owner,
                    repo,
                    number,
                    merge_sha,
                    request.sha.as_deref(),
                    &base,
                )
            }
        }
    }
}
