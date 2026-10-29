//! Pull request reviews and review comments.
//!
//! A reviewer may always dismiss their own current verdict. Dismissing another
//! reviewer's verdict is an administrator decision bound by the same rules as
//! a merge override (`merge_overrides.rs`), checked under the same lock as the
//! head:
//!
//! - the actor is an active repository administrator (global admin role or an
//!   explicit Admin grant), never a team bot and never the pull request author;
//! - the base branch has a protection rule that opts in with
//!   `allow_merge_override` and does not set `enforce_admins`;
//! - separation of duties: the actor has no standing approval on the pull
//!   request, and after the dismissal the actor's approvals never count there
//!   (Core refuses new ones and branch protection ignores old ones);
//! - the core has durable storage: a `pull.review_dismissal` audit receipt is
//!   recorded as `requested` before the row is written, `completed` after, and
//!   `failed` for a refused attempt.
//!
//! Core records `DismissalAuthority::RepositoryAdmin` on such a row, and branch
//! protection honors a cross-author dismissal only with it. The original
//! verdict and its comments stay in history.
//!
//! The API edge must authenticate the actor (never accept an actor from the
//! request body), enforce credential scopes and repository access, and expose
//! `DismissReviewRequest` with a target review, exact head SHA and non-empty
//! reason. It must return head conflicts for refresh and expose both the original
//! verdict and dismissal actor/reason in review history. Transport routing and
//! UI actions are supplied by the consuming API/web release.

use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use super::{ForgeCore, apply_evaluation, emit_event_locked, evaluate_locked};
use crate::branch_protection::{
    VerdictReach, effective_reviews_for_head, effective_reviews_for_pull_request_with,
    is_cross_author_dismissal, withdrawn_verdicts,
};
use crate::errors::{ForgeError, Result};
use crate::model::*;
use crate::webhooks::event_payload;

impl ForgeCore {
    pub fn create_review(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
        author: &str,
        request: CreateReviewRequest,
    ) -> Result<Review> {
        if request.event == ReviewState::Dismissed {
            return Err(ForgeError::Validation(
                "use dismiss_review with a target review, exact head and reason".to_string(),
            ));
        }
        self.record_review(owner, repo, number, author, request, None)
    }

    /// The caller supplies an actor login; this method does not authenticate a
    /// credential. Transport and internal callers must establish actor custody.
    pub fn dismiss_review(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
        actor: &str,
        request: DismissReviewRequest,
    ) -> Result<Review> {
        if request.reason.trim().is_empty() {
            return Err(ForgeError::Validation(
                "review dismissal requires a non-empty reason".to_string(),
            ));
        }
        if request.expected_head_sha.len() != 40
            || !request
                .expected_head_sha
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(ForgeError::Validation(
                "review dismissal requires a full lowercase SHA-1 head".to_string(),
            ));
        }
        let target_id = request.review_id;
        let result = self.record_review(
            owner,
            repo,
            number,
            actor,
            CreateReviewRequest {
                body: Some(request.reason.clone()),
                event: ReviewState::Dismissed,
                comments: Vec::new(),
                expected_head_sha: Some(request.expected_head_sha),
            },
            Some(target_id),
        );
        if let Err(error) = &result {
            // A refused attempt on another reviewer's verdict is the probe
            // worth detecting, recorded like a refused merge override. The
            // receipt never masks the refusal.
            let target_author = self
                .state
                .read()
                .reviews
                .get(&(owner.to_string(), repo.to_string(), number))
                .and_then(|reviews| reviews.iter().find(|review| review.id == target_id))
                .map(|review| review.author.clone());
            if target_author.is_some_and(|target_author| target_author != actor) {
                let _ = self.append_audit_as(
                    if actor.trim().is_empty() {
                        "unknown"
                    } else {
                        actor
                    },
                    DISMISSAL_AUDIT_ACTION,
                    &format!("{owner}/{repo}#{number}"),
                    "failed",
                    json!({
                        "pr_number": number,
                        "review_id": target_id,
                        "reason": request.reason.trim(),
                        "error": error.to_string(),
                    }),
                );
            }
        }
        result
    }

    fn record_review(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
        author: &str,
        request: CreateReviewRequest,
        dismissed_review_id: Option<Uuid>,
    ) -> Result<Review> {
        self.ensure_repository_writable(owner, repo)?;
        super::auth::require_login(author)?;
        let mut state = self.state.write();
        let key = (owner.to_string(), repo.to_string(), number);
        let (head_sha, head_patch_ids, pr_now) = match state.pulls.get(&key) {
            Some(pr) => {
                if request.event == ReviewState::Approved && pr.author.eq_ignore_ascii_case(author)
                {
                    return Err(ForgeError::Forbidden(
                        "pull request authors cannot approve their own changes".to_string(),
                    ));
                }
                if request.event == ReviewState::Approved
                    && state.reviews.get(&key).is_some_and(|reviews| {
                        reviews.iter().any(|review| {
                            review.author.eq_ignore_ascii_case(author)
                                && is_cross_author_dismissal(reviews, review)
                        })
                    })
                {
                    return Err(ForgeError::Forbidden(
                        "an administrator who dismissed another reviewer's verdict cannot approve this pull request"
                            .to_string(),
                    ));
                }
                if request
                    .expected_head_sha
                    .as_deref()
                    .is_some_and(|expected| expected != pr.head.sha)
                {
                    return Err(ForgeError::Conflict(format!(
                        "pull request {owner}/{repo}#{number} head changed"
                    )));
                }
                (pr.head.sha.clone(), pr.head_patch_ids.clone(), pr.clone())
            }
            None => {
                return Err(ForgeError::NotFound(format!(
                    "pull request {owner}/{repo}#{number}"
                )));
            }
        };
        let mut dismissal_authority = None;
        if let Some(target_id) = dismissed_review_id {
            let reviews = state.reviews.get(&key).map(Vec::as_slice).unwrap_or(&[]);
            let target = reviews
                .iter()
                .find(|review| review.id == target_id)
                .ok_or_else(|| {
                    ForgeError::NotFound(format!("review {target_id} in {owner}/{repo}#{number}"))
                })?;
            if target.author != author {
                authorize_cross_author_dismissal(&state, &pr_now, reviews, author)?;
                if self.storage.is_none() {
                    return Err(ForgeError::Validation(
                        "dismissing another reviewer requires durable audit storage".to_string(),
                    ));
                }
                dismissal_authority = Some(DismissalAuthority::RepositoryAdmin);
            }
            if !matches!(
                target.state,
                ReviewState::Approved | ReviewState::ChangesRequested
            ) {
                return Err(ForgeError::Validation(
                    "dismissal target must be an explicit review verdict".to_string(),
                ));
            }
            // The verdict may be counting at this head either because it was
            // written here or because it carries over an unchanged diff.
            // Withdrawing either is always allowed: it can only remove an
            // approval or a rejection, never add one.
            let counting_here = effective_reviews_for_head(reviews, &head_sha)
                .iter()
                .any(|review| review.id == target_id)
                || effective_reviews_for_pull_request_with(
                    reviews,
                    &pr_now,
                    VerdictReach::UnchangedDiff,
                )
                .iter()
                .any(|review| review.id == target_id);
            if !counting_here {
                return Err(ForgeError::Conflict(
                    "dismissal target is not the reviewer's current-head verdict".to_string(),
                ));
            }
        }
        let review_id = Uuid::new_v4();
        let audit = dismissal_authority.map(|_| {
            (
                format!("{owner}/{repo}#{number}"),
                json!({
                    "pr_number": number,
                    "dismissal_id": review_id,
                    "review_id": dismissed_review_id,
                    "head_sha": head_sha,
                    "reason": request.body.as_deref().map(str::trim),
                    "authority": dismissal_authority,
                }),
            )
        });
        if let Some((subject, detail)) = &audit {
            // Bound before the row exists: no administrator dismissal is
            // written without its receipt.
            self.append_audit_as(
                author,
                DISMISSAL_AUDIT_ACTION,
                subject,
                "requested",
                detail.clone(),
            )?;
        }
        let previous = state.clone();
        // Preserve the existing trusted-caller profile behavior in the same
        // transaction as the review. A profile is not an authenticated account.
        state
            .users
            .entry(author.to_string())
            .or_insert_with(|| User {
                id: Uuid::new_v4(),
                login: author.to_string(),
                name: None,
                email: None,
                created_at: Utc::now(),
            });
        let review = Review {
            id: review_id,
            owner: owner.to_string(),
            repo: repo.to_string(),
            pull_number: number,
            author: author.to_string(),
            state: request.event,
            body: request.body,
            head_sha: Some(head_sha),
            head_patch_ids,
            dismissed_review_id,
            dismissal_authority,
            submitted_at: Utc::now(),
        };
        let comments: Vec<_> = request
            .comments
            .into_iter()
            .map(|comment| ReviewComment {
                id: Uuid::new_v4(),
                review_id,
                owner: owner.to_string(),
                repo: repo.to_string(),
                pull_number: number,
                path: comment.path,
                line: comment.line,
                author: author.to_string(),
                body: comment.body,
                created_at: Utc::now(),
            })
            .collect();
        state
            .reviews
            .entry((owner.to_string(), repo.to_string(), number))
            .or_default()
            .push(review.clone());
        state
            .review_comments
            .entry((owner.to_string(), repo.to_string(), number))
            .or_default()
            .extend(comments);
        if let Some(pr) = state
            .pulls
            .get(&(owner.to_string(), repo.to_string(), number))
            .cloned()
        {
            let mut updated = pr;
            let evaluation = evaluate_locked(&state, &updated, None);
            apply_evaluation(&mut updated, evaluation);
            state
                .pulls
                .insert((owner.to_string(), repo.to_string(), number), updated);
        }
        emit_event_locked(
            &mut state,
            owner,
            repo,
            "pull_request_review",
            event_payload("submitted", "review", json!(review.clone())),
        );
        self.persist_after_mutation(&mut state, previous)?;
        drop(state);
        if let Some((subject, detail)) = audit {
            // The row is durable; a missing `completed` beside its `requested`
            // receipt is visible in the trail, so it does not undo the write.
            let _ = self.append_audit_as(
                author,
                DISMISSAL_AUDIT_ACTION,
                &subject,
                "completed",
                detail,
            );
        }
        Ok(review)
    }

    pub fn list_reviews(&self, owner: &str, repo: &str, number: u64) -> Result<Vec<Review>> {
        self.get_pull_request(owner, repo, number)?;
        // The PR exists (checked above); a missing reviews entry just means it
        // has no reviews yet, so an empty list is the intended value.
        Ok(
            match self
                .state
                .read()
                .reviews
                .get(&(owner.to_string(), repo.to_string(), number))
            {
                Some(reviews) => reviews.clone(),
                None => Vec::new(),
            },
        )
    }

    pub fn list_review_comments(
        &self,
        owner: &str,
        repo: &str,
        number: u64,
    ) -> Result<Vec<ReviewComment>> {
        self.get_pull_request(owner, repo, number)?;
        // The PR exists (checked above); a missing review-comments entry just
        // means it has no review comments yet, so an empty list is intended.
        Ok(
            match self.state.read().review_comments.get(&(
                owner.to_string(),
                repo.to_string(),
                number,
            )) {
                Some(comments) => comments.clone(),
                None => Vec::new(),
            },
        )
    }
}

/// Audit action for an administrator's dismissal of another reviewer's verdict.
const DISMISSAL_AUDIT_ACTION: &str = "pull.review_dismissal";

/// The rules for withdrawing another reviewer's verdict: the same binding as
/// a merge override (`merge_overrides::validate_override`). An administrator
/// who may not override the merge gate may not clear its review holds either.
fn authorize_cross_author_dismissal(
    state: &super::State,
    pr: &PullRequest,
    reviews: &[Review],
    actor: &str,
) -> Result<()> {
    // A human administrator's decision; a team bot's acting login never takes
    // one, even where its grants would allow repository admin.
    let admin = parse_team_bot_login(actor).is_none()
        && super::auth::repo_access_for_locked(state, actor, &pr.owner, &pr.repo)
            .is_some_and(RepoAccessLevel::allows_admin);
    if !admin {
        return Err(ForgeError::Forbidden(
            "dismissing another reviewer requires an active repository administrator".to_string(),
        ));
    }
    let protection = state
        .branch_protections
        .get(&(pr.owner.clone(), pr.repo.clone(), pr.base.ref_name.clone()))
        .filter(|rule| rule.allow_merge_override);
    let Some(protection) = protection else {
        return Err(ForgeError::Forbidden(
            "dismissing another reviewer requires explicit allow_merge_override=true".to_string(),
        ));
    };
    if protection.enforce_admins {
        return Err(ForgeError::Forbidden(
            "dismissing another reviewer is unavailable while the branch enforces administrators"
                .to_string(),
        ));
    }
    if pr.author.eq_ignore_ascii_case(actor) {
        return Err(ForgeError::Forbidden(
            "a pull request author cannot dismiss another reviewer's verdict on it".to_string(),
        ));
    }
    // Separation of duties: the deciding administrator may not also be a
    // reviewer whose approval stands on this pull request, at any head.
    let withdrawn = withdrawn_verdicts(reviews);
    if reviews.iter().any(|review| {
        review.state == ReviewState::Approved
            && review.author.eq_ignore_ascii_case(actor)
            && !withdrawn.contains(&review.id)
    }) {
        return Err(ForgeError::Forbidden(
            "an administrator with a standing approval cannot dismiss another reviewer's verdict"
                .to_string(),
        ));
    }
    Ok(())
}
