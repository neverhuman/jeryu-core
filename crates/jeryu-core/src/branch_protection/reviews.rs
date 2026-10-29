//! Current-head review selection shared by merge protection and readback.

use std::collections::BTreeMap;

use crate::model::{BranchProtectionRule, PullRequest, Review, ReviewState};

/// Which heads a verdict can speak for.
///
/// `ExactHead` is the strict rule: a verdict counts on the head it was written
/// against and nowhere else. `UnchangedDiff` also accepts a verdict written
/// against an earlier head whose diff was the same — equal per-commit patch
/// ids, so a rewrite with the same base, messages, and diff bytes keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictReach {
    ExactHead,
    UnchangedDiff,
}

impl VerdictReach {
    /// The reach a branch-protection rule asks for. Both settings are opt-outs
    /// of the strict rule, so a rule that asks for either strictness gets it;
    /// no rule at all is strict.
    pub fn for_rule(rule: Option<&BranchProtectionRule>) -> Self {
        match rule {
            Some(rule) if !rule.dismiss_stale_approvals && !rule.require_exact_sha_approval => {
                Self::UnchangedDiff
            }
            _ => Self::ExactHead,
        }
    }
}

/// Return at most one effective review per reviewer for `head_sha`.
///
/// Historical reviews without a recorded head and reviews recorded at another
/// head are audit history only. Comments preserve explicit verdicts. A targeted
/// dismissal clears its current verdict without recovering an earlier one.
/// Core appends reviews to this slice, and SQLite restores it in row order.
pub fn effective_reviews_for_head<'a>(reviews: &'a [Review], head_sha: &str) -> Vec<&'a Review> {
    reduce_reviews(reviews, head_sha, &[], VerdictReach::ExactHead, None)
}

fn reduce_reviews<'a>(
    reviews: &'a [Review],
    head_sha: &str,
    head_patch_ids: &[String],
    reach: VerdictReach,
    pr_author: Option<&str>,
) -> Vec<&'a Review> {
    // A head whose diff identity is unknown (no patch ids recorded) speaks for
    // no other head: an unknown diff is never "the same diff".
    let carries_unchanged_diff = reach == VerdictReach::UnchangedDiff
        && !head_patch_ids.is_empty()
        && head_patch_ids.len() <= jeryu_gitd::patch_id::MAX_COMMITS
        && head_patch_ids
            .iter()
            .all(|id| jeryu_gitd::patch_id::is_review_patch_id(id));
    // A targeted dismissal withdraws its verdict for good, at every head and
    // identity: a withdrawn approval never resurfaces because the identity
    // came back to the one it was written against.
    // Core authorizes the actor when appending a targeted dismissal. Do not
    // recheck authorship or current grants here: an administrator's recorded
    // decision survives later access changes. Head-less rows withdraw nothing.
    let withdrawn: std::collections::BTreeSet<_> = reviews
        .iter()
        .filter(|review| review.state == ReviewState::Dismissed && review.head_sha.is_some())
        .filter_map(|dismissal| {
            let target = dismissal.dismissed_review_id?;
            reviews
                .iter()
                .any(|review| review.id == target)
                .then_some(target)
        })
        .collect();
    let mut latest = BTreeMap::<&str, &Review>::new();
    for review in reviews.iter().filter(|review| {
        review.head_sha.as_deref() == Some(head_sha)
            || (carries_unchanged_diff && review.head_patch_ids == head_patch_ids)
    }) {
        if withdrawn.contains(&review.id) {
            // Still a later verdict by this reviewer: it replaces the earlier
            // one, so the earlier one cannot come back either.
            latest.remove(review.author.as_str());
            continue;
        }
        // An invalid inherited self approval cannot erase an earlier rejection.
        if review.state == ReviewState::Approved
            && pr_author.is_some_and(|author| review.author.eq_ignore_ascii_case(author))
        {
            continue;
        }
        match review.state {
            ReviewState::Approved | ReviewState::ChangesRequested => {
                latest.insert(review.author.as_str(), review);
            }
            ReviewState::Commented => {}
            ReviewState::Dismissed => {
                if let Some(current) = latest.get(review.author.as_str()) {
                    let clears = match review.dismissed_review_id {
                        Some(target) => target == current.id,
                        // A historical unbound dismissal cannot establish
                        // approval or erase a rejection. Never infer its target.
                        None => current.state == ReviewState::Approved,
                    };
                    if clears {
                        latest.remove(review.author.as_str());
                    }
                }
            }
        }
    }
    latest.into_values().collect()
}

/// Qualification and readback use the same verdicts, excluding inherited
/// self approvals even when they were written before Core enforced the rule.
pub fn effective_reviews_for_pull_request<'a>(
    reviews: &'a [Review],
    pr: &PullRequest,
) -> Vec<&'a Review> {
    effective_reviews_for_pull_request_with(reviews, pr, VerdictReach::ExactHead)
}

/// As [`effective_reviews_for_pull_request`], with the reach the repository's
/// branch-protection rule asks for.
pub fn effective_reviews_for_pull_request_with<'a>(
    reviews: &'a [Review],
    pr: &PullRequest,
    reach: VerdictReach,
) -> Vec<&'a Review> {
    reduce_reviews(
        reviews,
        &pr.head.sha,
        &pr.head_patch_ids,
        reach,
        Some(&pr.author),
    )
}
