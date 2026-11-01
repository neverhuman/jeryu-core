//! Branch-protection evaluation: merge gates, ref-operation bars, CODEOWNERS.

mod codeowners;
mod evaluate;
mod reviews;
mod types;

pub use evaluate::{evaluate_branch_protection_with, evaluate_ref_operation};
pub use reviews::{
    VerdictReach, effective_reviews_for_head, effective_reviews_for_pull_request,
    effective_reviews_for_pull_request_with,
};
pub(crate) use reviews::{is_cross_author_dismissal, withdrawn_verdicts};
pub use types::{
    BranchProtectionEvaluation, EvaluationContext, MergeBlocker, RefOperation, RefOperationBlocker,
    RefOperationEvaluation,
};

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::evaluate::{RequiredContextState, required_context_state};
    use super::*;
    use crate::model::{
        BranchProtectionRule, CheckConclusion, CheckRun, CheckRunStatus, GitBranchRef, PullRequest,
        PullRequestState,
    };
    use chrono::TimeZone;

    fn pr() -> PullRequest {
        PullRequest {
            id: Uuid::new_v4(),
            owner: "acme".to_string(),
            repo: "jeryu".to_string(),
            number: 1,
            issue_number: 1,
            title: "change".to_string(),
            body: None,
            state: PullRequestState::Open,
            draft: false,
            author: "dev".to_string(),
            source_repository: "acme/jeryu".to_string(),
            head: GitBranchRef::new("feature", "abc"),
            base: GitBranchRef::new("main", "base"),
            mergeable: false,
            mergeable_state: "unknown".to_string(),
            merged: false,
            merged_at: None,
            merge_commit_sha: None,
            commits: Vec::new(),
            changed_files: Vec::new(),
            head_patch_ids: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn proof_run(sequence: u64, conclusion: CheckConclusion, finished_after: i64) -> CheckRun {
        let started = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        CheckRun {
            id: Uuid::new_v4(),
            owner: "acme".to_string(),
            repo: "jeryu".to_string(),
            name: "jankurai/proof".to_string(),
            head_sha: "abc".to_string(),
            status: CheckRunStatus::Completed,
            conclusion: Some(conclusion),
            details_url: None,
            output: None,
            started_at: started,
            completed_at: Some(started + chrono::Duration::seconds(finished_after)),
            creation_sequence: sequence,
        }
    }

    #[test]
    fn newest_proof_is_the_last_created_whatever_finished_last() {
        // Same start instant; the older run finished later. Creation order
        // decides, in either storage order.
        let older = proof_run(1, CheckConclusion::Success, 90);
        let newer = proof_run(2, CheckConclusion::Failure, 5);
        for runs in [
            vec![older.clone(), newer.clone()],
            vec![newer.clone(), older.clone()],
        ] {
            assert_eq!(
                required_context_state("jankurai/proof", &[], &runs, "main"),
                RequiredContextState::Failed
            );
        }
    }

    #[test]
    fn branch_protection_blocks_missing_review_and_status() {
        let rule = BranchProtectionRule {
            owner: "acme".to_string(),
            repo: "jeryu".to_string(),
            branch: "main".to_string(),
            required_status_checks: vec!["ci/fast".to_string()],
            strict: false,
            required_approving_review_count: 1,
            allow_merge_override: false,
            allow_admin_review_dismissal: false,
            merge_override_status_checks: Vec::new(),
            merge_override_status_creators: Vec::new(),
            enforce_admins: true,
            required_linear_history: true,
            allow_force_pushes: false,
            allow_deletions: false,
            require_signed_commits: false,
            require_jankurai_proof: false,
            dismiss_stale_approvals: true,
            require_exact_sha_approval: true,
            updated_at: Utc::now(),
        };

        let eval = evaluate_branch_protection_with(
            &pr(),
            Some(&rule),
            &[],
            &[],
            &[],
            None,
            EvaluationContext::default(),
        );
        assert!(!eval.mergeable);
        assert_eq!(eval.blockers.len(), 2);
    }
}
