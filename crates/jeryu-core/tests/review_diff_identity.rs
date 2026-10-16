//! Carrying an approval across a push that changed no content.
//!
//! A pull request's diff identity is git's per-commit patch ids, recorded by
//! the pusher. When the branch's rule turns both exact-head settings off, an
//! approval written against one head counts for the next head with the same
//! identity — a pure rebase — and for no other.

use jeryu_core::{
    CreatePullRequestRequest, CreateRepositoryRequest, CreateReviewRequest, ForgeCore, ForgeError,
    MergeBlocker, ReviewState, SetBranchProtectionRequest,
};
use rusqlite::Connection;

const HEAD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const REBASED: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PATCH_ONE: &str = "1111111111111111111111111111111111111111";
const PATCH_TWO: &str = "2222222222222222222222222222222222222222";
const CHANGED_PATCH: &str = "3333333333333333333333333333333333333333";

fn patch_ids(ids: &[&str]) -> Vec<String> {
    ids.iter().map(|id| id.to_string()).collect()
}

/// A repository whose branch rule requires one approval, with
/// `dismiss_stale_approvals` and `require_exact_sha_approval` as given.
fn seed(core: &ForgeCore, dismiss_stale_approvals: bool, require_exact_sha_approval: bool) -> u64 {
    core.create_repository(
        "alice",
        CreateRepositoryRequest {
            name: "demo".to_string(),
            default_branch: Some("main".to_string()),
            ..Default::default()
        },
    )
    .unwrap();
    core.set_branch_protection(
        "alice",
        "demo",
        "main",
        SetBranchProtectionRequest {
            required_approving_review_count: 1,
            dismiss_stale_approvals,
            require_exact_sha_approval,
            ..Default::default()
        },
    )
    .unwrap();
    core.create_pull_request(
        "alice",
        "demo",
        "author",
        CreatePullRequestRequest {
            title: "reviewed change".to_string(),
            head: "feature".to_string(),
            base: "main".to_string(),
            head_sha: Some(HEAD.to_string()),
            head_patch_ids: patch_ids(&[PATCH_ONE, PATCH_TWO]),
            ..Default::default()
        },
    )
    .unwrap()
    .number
}

fn approve(core: &ForgeCore, number: u64) {
    core.create_review(
        "alice",
        "demo",
        number,
        "reviewer",
        CreateReviewRequest {
            body: Some("reviewed the diff".to_string()),
            event: ReviewState::Approved,
            comments: Vec::new(),
            expected_head_sha: Some(HEAD.to_string()),
        },
    )
    .unwrap();
}

fn push(core: &ForgeCore, head_sha: &str, head_patch_ids: &[&str]) {
    core.refresh_pull_request_heads_for_ref_with_diff(
        "alice",
        "demo",
        "feature",
        head_sha,
        &patch_ids(head_patch_ids),
    )
    .unwrap();
}

fn missing_review(core: &ForgeCore, number: u64) -> bool {
    core.evaluate_pull_request("alice", "demo", number, None)
        .unwrap()
        .blockers
        .iter()
        .any(|blocker| matches!(blocker, MergeBlocker::MissingReview { .. }))
}

#[test]
fn an_unchanged_diff_keeps_its_approval_across_a_push() {
    let core = ForgeCore::new();
    let number = seed(&core, false, false);
    approve(&core, number);
    assert!(!missing_review(&core, number));

    push(&core, REBASED, &[PATCH_ONE, PATCH_TWO]);
    let pr = core.get_pull_request("alice", "demo", number).unwrap();
    assert_eq!(pr.head.sha, REBASED);
    assert!(
        !missing_review(&core, number),
        "a rebase that changed no content keeps the approval"
    );
    assert!(pr.mergeable);
}

#[test]
fn any_content_change_invalidates_the_approval() {
    for next in [
        // An edited commit: same count, one different patch id.
        vec![PATCH_ONE, CHANGED_PATCH],
        // An appended commit.
        vec![PATCH_ONE, PATCH_TWO, CHANGED_PATCH],
        // A dropped commit.
        vec![PATCH_ONE],
        // Reordered commits are a different diff at every intermediate state.
        vec![PATCH_TWO, PATCH_ONE],
        // A pusher that recorded no diff identity.
        vec![],
    ] {
        let core = ForgeCore::new();
        let number = seed(&core, false, false);
        approve(&core, number);
        push(&core, REBASED, &next);
        assert!(
            missing_review(&core, number),
            "{next:?} is not the approved diff"
        );
        assert!(
            !core
                .get_pull_request("alice", "demo", number)
                .unwrap()
                .mergeable
        );
    }
}

#[test]
fn either_exact_head_setting_drops_the_approval_of_an_unchanged_diff() {
    for (dismiss_stale_approvals, require_exact_sha_approval) in
        [(true, true), (true, false), (false, true)]
    {
        let core = ForgeCore::new();
        let number = seed(&core, dismiss_stale_approvals, require_exact_sha_approval);
        approve(&core, number);
        push(&core, REBASED, &[PATCH_ONE, PATCH_TWO]);
        assert!(
            missing_review(&core, number),
            "dismiss_stale_approvals={dismiss_stale_approvals} \
             require_exact_sha_approval={require_exact_sha_approval} binds the exact head"
        );
    }
}

/// A pusher that records no diff identity gets the strict behaviour, which is
/// also what the call without one does.
#[test]
fn a_push_without_a_diff_identity_dismisses_the_approval() {
    let core = ForgeCore::new();
    let number = seed(&core, false, false);
    approve(&core, number);
    core.refresh_pull_request_heads_for_ref("alice", "demo", "feature", REBASED)
        .unwrap();
    assert!(
        core.get_pull_request("alice", "demo", number)
            .unwrap()
            .head_patch_ids
            .is_empty()
    );
    assert!(missing_review(&core, number));
}

/// A rejection is carried by the same rule, so a no-op rebase cannot wash one
/// away either.
#[test]
fn an_unchanged_diff_keeps_a_changes_requested_verdict() {
    let core = ForgeCore::new();
    let number = seed(&core, false, false);
    core.create_review(
        "alice",
        "demo",
        number,
        "reviewer",
        CreateReviewRequest {
            body: Some("needs work".to_string()),
            event: ReviewState::ChangesRequested,
            comments: Vec::new(),
            expected_head_sha: Some(HEAD.to_string()),
        },
    )
    .unwrap();
    push(&core, REBASED, &[PATCH_ONE, PATCH_TWO]);
    let blockers = core
        .evaluate_pull_request("alice", "demo", number, None)
        .unwrap()
        .blockers;
    assert!(
        blockers
            .iter()
            .any(|blocker| matches!(blocker, MergeBlocker::ChangesRequested { .. })),
        "{blockers:?}"
    );
}

#[test]
fn a_diff_identity_is_a_bounded_list_of_object_ids() {
    let core = ForgeCore::new();
    let number = seed(&core, false, false);
    for bad in [
        vec!["../../etc/passwd".to_string()],
        vec![PATCH_ONE[..12].to_string()],
        vec!["--all".to_string()],
        vec![PATCH_ONE.to_string(); 4097],
    ] {
        let error = core
            .refresh_pull_request_heads_for_ref_with_diff("alice", "demo", "feature", REBASED, &bad)
            .unwrap_err();
        assert!(matches!(error, ForgeError::Validation(_)), "{error:?}");
    }
    let pr = core.get_pull_request("alice", "demo", number).unwrap();
    assert_eq!(pr.head.sha, HEAD, "a refused push moves no head");
    assert_eq!(pr.head_patch_ids, patch_ids(&[PATCH_ONE, PATCH_TWO]));
}

#[test]
fn diff_identity_survives_sqlite_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("forge.sqlite");
    let core = ForgeCore::open_sqlite(&db).unwrap();
    let number = seed(&core, false, false);
    approve(&core, number);
    push(&core, REBASED, &[PATCH_ONE, PATCH_TWO]);
    drop(core);

    let core = ForgeCore::open_sqlite(&db).unwrap();
    let pr = core.get_pull_request("alice", "demo", number).unwrap();
    assert_eq!(pr.head_patch_ids, patch_ids(&[PATCH_ONE, PATCH_TWO]));
    let reviews = core.list_reviews("alice", "demo", number).unwrap();
    assert_eq!(
        reviews[0].head_patch_ids,
        patch_ids(&[PATCH_ONE, PATCH_TWO])
    );
    assert!(
        !missing_review(&core, number),
        "the carried approval survives a reopen"
    );
    let rule = core.get_branch_protection("alice", "demo", "main").unwrap();
    assert!(!rule.dismiss_stale_approvals);
    assert!(!rule.require_exact_sha_approval);

    let conn = Connection::open(&db).unwrap();
    let stored: String = conn
        .query_row("SELECT head_patch_ids_json FROM pull_requests", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(stored, format!("[\"{PATCH_ONE}\",\"{PATCH_TWO}\"]"));
}
