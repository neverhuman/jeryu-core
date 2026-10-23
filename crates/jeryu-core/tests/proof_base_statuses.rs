//! Per-base commit statuses: a result carries the base it was proved against,
//! and branch protection for a pull request into `B` reads only the result
//! proved against `B`.
//!
//! The gate that publishes `<repo>/required` proves a head against its target
//! branch, so its answer is per (sha, context, base). These tests pin what that
//! buys: one commit open in two pull requests with different bases is green for
//! one and pending for the other at the same time, and a retarget stops
//! counting the old base's result the moment the base moves.

use jeryu_core::{
    CommitStatus, CommitStatusState, CreateCommitStatusRequest, CreatePullRequestRequest,
    CreateRepositoryRequest, CreateUserRequest, ForgeCore, MergeBlocker,
    SetBranchProtectionRequest, UpdatePullRequestRequest,
};

const REQUIRED: &str = "jeryu/required";
const RELEASE: &str = "release/1";
const HEAD: &str = "c0ffee";

fn core_with_protected_bases() -> ForgeCore {
    let core = ForgeCore::new();
    core.create_user(CreateUserRequest {
        login: "alice".to_string(),
        ..Default::default()
    })
    .unwrap();
    core.create_repository(
        "alice",
        CreateRepositoryRequest {
            name: "jeryu".to_string(),
            default_branch: Some("main".to_string()),
            ..Default::default()
        },
    )
    .unwrap();
    for branch in ["main", RELEASE] {
        core.set_branch_protection(
            "alice",
            "jeryu",
            branch,
            SetBranchProtectionRequest {
                required_status_checks: vec![REQUIRED.to_string()],
                ..Default::default()
            },
        )
        .unwrap();
    }
    core
}

fn open_pr(core: &ForgeCore, head: &str, base: &str) -> u64 {
    core.create_pull_request(
        "alice",
        "jeryu",
        "alice",
        CreatePullRequestRequest {
            title: format!("change into {base}"),
            head: "feature".to_string(),
            base: base.to_string(),
            head_sha: Some(head.to_string()),
            ..Default::default()
        },
    )
    .unwrap()
    .number
}

fn post(
    core: &ForgeCore,
    head: &str,
    state: CommitStatusState,
    base: Option<&str>,
) -> CommitStatus {
    core.create_commit_status(
        "alice",
        "jeryu",
        head,
        "ci-bot",
        CreateCommitStatusRequest {
            state,
            context: REQUIRED.to_string(),
            base: base.map(str::to_string),
            description: None,
            target_url: None,
        },
    )
    .unwrap()
}

fn blockers(core: &ForgeCore, number: u64) -> Vec<MergeBlocker> {
    core.evaluate_pull_request("alice", "jeryu", number, None)
        .unwrap()
        .blockers
}

fn missing_required(blockers: &[MergeBlocker]) -> bool {
    blockers.iter().any(|blocker| {
        matches!(blocker, MergeBlocker::MissingStatusCheck { context } if context == REQUIRED)
    })
}

fn failed_required(blockers: &[MergeBlocker]) -> bool {
    blockers.iter().any(|blocker| {
        matches!(blocker, MergeBlocker::FailedStatusCheck { context } if context == REQUIRED)
    })
}

#[test]
fn one_commit_is_green_for_a_release_line_and_pending_for_main_at_once() {
    let core = core_with_protected_bases();
    let into_release = open_pr(&core, HEAD, RELEASE);
    let into_main = open_pr(&core, HEAD, "main");

    let status = post(&core, HEAD, CommitStatusState::Success, Some(RELEASE));
    assert_eq!(status.base.as_deref(), Some(RELEASE));

    assert!(
        blockers(&core, into_release).is_empty(),
        "the base it was proved against is satisfied"
    );
    assert!(
        core.get_pull_request("alice", "jeryu", into_release)
            .unwrap()
            .mergeable
    );

    let main_blockers = blockers(&core, into_main);
    assert!(
        missing_required(&main_blockers),
        "main is unanswered, not green: {main_blockers:?}"
    );
    assert!(
        !core
            .get_pull_request("alice", "jeryu", into_main)
            .unwrap()
            .mergeable
    );

    // The same split in the status rollup the merge panel reads.
    assert_eq!(
        core.combined_status_for_base("alice", "jeryu", HEAD, RELEASE)
            .unwrap()
            .state,
        CommitStatusState::Success
    );
    let main_combined = core
        .combined_status_for_base("alice", "jeryu", HEAD, "main")
        .unwrap();
    assert_eq!(main_combined.state, CommitStatusState::Pending);
    assert!(main_combined.statuses.is_empty());

    // The unfiltered per-sha rollup still reports every row posted.
    let all = core.combined_status("alice", "jeryu", HEAD).unwrap();
    assert_eq!(all.total_count, 1);
}

#[test]
fn a_failure_proved_against_another_base_does_not_fail_this_base() {
    let core = core_with_protected_bases();
    let into_main = open_pr(&core, HEAD, "main");
    post(&core, HEAD, CommitStatusState::Failure, Some(RELEASE));

    let main_blockers = blockers(&core, into_main);
    assert!(missing_required(&main_blockers), "{main_blockers:?}");
    assert!(!failed_required(&main_blockers), "{main_blockers:?}");
}

#[test]
fn a_status_posted_without_a_base_still_answers_for_every_base() {
    let core = core_with_protected_bases();
    let into_main = open_pr(&core, HEAD, "main");
    let into_release = open_pr(&core, HEAD, RELEASE);

    let status = post(&core, HEAD, CommitStatusState::Success, None);
    assert_eq!(status.base, None);

    assert!(blockers(&core, into_main).is_empty());
    assert!(blockers(&core, into_release).is_empty());
}

#[test]
fn a_blank_base_is_recorded_as_no_base_stated() {
    let core = core_with_protected_bases();
    let into_main = open_pr(&core, HEAD, "main");
    let status = post(&core, HEAD, CommitStatusState::Success, Some("   "));
    assert_eq!(status.base, None);
    assert!(blockers(&core, into_main).is_empty());
}

#[test]
fn a_full_ref_base_matches_the_pull_requests_short_base_name() {
    let core = core_with_protected_bases();
    let into_release = open_pr(&core, HEAD, RELEASE);
    let into_main = open_pr(&core, HEAD, "main");
    let status = post(
        &core,
        HEAD,
        CommitStatusState::Success,
        Some("refs/heads/release/1"),
    );
    assert_eq!(status.base.as_deref(), Some(RELEASE));
    assert!(blockers(&core, into_release).is_empty());
    assert!(missing_required(&blockers(&core, into_main)));
}

#[test]
fn a_result_proved_against_the_base_outranks_a_base_agnostic_one() {
    let core = core_with_protected_bases();
    let into_main = open_pr(&core, HEAD, "main");
    let into_release = open_pr(&core, HEAD, RELEASE);

    // The base-agnostic row is posted last, so recency alone would make main
    // green; the row proved against main is the one that answers for main.
    post(&core, HEAD, CommitStatusState::Failure, Some("main"));
    post(&core, HEAD, CommitStatusState::Success, None);

    assert!(failed_required(&blockers(&core, into_main)));
    assert!(
        blockers(&core, into_release).is_empty(),
        "the release line has no row of its own and falls back to the base-agnostic pass"
    );
}

#[test]
fn the_latest_result_for_a_base_wins_over_its_earlier_ones() {
    let core = core_with_protected_bases();
    let into_main = open_pr(&core, HEAD, "main");
    post(&core, HEAD, CommitStatusState::Failure, Some("main"));
    post(&core, HEAD, CommitStatusState::Success, Some("main"));
    assert!(blockers(&core, into_main).is_empty());
}

#[test]
fn retargeting_a_pull_request_drops_the_old_bases_result_immediately() {
    let core = core_with_protected_bases();
    let number = open_pr(&core, HEAD, RELEASE);
    post(&core, HEAD, CommitStatusState::Success, Some(RELEASE));
    assert!(blockers(&core, number).is_empty());

    // No further status is posted, and no publisher tick happens in between:
    // the retarget alone invalidates the release-line proof.
    let retargeted = core
        .update_pull_request(
            "alice",
            "jeryu",
            number,
            UpdatePullRequestRequest {
                base: Some("main".to_string()),
                base_sha: Some("ba5e".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(retargeted.base.ref_name, "main");
    assert_eq!(retargeted.base.sha, "ba5e");
    assert!(!retargeted.mergeable);
    assert!(missing_required(&blockers(&core, number)));

    // And the release line's own answer is untouched by the move.
    assert_eq!(
        core.combined_status_for_base("alice", "jeryu", HEAD, RELEASE)
            .unwrap()
            .state,
        CommitStatusState::Success
    );
}

#[test]
fn retargeting_back_restores_the_base_it_was_proved_against() {
    let core = core_with_protected_bases();
    let number = open_pr(&core, HEAD, "main");
    post(&core, HEAD, CommitStatusState::Success, Some(RELEASE));
    assert!(missing_required(&blockers(&core, number)));

    let retargeted = core
        .update_pull_request(
            "alice",
            "jeryu",
            number,
            UpdatePullRequestRequest {
                base: Some(RELEASE.to_string()),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(retargeted.mergeable);
    assert!(blockers(&core, number).is_empty());
}

#[test]
fn a_retarget_without_a_base_sha_records_the_create_paths_placeholder() {
    let core = core_with_protected_bases();
    let number = open_pr(&core, HEAD, "main");
    let created = core.get_pull_request("alice", "jeryu", number).unwrap();
    let retargeted = core
        .update_pull_request(
            "alice",
            "jeryu",
            number,
            UpdatePullRequestRequest {
                base: Some(RELEASE.to_string()),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(retargeted.base.sha, created.base.sha);
}

#[test]
fn an_empty_base_cannot_retarget_a_pull_request() {
    let core = core_with_protected_bases();
    let number = open_pr(&core, HEAD, "main");
    let err = core
        .update_pull_request(
            "alice",
            "jeryu",
            number,
            UpdatePullRequestRequest {
                base: Some("  ".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(matches!(err, jeryu_core::ForgeError::Validation(_)));
    assert_eq!(
        core.get_pull_request("alice", "jeryu", number)
            .unwrap()
            .base
            .ref_name,
        "main"
    );
}

#[test]
fn a_jankurai_proof_from_another_base_does_not_satisfy_the_proof_gate() {
    let core = core_with_protected_bases();
    core.set_branch_protection(
        "alice",
        "jeryu",
        "main",
        SetBranchProtectionRequest {
            require_jankurai_proof: true,
            ..Default::default()
        },
    )
    .unwrap();
    let into_main = open_pr(&core, HEAD, "main");
    core.create_commit_status(
        "alice",
        "jeryu",
        HEAD,
        "ci-bot",
        CreateCommitStatusRequest {
            state: CommitStatusState::Success,
            context: "jankurai/proof".to_string(),
            base: Some(RELEASE.to_string()),
            description: None,
            target_url: None,
        },
    )
    .unwrap();
    assert!(
        blockers(&core, into_main)
            .iter()
            .any(|blocker| matches!(blocker, MergeBlocker::JankuraiProofRequired))
    );
}

#[test]
fn a_stored_status_without_a_base_loads_base_agnostic() {
    let core = core_with_protected_bases();
    let status = post(&core, HEAD, CommitStatusState::Success, Some(RELEASE));
    let mut stored = serde_json::to_value(&status).unwrap();
    assert_eq!(stored["base"], RELEASE);
    stored.as_object_mut().unwrap().remove("base");
    let reloaded: CommitStatus = serde_json::from_value(stored).unwrap();
    assert_eq!(reloaded.base, None);
    assert_eq!(reloaded.context, REQUIRED);
}

#[test]
fn a_posted_base_survives_a_reload_from_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("forge.sqlite");
    {
        let core = ForgeCore::open_sqlite(&path).unwrap();
        core.create_user(CreateUserRequest {
            login: "alice".to_string(),
            ..Default::default()
        })
        .unwrap();
        core.create_repository(
            "alice",
            CreateRepositoryRequest {
                name: "jeryu".to_string(),
                default_branch: Some("main".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        post(&core, HEAD, CommitStatusState::Success, Some(RELEASE));
    }
    let reopened = ForgeCore::open_sqlite(&path).unwrap();
    assert_eq!(
        reopened
            .combined_status_for_base("alice", "jeryu", HEAD, RELEASE)
            .unwrap()
            .state,
        CommitStatusState::Success
    );
    assert_eq!(
        reopened
            .combined_status_for_base("alice", "jeryu", HEAD, "main")
            .unwrap()
            .state,
        CommitStatusState::Pending
    );
}
