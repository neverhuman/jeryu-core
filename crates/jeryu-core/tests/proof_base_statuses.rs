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
    CheckConclusion, CheckRunStatus, CommitStatus, CommitStatusState, CreateCheckRunRequest,
    CreateCommitStatusRequest, CreatePullRequestRequest, CreateRepositoryRequest,
    CreateReviewRequest, CreateUserRequest, DismissReviewRequest, ForgeCore, ForgeError,
    MergeBlocker, MergePullRequestRequest, MergeReadiness, PullRequestCommit, PullRequestState,
    RepoBranches, Result, RetargetPullRequestRequest, ReviewState, SetBranchProtectionRequest,
    UpdatePullRequestRequest,
};

const REQUIRED: &str = "jeryu/required";
const RELEASE: &str = "release/1";
const HEAD: &str = "c0ffee";
const MERGE_BASE: &str = "ba5eba5eba5eba5eba5eba5eba5eba5eba5eba5e";

/// Git storage where `main`, the release line and `feature` exist.
#[derive(Debug)]
struct Branches;

impl RepoBranches for Branches {
    fn branch_exists(&self, _owner: &str, _name: &str, branch: &str) -> Result<bool> {
        Ok(matches!(branch, "main" | RELEASE | "feature"))
    }
}

fn retarget_request(base: &str) -> RetargetPullRequestRequest {
    RetargetPullRequestRequest {
        base: base.to_string(),
        base_sha: MERGE_BASE.to_string(),
        head_sha: HEAD.to_string(),
        commits: vec![PullRequestCommit {
            sha: HEAD.to_string(),
            verified: true,
            parents: 1,
        }],
        changed_files: vec!["src/lib.rs".to_string()],
    }
}

fn retarget(
    core: &ForgeCore,
    number: u64,
    request: RetargetPullRequestRequest,
) -> Result<jeryu_core::PullRequest> {
    core.retarget_pull_request("alice", "alice", "jeryu", number, request, &Branches)
}

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
fn a_later_base_agnostic_failure_replaces_an_earlier_pass_proved_against_the_base() {
    let core = core_with_protected_bases();
    let into_main = open_pr(&core, HEAD, "main");
    post(&core, HEAD, CommitStatusState::Success, Some("main"));
    assert!(blockers(&core, into_main).is_empty());
    // A stale pinned pass must not shadow a newer authoritative failure.
    post(&core, HEAD, CommitStatusState::Failure, None);
    assert!(failed_required(&blockers(&core, into_main)));
    assert_eq!(
        core.combined_status_for_base("alice", "jeryu", HEAD, "main")
            .unwrap()
            .state,
        CommitStatusState::Failure
    );
}

#[test]
fn the_latest_answering_result_wins_whichever_kind_it_is() {
    let core = core_with_protected_bases();
    let into_main = open_pr(&core, HEAD, "main");
    let into_release = open_pr(&core, HEAD, RELEASE);
    post(&core, HEAD, CommitStatusState::Failure, None);
    post(&core, HEAD, CommitStatusState::Success, Some("main"));
    assert!(blockers(&core, into_main).is_empty());
    assert!(
        failed_required(&blockers(&core, into_release)),
        "the release line has no row of its own; the base-agnostic failure answers"
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
fn the_per_base_rollup_reports_its_history_like_the_per_sha_rollup() {
    let core = core_with_protected_bases();
    post(&core, HEAD, CommitStatusState::Failure, Some("main"));
    post(&core, HEAD, CommitStatusState::Success, Some("main"));
    post(&core, HEAD, CommitStatusState::Success, Some(RELEASE));
    post(&core, HEAD, CommitStatusState::Pending, None);
    let main = core
        .combined_status_for_base("alice", "jeryu", HEAD, "main")
        .unwrap();
    assert_eq!(
        main.total_count, 3,
        "both main rows and the base-agnostic one"
    );
    assert_eq!(main.statuses.len(), 3);
    assert_eq!(main.state, CommitStatusState::Pending);
    // A blank base asks for the base-agnostic rows alone.
    let agnostic = core
        .combined_status_for_base("alice", "jeryu", HEAD, "  ")
        .unwrap();
    assert_eq!(agnostic.total_count, 1);
    assert_eq!(agnostic.statuses[0].base, None);
    assert_eq!(
        core.combined_status("alice", "jeryu", HEAD)
            .unwrap()
            .total_count,
        4
    );
}

#[test]
fn retargeting_a_pull_request_drops_the_old_bases_result_immediately() {
    let core = core_with_protected_bases();
    let number = open_pr(&core, HEAD, RELEASE);
    post(&core, HEAD, CommitStatusState::Success, Some(RELEASE));
    assert!(blockers(&core, number).is_empty());

    // No further status is posted, and no publisher tick happens in between:
    // the retarget alone invalidates the release-line proof.
    let retargeted = retarget(&core, number, retarget_request("main")).unwrap();
    assert_eq!(retargeted.base.ref_name, "main");
    assert_eq!(retargeted.base.sha, MERGE_BASE);
    assert!(retargeted.head_patch_ids.is_empty());
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

    let retargeted = retarget(&core, number, retarget_request("refs/heads/release/1")).unwrap();
    assert_eq!(
        retargeted.base.ref_name, RELEASE,
        "stored without refs/heads/"
    );
    assert!(retargeted.mergeable);
    assert!(blockers(&core, number).is_empty());
}

/// The commit range and changed paths come with the move, so the new base's
/// signed-commit rule reads the new range, never the old one.
#[test]
fn a_retarget_replaces_the_base_relative_range() {
    let core = core_with_protected_bases();
    core.set_branch_protection(
        "alice",
        "jeryu",
        "main",
        SetBranchProtectionRequest {
            require_signed_commits: true,
            ..Default::default()
        },
    )
    .unwrap();
    let number = open_pr(&core, HEAD, RELEASE);
    post(&core, HEAD, CommitStatusState::Success, None);
    let mut request = retarget_request("main");
    request.commits = vec![
        PullRequestCommit {
            sha: "0ld".to_string(),
            verified: false,
            parents: 1,
        },
        PullRequestCommit {
            sha: HEAD.to_string(),
            verified: true,
            parents: 1,
        },
    ];
    let retargeted = retarget(&core, number, request).unwrap();
    assert_eq!(retargeted.commits.len(), 2);
    assert_eq!(retargeted.changed_files, ["src/lib.rs"]);
    assert!(blockers(&core, number).iter().any(|blocker| matches!(
        blocker,
        MergeBlocker::UnsignedCommits { unsigned } if unsigned == &["0ld".to_string()]
    )));
}

#[test]
fn a_retarget_refuses_what_it_cannot_trust() {
    let core = core_with_protected_bases();
    let number = open_pr(&core, HEAD, "main");
    let refused = |request: RetargetPullRequestRequest| {
        let err = retarget(&core, number, request).unwrap_err();
        assert!(matches!(err, ForgeError::Validation(_)), "{err:?}");
    };
    let mut blank = retarget_request("  ");
    refused(blank.clone());
    blank.base = "refs/heads/".to_string();
    refused(blank);
    for sha in ["ba5e", "main", "--all", ""] {
        let mut request = retarget_request(RELEASE);
        request.base_sha = sha.to_string();
        refused(request);
    }
    let mut empty_diff = retarget_request(RELEASE);
    empty_diff.base_sha = MERGE_BASE.to_string();
    empty_diff.head_sha = MERGE_BASE.to_uppercase();
    refused(empty_diff);
    let mut no_range = retarget_request(RELEASE);
    no_range.commits.clear();
    refused(no_range);
    let mut no_paths = retarget_request(RELEASE);
    no_paths.changed_files.clear();
    refused(no_paths);
    let err = core
        .retarget_pull_request(
            " ",
            "alice",
            "jeryu",
            number,
            retarget_request(RELEASE),
            &Branches,
        )
        .unwrap_err();
    assert!(matches!(err, ForgeError::Validation(_)), "{err:?}");
    refused(retarget_request("release/404"));
    refused(retarget_request("feature"));

    let mut moved = retarget_request(RELEASE);
    moved.head_sha = "f00d".to_string();
    assert!(matches!(
        retarget(&core, number, moved),
        Err(ForgeError::Conflict(_))
    ));
    assert!(matches!(
        retarget(&core, 999, retarget_request(RELEASE)),
        Err(ForgeError::NotFound(_))
    ));
    let pr = core.get_pull_request("alice", "jeryu", number).unwrap();
    assert_eq!(pr.base.ref_name, "main");
}

#[test]
fn a_closed_pull_requests_base_is_never_retargeted() {
    let core = core_with_protected_bases();
    let number = open_pr(&core, HEAD, "main");
    core.update_pull_request(
        "alice",
        "jeryu",
        number,
        UpdatePullRequestRequest {
            state: Some(PullRequestState::Closed),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(matches!(
        retarget(&core, number, retarget_request(RELEASE)),
        Err(ForgeError::Conflict(_))
    ));
    assert_eq!(
        core.get_pull_request("alice", "jeryu", number)
            .unwrap()
            .base
            .ref_name,
        "main"
    );
}

#[test]
fn a_create_with_a_full_ref_base_is_keyed_like_its_protection_rule() {
    let core = core_with_protected_bases();
    let number = open_pr(&core, HEAD, "refs/heads/main");
    let pr = core.get_pull_request("alice", "jeryu", number).unwrap();
    assert_eq!(pr.base.ref_name, "main");
    assert!(missing_required(&blockers(&core, number)));
}

#[test]
fn a_retarget_is_audited_and_refused_on_an_archived_repository() {
    let dir = tempfile::tempdir().unwrap();
    let core = ForgeCore::open_sqlite(dir.path().join("forge.sqlite")).unwrap();
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
    let number = open_pr(&core, HEAD, "main");
    retarget(&core, number, retarget_request(RELEASE)).unwrap();
    let audit = core.list_audit("alice/jeryu").unwrap();
    let entry = audit
        .iter()
        .find(|entry| entry.action == "pull_request.retargeted")
        .expect("retarget audited");
    assert_eq!(entry.actor, "alice");
    assert_eq!(entry.detail["from_base"], "main");
    assert_eq!(entry.detail["to_base"], RELEASE);
    assert_eq!(entry.detail["to_base_sha"], MERGE_BASE);

    core.set_repository_archived("alice", "alice", "jeryu", true)
        .unwrap();
    assert!(matches!(
        retarget(&core, number, retarget_request("main")),
        Err(ForgeError::RepositoryArchived(_))
    ));
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

/// A full lowercase SHA-1 head, which review dismissal requires.
const SHA1_HEAD: &str = "c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ff";

fn review(core: &ForgeCore, number: u64, author: &str, event: ReviewState) -> uuid::Uuid {
    core.create_review(
        "alice",
        "jeryu",
        number,
        author,
        CreateReviewRequest {
            body: None,
            event,
            comments: Vec::new(),
            expected_head_sha: None,
        },
    )
    .unwrap()
    .id
}

fn sha1_request(base: &str) -> RetargetPullRequestRequest {
    let mut request = retarget_request(base);
    request.head_sha = SHA1_HEAD.to_string();
    request.commits[0].sha = SHA1_HEAD.to_string();
    request
}

/// An approval judged the diff against the old base: it never carries to the
/// new one. The retarget waits until its author withdraws it.
#[test]
fn a_retarget_is_refused_while_an_approval_counts() {
    let core = core_with_protected_bases();
    let number = open_pr(&core, SHA1_HEAD, RELEASE);
    let approval = review(&core, number, "bob", ReviewState::Approved);
    assert!(matches!(
        retarget(&core, number, sha1_request("main")),
        Err(ForgeError::Conflict(_))
    ));
    assert_eq!(
        core.get_pull_request("alice", "jeryu", number)
            .unwrap()
            .base
            .ref_name,
        RELEASE
    );

    core.dismiss_review(
        "alice",
        "jeryu",
        number,
        "bob",
        DismissReviewRequest {
            review_id: approval,
            reason: "re-review against main".to_string(),
            expected_head_sha: SHA1_HEAD.to_string(),
        },
    )
    .unwrap();
    let retargeted = retarget(&core, number, sha1_request("main")).unwrap();
    assert_eq!(retargeted.base.ref_name, "main");
}

/// A rejection can only block, so it does not stand in the way.
#[test]
fn a_rejection_does_not_hold_a_retarget() {
    let core = core_with_protected_bases();
    let number = open_pr(&core, SHA1_HEAD, RELEASE);
    review(&core, number, "bob", ReviewState::ChangesRequested);
    retarget(&core, number, sha1_request("main")).unwrap();
}

/// A retarget between readiness and finalize: git merged into the base it was
/// told about, so the finalize is refused instead of being judged under the
/// new base's rule.
#[test]
fn a_finalize_is_refused_when_the_base_moved_since_readiness() {
    let core = core_with_protected_bases();
    let number = open_pr(&core, HEAD, RELEASE);
    post(&core, HEAD, CommitStatusState::Success, None);
    let evaluated = core
        .evaluate_merge_readiness("alice", "jeryu", number, None)
        .unwrap()
        .merge_base()
        .expect("ready");
    retarget(&core, number, retarget_request("main")).unwrap();
    let err = core
        .finalize_merge(
            "alice",
            "jeryu",
            number,
            "merged".to_string(),
            None,
            &evaluated,
        )
        .unwrap_err();
    assert!(matches!(err, ForgeError::Conflict(_)), "{err:?}");
    assert!(
        !core
            .get_pull_request("alice", "jeryu", number)
            .unwrap()
            .merged
    );
}

#[test]
fn a_create_whose_base_normalizes_to_nothing_is_refused() {
    let core = core_with_protected_bases();
    for base in ["refs/heads/", "  refs/heads/  "] {
        let err = core
            .create_pull_request(
                "alice",
                "jeryu",
                "alice",
                CreatePullRequestRequest {
                    title: "empty base".to_string(),
                    head: "feature".to_string(),
                    base: base.to_string(),
                    ..Default::default()
                },
            )
            .unwrap_err();
        assert!(
            matches!(err, ForgeError::Validation(_)),
            "{base:?}: {err:?}"
        );
    }
}

/// Approve at H, move the head off H, retarget, rewind to H: the approval
/// would count again under the new base. Any approval still standing at a
/// head it was given at therefore holds the retarget, not only one that
/// counts at the current head.
#[test]
fn an_approval_at_an_earlier_head_still_holds_a_retarget() {
    let core = core_with_protected_bases();
    let number = open_pr(&core, SHA1_HEAD, RELEASE);
    review(&core, number, "bob", ReviewState::Approved);
    let moved = "f00df00df00df00df00df00df00df00df00df00d";
    core.refresh_pull_request_heads_for_ref("alice", "jeryu", "feature", moved)
        .unwrap();
    let mut request = sha1_request("main");
    request.head_sha = moved.to_string();
    request.commits[0].sha = moved.to_string();
    assert!(matches!(
        retarget(&core, number, request),
        Err(ForgeError::Conflict(_))
    ));
    assert_eq!(
        core.get_pull_request("alice", "jeryu", number)
            .unwrap()
            .base
            .ref_name,
        RELEASE
    );
}

/// A context whose statuses are pinned to bases is answered only by a status
/// for this base: a like-named check run, which is not base-bound, does not
/// stand in for the missing answer.
#[test]
fn a_check_run_does_not_answer_for_a_base_pinned_context() {
    let core = core_with_protected_bases();
    let into_main = open_pr(&core, HEAD, "main");
    post(&core, HEAD, CommitStatusState::Success, Some(RELEASE));
    core.create_check_run(
        "alice",
        "jeryu",
        CreateCheckRunRequest {
            name: REQUIRED.to_string(),
            head_sha: HEAD.to_string(),
            status: Some(CheckRunStatus::Completed),
            conclusion: Some(CheckConclusion::Success),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(missing_required(&blockers(&core, into_main)));
}

#[test]
fn an_already_merged_readiness_discloses_no_base() {
    let core = core_with_protected_bases();
    let number = open_pr(&core, HEAD, "main");
    post(&core, HEAD, CommitStatusState::Success, None);
    core.merge_pull_request("alice", "jeryu", number, MergePullRequestRequest::default())
        .unwrap();
    let readiness = core
        .evaluate_merge_readiness("alice", "jeryu", number, None)
        .unwrap();
    assert!(matches!(readiness, MergeReadiness::AlreadyMerged { .. }));
    assert_eq!(readiness.merge_base(), None);
}
