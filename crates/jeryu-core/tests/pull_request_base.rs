//! A pull request's base follows its head: after a push, the serve layer
//! records the merge base of the new head with the base branch, so the pull
//! request's diff and its review stop including commits already on the base.

use jeryu_core::{
    CreatePullRequestRequest, CreateRepositoryRequest, ForgeCore, ForgeError, PullRequestState,
    UpdatePullRequestRequest,
};

const OPENED_BASE: &str = "0000000000000000000000000000000000000001";
const HEAD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const REBASED: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const NEWER_BASE: &str = "cccccccccccccccccccccccccccccccccccccccc";

fn open(core: &ForgeCore) -> u64 {
    core.create_repository(
        "alice",
        CreateRepositoryRequest {
            name: "demo".to_string(),
            default_branch: Some("main".to_string()),
            ..Default::default()
        },
    )
    .unwrap();
    core.create_pull_request(
        "alice",
        "demo",
        "alice",
        CreatePullRequestRequest {
            title: "change".to_string(),
            head: "feature".to_string(),
            base: "main".to_string(),
            head_sha: Some(HEAD.to_string()),
            base_sha: Some(OPENED_BASE.to_string()),
            ..Default::default()
        },
    )
    .unwrap()
    .number
}

#[test]
fn a_rebased_head_takes_its_merge_base_as_the_pr_base() {
    let core = ForgeCore::new();
    let number = open(&core);
    core.refresh_pull_request_heads_for_ref("alice", "demo", "feature", REBASED)
        .unwrap();
    let pr = core
        .record_pull_request_base("system:push", "alice", "demo", number, REBASED, NEWER_BASE)
        .unwrap();
    assert_eq!(pr.base.sha, NEWER_BASE);
    assert_eq!(pr.base.ref_name, "main", "only the sha moves");
    assert_eq!(
        core.get_pull_request("alice", "demo", number)
            .unwrap()
            .base
            .sha,
        NEWER_BASE
    );
}

#[test]
fn a_base_for_a_head_that_moved_on_is_refused() {
    let core = ForgeCore::new();
    let number = open(&core);
    core.refresh_pull_request_heads_for_ref("alice", "demo", "feature", REBASED)
        .unwrap();
    let error = core
        .record_pull_request_base("system:push", "alice", "demo", number, HEAD, NEWER_BASE)
        .unwrap_err();
    assert!(matches!(error, ForgeError::Conflict(_)), "{error}");
    assert_eq!(
        core.get_pull_request("alice", "demo", number)
            .unwrap()
            .base
            .sha,
        OPENED_BASE
    );
}

#[test]
fn a_base_that_is_not_a_full_object_id_or_is_the_head_is_refused() {
    let core = ForgeCore::new();
    let number = open(&core);
    for bad in ["main", "--all", "abc123", "", HEAD] {
        let error = core
            .record_pull_request_base("system:push", "alice", "demo", number, HEAD, bad)
            .unwrap_err();
        assert!(matches!(error, ForgeError::Validation(_)), "{bad}: {error}");
    }
}

#[test]
fn a_closed_pull_requests_base_is_never_rewritten() {
    let core = ForgeCore::new();
    let number = open(&core);
    core.update_pull_request(
        "alice",
        "demo",
        number,
        UpdatePullRequestRequest {
            state: Some(PullRequestState::Closed),
            ..Default::default()
        },
    )
    .unwrap();
    let error = core
        .record_pull_request_base("system:push", "alice", "demo", number, HEAD, NEWER_BASE)
        .unwrap_err();
    assert!(matches!(error, ForgeError::Conflict(_)), "{error}");
    assert_eq!(
        core.get_pull_request("alice", "demo", number)
            .unwrap()
            .base
            .sha,
        OPENED_BASE
    );
}

#[test]
fn a_recorded_base_survives_a_restart_and_is_audited() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("forge.sqlite");
    let core = ForgeCore::open_sqlite(&path).unwrap();
    let number = open(&core);
    core.record_pull_request_base("system:push", "alice", "demo", number, HEAD, NEWER_BASE)
        .unwrap();
    drop(core);
    let reopened = ForgeCore::open_sqlite(&path).unwrap();
    assert_eq!(
        reopened
            .get_pull_request("alice", "demo", number)
            .unwrap()
            .base
            .sha,
        NEWER_BASE
    );
    let audit = reopened.list_audit("alice/demo").unwrap();
    let entry = audit
        .iter()
        .find(|entry| entry.action == "pull_request.base_recorded")
        .expect("an audit entry");
    assert_eq!(entry.actor, "system:push");
    assert_eq!(entry.subject, "alice/demo");
    assert_eq!(entry.detail["from"], OPENED_BASE);
    assert_eq!(entry.detail["to"], NEWER_BASE);
}
