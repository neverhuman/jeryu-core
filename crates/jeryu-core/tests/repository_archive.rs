//! Archiving makes a repository read-only; unarchiving restores every write.

use jeryu_core::{
    CommitStatusState, CreateCheckRunRequest, CreateCommitStatusRequest, CreatePullRequestRequest,
    CreateRepositoryRequest, CreateReviewRequest, ForgeCore, ForgeError, MergePullRequestRequest,
    ReviewState, UpdatePullRequestRequest,
};

fn create_repo(core: &ForgeCore, name: &str) {
    core.create_repository(
        "jeryu",
        CreateRepositoryRequest {
            name: name.to_string(),
            private: true,
            description: None,
            default_branch: Some("main".to_string()),
        },
    )
    .unwrap();
}

fn pr_request() -> CreatePullRequestRequest {
    CreatePullRequestRequest {
        title: "change".to_string(),
        body: None,
        head: "feature".to_string(),
        base: "main".to_string(),
        head_sha: Some("abc123".to_string()),
        ..Default::default()
    }
}

fn assert_archived<T: std::fmt::Debug>(result: Result<T, ForgeError>) {
    match result {
        Err(err @ ForgeError::RepositoryArchived(_)) => {
            assert!(err.to_string().starts_with("repository_archived"), "{err}");
        }
        other => panic!("expected RepositoryArchived, got {other:?}"),
    }
}

#[test]
fn archived_repository_refuses_writes_and_unarchive_restores_them() {
    let core = ForgeCore::new();
    create_repo(&core, "jain-dup");
    let pr = core
        .create_pull_request("jeryu", "jain-dup", "jeryu", pr_request())
        .unwrap();

    let archived = core
        .set_repository_archived("alton", "jeryu", "jain-dup", true)
        .unwrap();
    assert!(archived.archived);
    // Idempotent.
    let again = core
        .set_repository_archived("alton", "jeryu", "jain-dup", true)
        .unwrap();
    assert_eq!(again.updated_at, archived.updated_at);

    assert_archived(core.create_pull_request("jeryu", "jain-dup", "jeryu", pr_request()));
    assert_archived(core.update_pull_request(
        "jeryu",
        "jain-dup",
        pr.number,
        UpdatePullRequestRequest::default(),
    ));
    assert_archived(core.create_review(
        "jeryu",
        "jain-dup",
        pr.number,
        "reviewer",
        CreateReviewRequest {
            body: None,
            event: ReviewState::Approved,
            comments: Vec::new(),
            expected_head_sha: None,
        },
    ));
    assert_archived(core.merge_pull_request(
        "jeryu",
        "jain-dup",
        pr.number,
        MergePullRequestRequest::default(),
    ));
    assert_archived(core.create_commit_status(
        "jeryu",
        "jain-dup",
        "abc123",
        "ci",
        CreateCommitStatusRequest {
            state: CommitStatusState::Success,
            context: "ci".to_string(),
            description: None,
            target_url: None,
        },
    ));
    assert_archived(core.create_check_run(
        "jeryu",
        "jain-dup",
        CreateCheckRunRequest {
            name: "ci".to_string(),
            head_sha: "abc123".to_string(),
            ..Default::default()
        },
    ));
    assert_archived(core.force_push("jeryu", "jain-dup", "topic", true));
    assert_archived(core.delete_ref("jeryu", "jain-dup", "topic", true));
    assert_archived(core.ensure_repository_writable("jeryu", "jain-dup"));

    // Reads keep working; protection and history are untouched.
    assert!(core.get_repository("jeryu", "jain-dup").unwrap().archived);
    assert_eq!(
        core.get_pull_request("jeryu", "jain-dup", pr.number)
            .unwrap()
            .number,
        pr.number
    );
    assert!(
        core.get_branch_protection("jeryu", "jain-dup", "main")
            .is_ok()
    );

    let restored = core
        .set_repository_archived("alton", "jeryu", "jain-dup", false)
        .unwrap();
    assert!(!restored.archived);
    core.ensure_repository_writable("jeryu", "jain-dup")
        .unwrap();
    core.create_pull_request("jeryu", "jain-dup", "jeryu", pr_request())
        .unwrap();
    core.force_push("jeryu", "jain-dup", "topic", true).unwrap();
}

#[test]
fn archiving_an_unknown_repository_is_not_found() {
    let core = ForgeCore::new();
    assert!(matches!(
        core.set_repository_archived("alton", "jeryu", "missing", true),
        Err(ForgeError::NotFound(_))
    ));
    assert!(matches!(
        core.ensure_repository_writable("jeryu", "missing"),
        Err(ForgeError::NotFound(_))
    ));
}

#[test]
fn archived_flag_survives_reopen_and_is_audited_with_the_actor() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("forge.sqlite");
    {
        let core = ForgeCore::open_sqlite(&db).unwrap();
        create_repo(&core, "jain-old");
        core.set_repository_archived("alton", "jeryu", "jain-old", true)
            .unwrap();
    }
    {
        let core = ForgeCore::open_sqlite(&db).unwrap();
        assert!(core.get_repository("jeryu", "jain-old").unwrap().archived);
        assert_archived(core.create_pull_request("jeryu", "jain-old", "jeryu", pr_request()));
        let audit = core.list_audit("jeryu/jain-old").unwrap();
        let phases: Vec<_> = audit
            .iter()
            .filter(|entry| entry.action == "repository.archived")
            .map(|entry| (entry.actor.as_str(), entry.phase.as_str()))
            .collect();
        assert_eq!(phases, vec![("alton", "requested"), ("alton", "completed")]);
        core.set_repository_archived("alton", "jeryu", "jain-old", false)
            .unwrap();
    }
    let core = ForgeCore::open_sqlite(&db).unwrap();
    assert!(!core.get_repository("jeryu", "jain-old").unwrap().archived);
    core.create_pull_request("jeryu", "jain-old", "jeryu", pr_request())
        .unwrap();
}
