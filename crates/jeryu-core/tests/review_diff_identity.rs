//! Review identity is computed from real objects at the Core/gitd boundary.
use jeryu_core::{
    CreatePullRequestRequest, CreateRepositoryRequest, CreateReviewRequest, DismissReviewRequest,
    ForgeCore, ForgeError, MergeBlocker, ReviewState, SetBranchProtectionRequest,
};
use jeryu_gitd::{RepoId, repo::Repository};
use std::{path::Path, process::Command};

struct Fixture {
    _dir: tempfile::TempDir,
    repository: Repository,
    base: String,
    head: String,
    number: u64,
}

fn git(path: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(path)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

impl Fixture {
    fn new(core: &ForgeCore, dismiss: bool, exact: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path();
        git(path, &["init", "-q", "-b", "main"]);
        git(path, &["config", "user.name", "Author"]);
        git(path, &["config", "user.email", "author@example.invalid"]);
        std::fs::write(path.join("base"), "base\n").unwrap();
        git(path, &["add", "."]);
        git(path, &["commit", "-q", "-m", "base"]);
        let base = git(path, &["rev-parse", "HEAD"]);
        std::fs::write(path.join("feature"), "feature\n").unwrap();
        git(path, &["add", "."]);
        git(path, &["commit", "-q", "-m", "feature"]);
        let head = git(path, &["rev-parse", "HEAD"]);
        core.create_repository(
            "alice",
            CreateRepositoryRequest {
                name: "demo".into(),
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
                dismiss_stale_approvals: dismiss,
                require_exact_sha_approval: exact,
                ..Default::default()
            },
        )
        .unwrap();
        let number = core
            .create_pull_request(
                "alice",
                "demo",
                "author",
                CreatePullRequestRequest {
                    title: "change".into(),
                    head: "feature".into(),
                    base: "main".into(),
                    head_sha: Some(head.clone()),
                    base_sha: Some(base.clone()),
                    ..Default::default()
                },
            )
            .unwrap()
            .number;
        let repository = Repository {
            id: RepoId::new("alice", "demo").unwrap(),
            path: path.into(),
        };
        let fx = Self {
            _dir: dir,
            repository,
            base,
            head,
            number,
        };
        fx.refresh(core, &fx.base, &fx.head);
        fx
    }

    fn refresh(&self, core: &ForgeCore, base: &str, head: &str) {
        core.refresh_pull_request_heads_from_git(
            "alice",
            "demo",
            &self.repository.path,
            "feature",
            head,
            base,
        )
        .unwrap();
    }

    fn review(&self, core: &ForgeCore, event: ReviewState) {
        core.create_review(
            "alice",
            "demo",
            self.number,
            "reviewer",
            CreateReviewRequest {
                body: None,
                event,
                comments: vec![],
                expected_head_sha: Some(self.head.clone()),
            },
        )
        .unwrap();
    }

    fn rewrite(&self, message: &str) -> String {
        git(
            &self.repository.path,
            &[
                "-c",
                "user.name=Another Author",
                "commit",
                "--amend",
                "--author=Another <another@example.invalid>",
                "-q",
                "-m",
                message,
            ],
        );
        git(&self.repository.path, &["rev-parse", "HEAD"])
    }

    fn missing(&self, core: &ForgeCore) -> bool {
        core.evaluate_pull_request("alice", "demo", self.number, None)
            .unwrap()
            .blockers
            .iter()
            .any(|b| matches!(b, MergeBlocker::MissingReview { .. }))
    }
}

#[test]
fn same_base_message_and_diff_carry_and_can_be_withdrawn() {
    let core = ForgeCore::new();
    let fx = Fixture::new(&core, false, false);
    fx.review(&core, ReviewState::Approved);
    let next = fx.rewrite("feature");
    assert_ne!(next, fx.head);
    fx.refresh(&core, &fx.base, &next);
    assert!(!fx.missing(&core));
    let pr = core.get_pull_request("alice", "demo", fx.number).unwrap();
    assert!(pr.mergeable);
    assert_eq!(pr.commits.len(), 1);
    assert_eq!(pr.commits[0].sha, next);
    assert!(!pr.commits[0].verified);
    let review = core.list_reviews("alice", "demo", fx.number).unwrap()[0].id;
    core.dismiss_review(
        "alice",
        "demo",
        fx.number,
        "reviewer",
        DismissReviewRequest {
            review_id: review,
            expected_head_sha: next,
            reason: "withdrawn".into(),
        },
    )
    .unwrap();
    assert!(fx.missing(&core));
    fx.refresh(&core, &fx.base, &fx.head);
    assert!(fx.missing(&core));
}

#[test]
fn either_strict_setting_requires_a_new_review() {
    for (dismiss, exact) in [(true, true), (true, false), (false, true)] {
        let core = ForgeCore::new();
        let fx = Fixture::new(&core, dismiss, exact);
        fx.review(&core, ReviewState::Approved);
        fx.refresh(&core, &fx.base, &fx.rewrite("feature"));
        assert!(fx.missing(&core));
    }
}

#[test]
fn reword_and_content_edit_require_fresh_review() {
    for edit in [false, true] {
        let core = ForgeCore::new();
        let fx = Fixture::new(&core, false, false);
        fx.review(&core, ReviewState::Approved);
        if edit {
            std::fs::write(fx.repository.path.join("feature"), "changed\n").unwrap();
            git(&fx.repository.path, &["add", "."]);
        }
        fx.refresh(
            &core,
            &fx.base,
            &fx.rewrite(if edit { "feature" } else { "reword" }),
        );
        assert!(fx.missing(&core));
    }
}

#[test]
fn changed_base_cannot_recover_an_approval() {
    let core = ForgeCore::new();
    let fx = Fixture::new(&core, false, false);
    fx.review(&core, ReviewState::Approved);
    git(
        &fx.repository.path,
        &["checkout", "-q", "--detach", &fx.base],
    );
    std::fs::write(fx.repository.path.join("other"), "new base\n").unwrap();
    git(&fx.repository.path, &["add", "."]);
    git(&fx.repository.path, &["commit", "-q", "-m", "base moves"]);
    let base = git(&fx.repository.path, &["rev-parse", "HEAD"]);
    core.record_pull_request_base("forge", "alice", "demo", fx.number, &fx.head, &base)
        .unwrap();
    git(&fx.repository.path, &["cherry-pick", &fx.head]);
    let head = git(&fx.repository.path, &["rev-parse", "HEAD"]);
    fx.refresh(&core, &base, &head);
    assert!(fx.missing(&core));
}

#[test]
fn supplied_identities_and_invalid_bases_are_refused_without_mutation() {
    let core = ForgeCore::new();
    let fx = Fixture::new(&core, false, false);
    let digest = format!("v2:{}", "a".repeat(64));
    for ids in [
        vec![digest.clone()],
        vec![digest.clone(); 256],
        vec![digest; 257],
    ] {
        assert!(matches!(
            core.refresh_pull_request_heads_for_ref_with_diff(
                "alice", "demo", "feature", &fx.base, &fx.base, &ids
            ),
            Err(ForgeError::Validation(_))
        ));
    }
    for base in ["base", "--all", ""] {
        assert!(
            core.refresh_pull_request_heads_from_git(
                "alice",
                "demo",
                &fx.repository.path,
                "feature",
                &fx.head,
                base
            )
            .is_err()
        );
        assert!(
            core.refresh_pull_request_heads_for_ref_with_diff(
                "alice",
                "demo",
                "feature",
                &fx.base,
                base,
                &[]
            )
            .is_err()
        );
    }
    assert_eq!(
        core.get_pull_request("alice", "demo", fx.number)
            .unwrap()
            .head
            .sha,
        fx.head
    );
}

#[test]
fn identity_and_verdict_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("forge.sqlite");
    let core = ForgeCore::open_sqlite(&db).unwrap();
    let fx = Fixture::new(&core, false, false);
    fx.review(&core, ReviewState::Approved);
    fx.refresh(&core, &fx.base, &fx.rewrite("feature"));
    drop(core);
    let core = ForgeCore::open_sqlite(&db).unwrap();
    assert!(!fx.missing(&core));
    assert!(
        !core
            .get_pull_request("alice", "demo", fx.number)
            .unwrap()
            .head_patch_ids
            .is_empty()
    );
}

#[test]
fn rejection_carries_and_unknown_identity_requires_fresh_review() {
    let core = ForgeCore::new();
    let fx = Fixture::new(&core, false, false);
    fx.review(&core, ReviewState::ChangesRequested);
    fx.refresh(&core, &fx.base, &fx.rewrite("feature"));
    assert!(
        core.evaluate_pull_request("alice", "demo", fx.number, None)
            .unwrap()
            .blockers
            .iter()
            .any(|b| matches!(b, MergeBlocker::ChangesRequested { .. }))
    );
    let core = ForgeCore::new();
    let fx = Fixture::new(&core, false, false);
    fx.review(&core, ReviewState::Approved);
    let next = fx.rewrite("feature");
    core.refresh_pull_request_heads_for_ref("alice", "demo", "feature", &next)
        .unwrap();
    assert!(fx.missing(&core));
}

#[test]
fn refreshed_commit_metadata_enforces_signature_and_linear_history_rules() {
    let core = ForgeCore::new();
    let fx = Fixture::new(&core, false, false);
    fx.review(&core, ReviewState::Approved);
    core.set_branch_protection(
        "alice",
        "demo",
        "main",
        SetBranchProtectionRequest {
            required_approving_review_count: 1,
            require_signed_commits: true,
            required_linear_history: true,
            dismiss_stale_approvals: false,
            require_exact_sha_approval: false,
            ..Default::default()
        },
    )
    .unwrap();
    let next = fx.rewrite("feature");
    fx.refresh(&core, &fx.base, &next);
    let blockers = core
        .evaluate_pull_request("alice", "demo", fx.number, None)
        .unwrap()
        .blockers;
    assert!(blockers.iter().any(|b| matches!(b, MergeBlocker::UnsignedCommits { unsigned } if unsigned == &vec![next.clone()])));
    assert!(
        !fx.missing(&core),
        "the approval still carries, but signatures are rechecked"
    );

    git(
        &fx.repository.path,
        &["checkout", "-q", "-b", "side", &fx.base],
    );
    std::fs::write(fx.repository.path.join("side"), "side\n").unwrap();
    git(&fx.repository.path, &["add", "."]);
    git(&fx.repository.path, &["commit", "-q", "-m", "side"]);
    git(&fx.repository.path, &["checkout", "-q", "--detach", &next]);
    git(
        &fx.repository.path,
        &["merge", "-q", "--no-ff", "-m", "merge", "side"],
    );
    let merged = git(&fx.repository.path, &["rev-parse", "HEAD"]);
    fx.refresh(&core, &fx.base, &merged);
    let blockers = core
        .evaluate_pull_request("alice", "demo", fx.number, None)
        .unwrap()
        .blockers;
    assert!(
        blockers
            .iter()
            .any(|b| matches!(b, MergeBlocker::NonLinearHistory { sha } if sha == &merged))
    );
    assert!(fx.missing(&core));
}

#[test]
fn untagged_stored_identities_cannot_carry_approvals() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("forge.sqlite");
    let core = ForgeCore::open_sqlite(&db).unwrap();
    let fx = Fixture::new(&core, false, false);
    fx.review(&core, ReviewState::Approved);
    fx.refresh(&core, &fx.base, &fx.rewrite("feature"));
    assert!(!fx.missing(&core));
    drop(core);
    let conn = rusqlite::Connection::open(&db).unwrap();
    let untagged = serde_json::to_string(&vec!["a".repeat(64)]).unwrap();
    conn.execute(
        "UPDATE pull_requests SET head_patch_ids_json = ?1",
        [&untagged],
    )
    .unwrap();
    conn.execute("UPDATE reviews SET head_patch_ids_json = ?1", [&untagged])
        .unwrap();
    drop(conn);
    let core = ForgeCore::open_sqlite(&db).unwrap();
    assert!(
        fx.missing(&core),
        "identities without base/message bindings fail closed"
    );
    fx.refresh(&core, &fx.base, &fx.head);
    assert!(
        !fx.missing(&core),
        "the original exact-head approval remains usable"
    );
}
