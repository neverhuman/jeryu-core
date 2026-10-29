//! Administrator dismissals use repository grants and preserve durable evidence.

use jeryu_core::{
    CreatePullRequestRequest, CreateRepositoryRequest, CreateReviewRequest, DismissReviewRequest,
    ForgeCore, ForgeError, MergeBlocker, RepoAccessLevel, Review, ReviewState,
    SetBranchProtectionRequest, UserRole, effective_reviews_for_head,
};

const HEAD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NEXT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn seed(core: &ForgeCore) {
    core.create_account("owner", "correct horse battery", UserRole::Admin)
        .unwrap();
    core.create_repository(
        "owner",
        CreateRepositoryRequest {
            name: "demo".into(),
            ..Default::default()
        },
    )
    .unwrap();
    core.set_branch_protection(
        "owner",
        "demo",
        "main",
        SetBranchProtectionRequest {
            required_approving_review_count: 1,
            ..Default::default()
        },
    )
    .unwrap();
    core.create_pull_request(
        "owner",
        "demo",
        "contributor",
        CreatePullRequestRequest {
            title: "change".into(),
            head: "feature".into(),
            base: "main".into(),
            head_sha: Some(HEAD.into()),
            ..Default::default()
        },
    )
    .unwrap();
    for (actor, access) in [
        ("admin", RepoAccessLevel::Admin),
        ("writer", RepoAccessLevel::Write),
        ("reader", RepoAccessLevel::Read),
    ] {
        core.create_account(actor, "correct horse battery", UserRole::User)
            .unwrap();
        core.grant_repo_access("owner", actor, "owner", "demo", access)
            .unwrap();
    }
}

fn submit(core: &ForgeCore, actor: &str, event: ReviewState) -> Review {
    core.create_review(
        "owner",
        "demo",
        1,
        actor,
        CreateReviewRequest {
            event,
            body: Some("review evidence".into()),
            comments: vec![],
            expected_head_sha: Some(HEAD.into()),
        },
    )
    .unwrap()
}

fn request(target: &Review) -> DismissReviewRequest {
    DismissReviewRequest {
        review_id: target.id,
        expected_head_sha: HEAD.into(),
        reason: "verified upstream revision independently".into(),
    }
}

fn has_rejection(core: &ForgeCore) -> bool {
    core.evaluate_pull_request("owner", "demo", 1, Some(HEAD))
        .unwrap()
        .blockers
        .iter()
        .any(|blocker| matches!(blocker, MergeBlocker::ChangesRequested { .. }))
}

#[test]
fn owner_and_repository_admin_dismiss_without_erasing_history_or_future_verdicts() {
    for actor in ["owner", "admin"] {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("forge.sqlite");
        let core = ForgeCore::open_sqlite(&db).unwrap();
        seed(&core);
        let approval = submit(&core, actor, ReviewState::Approved);
        let target = submit(&core, "reviewer", ReviewState::ChangesRequested);
        assert!(has_rejection(&core));
        let dismissed = core
            .dismiss_review("owner", "demo", 1, actor, request(&target))
            .unwrap();
        assert_eq!(dismissed.author, actor);
        assert_eq!(dismissed.body, Some(request(&target).reason));
        assert_eq!(dismissed.head_sha.as_deref(), Some(HEAD));
        assert_eq!(dismissed.dismissed_review_id, Some(target.id));
        assert_eq!(dismissed.state, ReviewState::Dismissed);
        assert!(!has_rejection(&core));
        assert!(core.get_pull_request("owner", "demo", 1).unwrap().mergeable);
        // Authorization is checked on write; losing access cannot restore a hold.
        core.disable_account(actor).unwrap();
        drop(core);
        let core = ForgeCore::open_sqlite(&db).unwrap();
        core.set_repository_readme("owner", "demo", "unrelated write".into())
            .unwrap();
        let history = core.list_reviews("owner", "demo", 1).unwrap();
        assert_eq!(history, vec![approval.clone(), target, dismissed]);
        assert_eq!(effective_reviews_for_head(&history, HEAD), vec![&approval]);
        assert!(!has_rejection(&core));
        let renewed = submit(&core, "reviewer", ReviewState::ChangesRequested);
        assert!(has_rejection(&core));
        let history = core.list_reviews("owner", "demo", 1).unwrap();
        assert!(effective_reviews_for_head(&history, HEAD).contains(&&renewed));
    }
}

#[test]
fn cross_author_dismissal_requires_active_admin_and_valid_current_head_request() {
    let core = ForgeCore::new();
    seed(&core);
    let target = submit(&core, "reviewer", ReviewState::ChangesRequested);
    let before = core.list_reviews("owner", "demo", 1).unwrap();
    for actor in ["writer", "reader", "unknown"] {
        assert!(matches!(
            core.dismiss_review("owner", "demo", 1, actor, request(&target)),
            Err(ForgeError::Forbidden(_))
        ));
    }
    for reason in ["", " \n\t"] {
        let mut invalid = request(&target);
        invalid.reason = reason.into();
        assert!(matches!(
            core.dismiss_review("owner", "demo", 1, "admin", invalid),
            Err(ForgeError::Validation(_))
        ));
    }
    let mut invalid = request(&target);
    invalid.expected_head_sha = NEXT.into();
    assert!(matches!(
        core.dismiss_review("owner", "demo", 1, "admin", invalid),
        Err(ForgeError::Conflict(_))
    ));
    core.disable_account("admin").unwrap();
    assert!(matches!(
        core.dismiss_review("owner", "demo", 1, "admin", request(&target)),
        Err(ForgeError::Forbidden(_))
    ));
    assert_eq!(core.list_reviews("owner", "demo", 1).unwrap(), before);
    assert!(has_rejection(&core));
    core.dismiss_review("owner", "demo", 1, "reviewer", request(&target))
        .unwrap();
    assert!(!has_rejection(&core));
}
