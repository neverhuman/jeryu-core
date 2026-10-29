//! Administrator dismissal of another reviewer's verdict: bound like a merge
//! override, recorded with its authority, and audited.

use jeryu_core::{
    CreatePullRequestRequest, CreateRepositoryRequest, CreateReviewRequest, DismissReviewRequest,
    DismissalAuthority, ForgeCore, ForgeError, MergeBlocker, RepoAccessLevel, Review, ReviewState,
    SetBranchProtectionRequest, UserRole, effective_reviews_for_head,
};

const HEAD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NEXT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SUBJECT: &str = "owner/demo#1";
const ACTION: &str = "pull.review_dismissal";

/// A branch that opts in to administrator dismissal and does not enforce
/// administrators: the only shape on which a cross-author dismissal is allowed.
/// `allow_merge_override` stays off -- the dismissal opt-in stands alone.
fn opted_in() -> SetBranchProtectionRequest {
    SetBranchProtectionRequest {
        required_approving_review_count: 1,
        allow_admin_review_dismissal: true,
        enforce_admins: false,
        ..Default::default()
    }
}

fn seed_with(core: &ForgeCore, protection: Option<SetBranchProtectionRequest>) {
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
    if let Some(protection) = protection {
        core.set_branch_protection("owner", "demo", "main", protection)
            .unwrap();
    }
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
        ("contributor", RepoAccessLevel::Admin),
        ("writer", RepoAccessLevel::Write),
        ("reader", RepoAccessLevel::Read),
    ] {
        core.create_account(actor, "correct horse battery", UserRole::User)
            .unwrap();
        core.grant_repo_access("owner", actor, "owner", "demo", access)
            .unwrap();
    }
}

fn seed(core: &ForgeCore) {
    seed_with(core, Some(opted_in()));
}

fn durable() -> (tempfile::TempDir, std::path::PathBuf, ForgeCore) {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("forge.sqlite");
    let core = ForgeCore::open_sqlite(&db).unwrap();
    (temp, db, core)
}

fn submit(core: &ForgeCore, actor: &str, event: ReviewState) -> Review {
    try_submit(core, actor, event).unwrap()
}

fn try_submit(core: &ForgeCore, actor: &str, event: ReviewState) -> jeryu_core::Result<Review> {
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

fn mergeable(core: &ForgeCore) -> bool {
    core.get_pull_request("owner", "demo", 1).unwrap().mergeable
}

fn receipts(core: &ForgeCore) -> Vec<(String, String)> {
    core.list_audit(SUBJECT)
        .unwrap()
        .into_iter()
        .filter(|entry| entry.action == ACTION)
        .map(|entry| (entry.actor, entry.phase))
        .collect()
}

#[test]
fn administrator_dismissal_survives_reopen_and_later_access_loss() {
    // `owner` is a global admin; `admin` holds an explicit repository grant.
    for actor in ["owner", "admin"] {
        let (_temp, db, core) = durable();
        seed(&core);
        let approval = submit(&core, "writer", ReviewState::Approved);
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
        assert_eq!(
            dismissed.dismissal_authority,
            Some(DismissalAuthority::RepositoryAdmin)
        );
        assert!(!has_rejection(&core));
        assert!(mergeable(&core));
        assert_eq!(
            receipts(&core),
            vec![
                (actor.to_string(), "requested".to_string()),
                (actor.to_string(), "completed".to_string()),
            ]
        );
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
fn a_single_administrator_cannot_approve_and_dismiss_to_reach_mergeable() {
    // Approve first, then dismiss the only rejection: refused.
    let (_temp, _db, core) = durable();
    seed(&core);
    submit(&core, "admin", ReviewState::Approved);
    let target = submit(&core, "reviewer", ReviewState::ChangesRequested);
    let before = core.list_reviews("owner", "demo", 1).unwrap();
    assert!(matches!(
        core.dismiss_review("owner", "demo", 1, "admin", request(&target)),
        Err(ForgeError::Forbidden(_))
    ));
    assert_eq!(core.list_reviews("owner", "demo", 1).unwrap(), before);
    assert!(has_rejection(&core));
    assert!(!mergeable(&core));
    assert_eq!(
        receipts(&core),
        vec![("admin".to_string(), "failed".to_string())]
    );

    // Dismiss first, then approve: the approval is refused, so the required
    // review still has to come from someone else.
    let (_temp, _db, core) = durable();
    seed(&core);
    let target = submit(&core, "reviewer", ReviewState::ChangesRequested);
    core.dismiss_review("owner", "demo", 1, "admin", request(&target))
        .unwrap();
    assert!(!has_rejection(&core));
    assert!(!mergeable(&core), "no independent approval yet");
    assert!(matches!(
        try_submit(&core, "admin", ReviewState::Approved),
        Err(ForgeError::Forbidden(_))
    ));
    assert!(!mergeable(&core));
    submit(&core, "writer", ReviewState::Approved);
    assert!(mergeable(&core));
}

#[test]
fn branch_protection_ignores_approvals_from_a_dismissing_administrator() {
    // A row set no current Core path can produce (an approval written next
    // to the same actor's administrator dismissal) still yields no approval.
    let (_temp, _db, core) = durable();
    seed(&core);
    let target = submit(&core, "reviewer", ReviewState::ChangesRequested);
    let dismissal = core
        .dismiss_review("owner", "demo", 1, "admin", request(&target))
        .unwrap();
    let approval = submit(&core, "writer", ReviewState::Approved);
    let mut forged = approval.clone();
    forged.id = uuid::Uuid::new_v4();
    forged.author = "admin".into();
    let history = [target, dismissal, forged];
    assert!(effective_reviews_for_head(&history, HEAD).is_empty());
}

#[test]
fn cross_author_dismissal_rows_need_recorded_authority() {
    let (_temp, _db, core) = durable();
    seed(&core);
    let target = submit(&core, "reviewer", ReviewState::ChangesRequested);
    let dismissal = core
        .dismiss_review("owner", "demo", 1, "admin", request(&target))
        .unwrap();
    let history = [target.clone(), dismissal.clone()];
    assert!(effective_reviews_for_head(&history, HEAD).is_empty());
    // The same row from a writer that recorded no authority withdraws nothing.
    let mut unrecorded = dismissal;
    unrecorded.dismissal_authority = None;
    let history = [target, unrecorded];
    assert_eq!(
        effective_reviews_for_head(&history, HEAD),
        vec![&history[0]]
    );
}

#[test]
fn cross_author_dismissal_is_bound_by_the_branch_rule() {
    let refusals = [
        // No rule at all.
        None,
        // A rule that does not opt in.
        Some(SetBranchProtectionRequest {
            required_approving_review_count: 1,
            ..Default::default()
        }),
        // Status-check overrides are allowed, but reviewer holds are not:
        // `allow_merge_override` does not carry dismissal with it.
        Some(SetBranchProtectionRequest {
            required_approving_review_count: 1,
            allow_merge_override: true,
            merge_override_status_checks: vec!["ci/fast".to_string()],
            merge_override_status_creators: vec!["ci-bot".to_string()],
            ..Default::default()
        }),
        // Opted in, but the branch binds administrators too.
        Some(SetBranchProtectionRequest {
            enforce_admins: true,
            ..opted_in()
        }),
    ];
    for protection in refusals {
        let (_temp, _db, core) = durable();
        seed_with(&core, protection.clone());
        let target = submit(&core, "reviewer", ReviewState::ChangesRequested);
        let before = core.list_reviews("owner", "demo", 1).unwrap();
        for actor in ["owner", "admin"] {
            assert!(
                matches!(
                    core.dismiss_review("owner", "demo", 1, actor, request(&target)),
                    Err(ForgeError::Forbidden(_))
                ),
                "{actor} under {protection:?}"
            );
        }
        assert_eq!(core.list_reviews("owner", "demo", 1).unwrap(), before);
        assert_eq!(
            receipts(&core),
            vec![
                ("owner".to_string(), "failed".to_string()),
                ("admin".to_string(), "failed".to_string()),
            ]
        );
        // The reviewer may still withdraw their own verdict.
        core.dismiss_review("owner", "demo", 1, "reviewer", request(&target))
            .unwrap();
        assert!(!has_rejection(&core));
    }
}

#[test]
fn the_pull_request_author_cannot_dismiss_another_reviewer() {
    let (_temp, _db, core) = durable();
    seed(&core);
    let target = submit(&core, "reviewer", ReviewState::ChangesRequested);
    assert!(matches!(
        core.dismiss_review("owner", "demo", 1, "contributor", request(&target)),
        Err(ForgeError::Forbidden(_))
    ));
    assert!(has_rejection(&core));
}

#[test]
fn a_repository_owner_without_admin_access_cannot_dismiss() {
    // Core has no implicit owner rule: owning the namespace is not repository
    // administrator access. Only the global admin role or an Admin grant is.
    let (_temp, _db, core) = durable();
    core.create_account("plain", "correct horse battery", UserRole::User)
        .unwrap();
    core.create_repository(
        "plain",
        CreateRepositoryRequest {
            name: "demo".into(),
            ..Default::default()
        },
    )
    .unwrap();
    core.set_branch_protection("plain", "demo", "main", opted_in())
        .unwrap();
    core.create_pull_request(
        "plain",
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
    let target = core
        .create_review(
            "plain",
            "demo",
            1,
            "reviewer",
            CreateReviewRequest {
                event: ReviewState::ChangesRequested,
                body: None,
                comments: vec![],
                expected_head_sha: Some(HEAD.into()),
            },
        )
        .unwrap();
    assert!(matches!(
        core.dismiss_review("plain", "demo", 1, "plain", request(&target)),
        Err(ForgeError::Forbidden(_))
    ));
}

#[test]
fn administrator_dismissal_requires_durable_audit_storage() {
    let core = ForgeCore::new();
    seed(&core);
    let target = submit(&core, "reviewer", ReviewState::ChangesRequested);
    assert!(matches!(
        core.dismiss_review("owner", "demo", 1, "admin", request(&target)),
        Err(ForgeError::Validation(message)) if message.contains("durable audit storage")
    ));
    assert!(has_rejection(&core));
}

#[test]
fn cross_author_dismissal_requires_active_admin_and_valid_current_head_request() {
    let (_temp, _db, core) = durable();
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

/// The opt-in is additive: a rule stored or sent without the field reads as
/// off, so an older payload never grants dismissal.
#[test]
fn an_absent_dismissal_opt_in_reads_as_off() {
    let stored: SetBranchProtectionRequest = serde_json::from_str(
        r#"{"required_status_checks":[],"required_approving_review_count":1,
            "enforce_admins":false,"allow_merge_override":true}"#,
    )
    .unwrap();
    assert!(!stored.allow_admin_review_dismissal);

    let (_temp, _db, core) = durable();
    seed_with(&core, Some(stored));
    let rule = core.get_branch_protection("owner", "demo", "main").unwrap();
    assert!(!rule.allow_admin_review_dismissal);
    let target = submit(&core, "reviewer", ReviewState::ChangesRequested);
    assert!(matches!(
        core.dismiss_review("owner", "demo", 1, "admin", request(&target)),
        Err(ForgeError::Forbidden(_))
    ));
    assert!(has_rejection(&core));

    // A rule JSON written before the field existed loads the same way.
    let older = serde_json::json!({
        "owner": "owner", "repo": "demo", "branch": "main",
        "required_status_checks": [], "required_approving_review_count": 1,
        "enforce_admins": false, "allow_merge_override": true,
        "required_linear_history": false, "allow_force_pushes": false,
        "allow_deletions": false, "require_signed_commits": false,
        "require_jankurai_proof": false, "updated_at": "2026-01-01T00:00:00Z",
    });
    let rule: jeryu_core::BranchProtectionRule = serde_json::from_value(older).unwrap();
    assert!(!rule.allow_admin_review_dismissal);
    assert!(rule.allow_merge_override);
}

/// With the dismissal opt-in on and every other gate met, the administrator
/// decision goes through even though status overrides are off.
#[test]
fn the_dismissal_opt_in_alone_permits_a_cross_author_dismissal() {
    let (_temp, _db, core) = durable();
    seed(&core);
    let rule = core.get_branch_protection("owner", "demo", "main").unwrap();
    assert!(rule.allow_admin_review_dismissal && !rule.allow_merge_override);
    let target = submit(&core, "reviewer", ReviewState::ChangesRequested);
    assert!(has_rejection(&core));
    let dismissal = core
        .dismiss_review("owner", "demo", 1, "admin", request(&target))
        .unwrap();
    assert_eq!(
        dismissal.dismissal_authority,
        Some(DismissalAuthority::RepositoryAdmin)
    );
    assert!(!has_rejection(&core));
    assert_eq!(
        receipts(&core),
        vec![
            ("admin".to_string(), "requested".to_string()),
            ("admin".to_string(), "completed".to_string()),
        ]
    );
}
