use super::*;

fn durable_core() -> (tempfile::TempDir, ForgeCore) {
    let dir = tempfile::tempdir().unwrap();
    let core = ForgeCore::open_sqlite(dir.path().join("forge.sqlite")).unwrap();
    (dir, core)
}

fn fixture(core: &ForgeCore) -> PullRequest {
    core.create_account("alice", "alice-password-1", UserRole::Admin)
        .unwrap();
    core.create_account("reviewer", "reviewer-password-1", UserRole::User)
        .unwrap();
    core.create_account("author", "author-password-1", UserRole::User)
        .unwrap();
    core.create_repository(
        "alice",
        CreateRepositoryRequest {
            name: "jeryu".into(),
            private: false,
            description: None,
            default_branch: Some("main".into()),
        },
    )
    .unwrap();
    protection(core, false);
    let pr = core
        .create_pull_request(
            "alice",
            "jeryu",
            "author",
            CreatePullRequestRequest {
                title: "Accept ratchet decision".into(),
                body: None,
                head: "decision".into(),
                base: "main".into(),
                head_sha: Some("exact-head".into()),
                base_sha: Some("base-head".into()),
                source_repository: None,
                draft: false,
                commits: vec![],
                changed_files: vec![],
            },
        )
        .unwrap();
    core.create_review(
        "alice",
        "jeryu",
        pr.number,
        "reviewer",
        CreateReviewRequest {
            body: Some("Independent source approval".into()),
            event: ReviewState::Approved,
            comments: vec![],
            expected_head_sha: Some(pr.head.sha.clone()),
        },
    )
    .unwrap();
    core.create_commit_status(
        "alice",
        "jeryu",
        &pr.head.sha,
        "reviewer",
        CreateCommitStatusRequest {
            state: CommitStatusState::Failure,
            context: "ratchet".into(),
            description: Some("94 to 92 requires a decision".into()),
            target_url: None,
        },
    )
    .unwrap();
    pr
}

fn protection(core: &ForgeCore, enforce_admins: bool) {
    core.set_branch_protection(
        "alice",
        "jeryu",
        "main",
        SetBranchProtectionRequest {
            required_status_checks: vec!["ratchet".into()],
            strict: false,
            required_approving_review_count: 1,
            enforce_admins,
            allow_merge_override: true,
            merge_override_status_checks: vec!["ratchet".into()],
            required_linear_history: false,
            allow_force_pushes: false,
            allow_deletions: false,
            require_signed_commits: false,
            require_jankurai_proof: false,
        },
    )
    .unwrap();
}

fn decision(actor: &str) -> MergeOverrideRequest {
    MergeOverrideRequest {
        actor: actor.into(),
        reason: "Owner decision: accept the ratchet floor of 92".into(),
        expected_head_sha: "exact-head".into(),
        expected_passport_hash: "passport:exact-gate".into(),
    }
}

#[test]
fn merge_override_records_exact_decision_and_blockers_durably() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("forge.sqlite");
    let core = ForgeCore::open_sqlite(&path).unwrap();
    let pr = fixture(&core);
    let before = core
        .evaluate_pull_request("alice", "jeryu", pr.number, Some(&pr.head.sha))
        .unwrap();
    assert!(!before.mergeable);
    assert!(
        before
            .blockers
            .iter()
            .any(|blocker| matches!(blocker, crate::MergeBlocker::FailedStatusCheck { .. }))
    );
    assert!(
        !before
            .blockers
            .iter()
            .any(|blocker| matches!(blocker, crate::MergeBlocker::ChangesRequested { .. }))
    );
    assert!(
        core.evaluate_merge_readiness("alice", "jeryu", pr.number, Some(&pr.head.sha))
            .is_err()
    );
    let (_, permit) = core
        .prepare_merge_override("alice", "jeryu", pr.number, decision("alice"))
        .unwrap();
    assert_eq!(
        core.evaluate_pull_request("alice", "jeryu", pr.number, Some(&pr.head.sha))
            .unwrap(),
        before
    );
    let result = core
        .finalize_merge_with_override(permit, "real-git-merge".into())
        .unwrap();
    assert!(result.merged);
    assert!(
        !core
            .get_branch_protection("alice", "jeryu", "main")
            .unwrap()
            .enforce_admins
    );
    drop(core);
    let reopened = ForgeCore::open_sqlite(&path).unwrap();
    let audit = reopened
        .list_audit(&format!("alice/jeryu#{}", pr.number))
        .unwrap();
    assert_eq!(audit.len(), 2);
    assert_eq!(audit[0].phase, "requested");
    assert_eq!(audit[1].phase, "completed");
    assert_eq!(audit[1].actor, "alice");
    assert_eq!(audit[1].action, "pull.merge_override");
    assert_eq!(audit[1].detail["head_sha"], pr.head.sha);
    assert_eq!(
        audit[1].detail["caller_passport_hash"],
        "passport:exact-gate"
    );
    assert_eq!(audit[1].detail["reason"], decision("alice").reason);
    assert_eq!(audit[1].detail["merge_sha"], "real-git-merge");
    assert_eq!(
        audit[1].detail["blockers"],
        serde_json::to_value(before.blockers).unwrap()
    );
}

#[test]
fn merge_override_requires_active_admin_reason_protection_and_exact_head() {
    let (_dir, core) = durable_core();
    let pr = fixture(&core);
    for actor in ["reviewer", "unknown"] {
        assert!(
            core.prepare_merge_override("alice", "jeryu", pr.number, decision(actor))
                .is_err()
        );
    }
    for field in ["reason", "passport", "head"] {
        let mut request = decision("alice");
        match field {
            "reason" => request.reason = " \n ".into(),
            "passport" => request.expected_passport_hash.clear(),
            _ => request.expected_head_sha = "another-head".into(),
        }
        assert!(
            core.prepare_merge_override("alice", "jeryu", pr.number, request)
                .is_err()
        );
    }
    protection(&core, true);
    assert!(
        core.prepare_merge_override("alice", "jeryu", pr.number, decision("alice"))
            .is_err()
    );
    protection(&core, false);
    core.lock_account("alice").unwrap();
    assert!(
        core.prepare_merge_override("alice", "jeryu", pr.number, decision("alice"))
            .is_err()
    );
}

#[test]
fn merge_override_rechecks_policy_and_grants_at_finalize() {
    for mutation in ["rule", "grant", "check", "head", "draft", "closed"] {
        let (_dir, core) = durable_core();
        let pr = fixture(&core);
        core.grant_repo_access(
            "alice",
            "reviewer",
            "alice",
            "jeryu",
            RepoAccessLevel::Admin,
        )
        .unwrap();
        let (_, permit) = core
            .prepare_merge_override("alice", "jeryu", pr.number, decision("reviewer"))
            .unwrap();
        match mutation {
            "rule" => protection(&core, true),
            "grant" => {
                core.revoke_repo_access("reviewer", "alice", "jeryu")
                    .unwrap();
            }
            "check" => {
                core.create_commit_status(
                    "alice",
                    "jeryu",
                    &pr.head.sha,
                    "reviewer",
                    CreateCommitStatusRequest {
                        state: CommitStatusState::Success,
                        context: "ratchet".into(),
                        description: None,
                        target_url: None,
                    },
                )
                .unwrap();
            }
            _ => {
                let mut state = core.state.write();
                let current = state
                    .pulls
                    .get_mut(&("alice".into(), "jeryu".into(), pr.number))
                    .unwrap();
                match mutation {
                    "head" => current.head.sha = "new-head".into(),
                    "draft" => current.draft = true,
                    _ => current.state = PullRequestState::Closed,
                }
            }
        }
        assert!(
            core.finalize_merge_with_override(permit, "real-merge".into())
                .is_err(),
            "{mutation}"
        );
        assert!(
            !core
                .get_pull_request("alice", "jeryu", pr.number)
                .unwrap()
                .merged
        );
    }
}

#[test]
fn merge_override_accepts_repository_admin_without_global_admin_role() {
    let (_dir, core) = durable_core();
    let pr = fixture(&core);
    core.grant_repo_access(
        "alice",
        "reviewer",
        "alice",
        "jeryu",
        RepoAccessLevel::Admin,
    )
    .unwrap();
    let (_, permit) = core
        .prepare_merge_override("alice", "jeryu", pr.number, decision("reviewer"))
        .unwrap();
    assert!(
        core.finalize_merge_with_override(permit, "real-merge".into())
            .unwrap()
            .merged
    );
}

#[test]
fn merge_override_preserves_review_and_proof_gates_and_requires_opt_in() {
    for missing in ["review", "proof", "opt_in", "self_author"] {
        let (_dir, core) = durable_core();
        let pr = fixture(&core);
        if missing == "review" {
            core.create_review(
                "alice",
                "jeryu",
                pr.number,
                "reviewer",
                CreateReviewRequest {
                    body: Some("Unresolved defect".into()),
                    event: ReviewState::ChangesRequested,
                    comments: vec![],
                    expected_head_sha: Some(pr.head.sha.clone()),
                },
            )
            .unwrap();
        } else if missing == "self_author" {
            core.grant_repo_access("alice", "author", "alice", "jeryu", RepoAccessLevel::Admin)
                .unwrap();
        } else {
            let mut state = core.state.write();
            let rule = state
                .branch_protections
                .get_mut(&("alice".into(), "jeryu".into(), "main".into()))
                .unwrap();
            if missing == "proof" {
                rule.require_jankurai_proof = true;
            } else {
                rule.allow_merge_override = false;
            }
        }
        let actor = if missing == "self_author" {
            "author"
        } else {
            "alice"
        };
        assert!(
            core.prepare_merge_override("alice", "jeryu", pr.number, decision(actor))
                .is_err(),
            "{missing}"
        );
        assert!(
            !core
                .get_pull_request("alice", "jeryu", pr.number)
                .unwrap()
                .merged
        );
    }
}

#[test]
fn merge_override_requires_a_durable_store() {
    let core = ForgeCore::new();
    let pr = fixture(&core);
    let error = core
        .prepare_merge_override("alice", "jeryu", pr.number, decision("alice"))
        .unwrap_err();
    assert!(error.to_string().contains("durable audit storage"));
}

#[test]
fn merge_override_completion_and_state_commit_atomically() {
    let (dir, core) = durable_core();
    let pr = fixture(&core);
    let (_, permit) = core
        .prepare_merge_override("alice", "jeryu", pr.number, decision("alice"))
        .unwrap();
    let conn = rusqlite::Connection::open(dir.path().join("forge.sqlite")).unwrap();
    conn.execute_batch("CREATE TRIGGER reject_override_completion BEFORE INSERT ON forge_audit_log WHEN NEW.phase = 'completed' BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;").unwrap();
    assert!(
        core.finalize_merge_with_override(permit, "real-merge".into())
            .is_err()
    );
    assert!(
        !core
            .get_pull_request("alice", "jeryu", pr.number)
            .unwrap()
            .merged
    );
    let audit = core
        .list_audit(&format!("alice/jeryu#{}", pr.number))
        .unwrap();
    assert_eq!(
        audit
            .iter()
            .map(|row| row.phase.as_str())
            .collect::<Vec<_>>(),
        vec!["requested", "failed"]
    );
    drop(core);
    let reopened = ForgeCore::open_sqlite(dir.path().join("forge.sqlite")).unwrap();
    assert!(
        !reopened
            .get_pull_request("alice", "jeryu", pr.number)
            .unwrap()
            .merged
    );
    conn.execute_batch("DROP TRIGGER reject_override_completion;")
        .unwrap();
    let (_, permit) = reopened
        .prepare_merge_override("alice", "jeryu", pr.number, decision("alice"))
        .unwrap();
    assert!(
        reopened
            .finalize_merge_with_override(permit, "real-merge".into())
            .unwrap()
            .merged
    );
}

#[test]
fn merge_override_refusal_records_failed_and_expired_permits_do_not_merge() {
    let (_dir, core) = durable_core();
    let pr = fixture(&core);
    let (_, mut permit) = core
        .prepare_merge_override("alice", "jeryu", pr.number, decision("alice"))
        .unwrap();
    permit.expires_at = 0;
    assert!(
        core.finalize_merge_with_override(permit, "real-merge".into())
            .is_err()
    );
    let rows = core
        .list_audit(&format!("alice/jeryu#{}", pr.number))
        .unwrap();
    assert_eq!(rows.last().unwrap().phase, "failed");
    assert!(
        !core
            .get_pull_request("alice", "jeryu", pr.number)
            .unwrap()
            .merged
    );
}

#[test]
fn merge_override_cannot_clear_missing_reviews_unlisted_or_pending_contexts() {
    for refusal in ["unlisted", "pending", "review"] {
        let (_dir, core) = durable_core();
        let pr = fixture(&core);
        if refusal == "pending" {
            core.create_commit_status(
                "alice",
                "jeryu",
                &pr.head.sha,
                "reviewer",
                CreateCommitStatusRequest {
                    state: CommitStatusState::Pending,
                    context: "ratchet".into(),
                    description: None,
                    target_url: None,
                },
            )
            .unwrap();
        } else {
            let mut rule = core
                .get_branch_protection("alice", "jeryu", "main")
                .unwrap();
            if refusal == "unlisted" {
                rule.merge_override_status_checks.clear();
            } else {
                rule.required_approving_review_count = 2;
            }
            core.set_branch_protection(
                "alice",
                "jeryu",
                "main",
                SetBranchProtectionRequest {
                    required_status_checks: rule.required_status_checks,
                    required_approving_review_count: rule.required_approving_review_count,
                    allow_merge_override: true,
                    merge_override_status_checks: rule.merge_override_status_checks,
                    ..Default::default()
                },
            )
            .unwrap();
        }
        assert!(
            core.prepare_merge_override("alice", "jeryu", pr.number, decision("alice"))
                .is_err(),
            "{refusal}"
        );
        assert!(
            !core
                .get_pull_request("alice", "jeryu", pr.number)
                .unwrap()
                .merged
        );
    }
}
