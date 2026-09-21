//! Repository rename and owner move: re-keying, redirects, refusals, rollback.

use std::sync::{Arc, Mutex};

use jeryu_core::{
    CommitStatusState, CreateCommitStatusRequest, CreateDeploymentRequest, CreateIssueRequest,
    CreateLabelRequest, CreateOrganizationRequest, CreatePullRequestRequest,
    CreateRepositoryRequest, CreateUserRequest, CreateWebhookRequest, ForgeCore, ForgeError,
    RepoAccessLevel, RepoRelocator, RepositoryAliasOrigin, UserRole, WebhookConfig,
};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn create_repo(core: &ForgeCore, owner: &str, name: &str) -> jeryu_core::Repository {
    core.create_repository(
        owner,
        CreateRepositoryRequest {
            name: name.to_string(),
            private: true,
            description: None,
            default_branch: Some("main".to_string()),
        },
    )
    .unwrap()
}

fn create_org(core: &ForgeCore, login: &str) {
    core.create_organization(CreateOrganizationRequest {
        login: login.to_string(),
        display_name: None,
    })
    .unwrap();
}

/// A repository with state in every repo-scoped collection the API exposes.
fn seed(core: &ForgeCore) -> jeryu_core::Repository {
    let repo = create_repo(core, "jain-split", "jain-todo");
    core.create_account("operator", "correct horse battery", UserRole::Admin)
        .unwrap();
    core.grant_repo_access(
        "operator",
        "operator",
        "jain-split",
        "jain-todo",
        RepoAccessLevel::Admin,
    )
    .unwrap();
    core.create_label(
        "jain-split",
        "jain-todo",
        CreateLabelRequest {
            name: "release".to_string(),
            color: "ff0000".to_string(),
            description: None,
        },
    )
    .unwrap();
    core.create_issue(
        "jain-split",
        "jain-todo",
        "operator",
        CreateIssueRequest {
            title: "move me".to_string(),
            body: None,
            labels: vec!["release".to_string()],
            assignees: Vec::new(),
            milestone: None,
        },
    )
    .unwrap();
    core.create_pull_request(
        "jain-split",
        "jain-todo",
        "operator",
        CreatePullRequestRequest {
            title: "change".to_string(),
            head: "feature".to_string(),
            base: "main".to_string(),
            head_sha: Some("abc123".to_string()),
            source_repository: Some("jain-split/jain-todo".to_string()),
            ..Default::default()
        },
    )
    .unwrap();
    core.create_commit_status(
        "jain-split",
        "jain-todo",
        SHA,
        "ci",
        CreateCommitStatusRequest {
            state: CommitStatusState::Success,
            context: "ci/test".to_string(),
            description: None,
            target_url: None,
        },
    )
    .unwrap();
    core.create_webhook(
        "jain-split",
        "jain-todo",
        CreateWebhookRequest {
            name: "events".to_string(),
            active: true,
            events: vec!["issues".to_string()],
            config: WebhookConfig {
                url: "https://hooks.invalid/todo".to_string(),
                content_type: "json".to_string(),
                secret: None,
            },
        },
    )
    .unwrap();
    core.set_repository_readme("jain-split", "jain-todo", "# Todo\n".to_string())
        .unwrap();
    core.create_deployment(
        "jain-split",
        "jain-todo",
        "deployer",
        CreateDeploymentRequest {
            sha: SHA.to_string(),
            ref_name: None,
            task: "deploy".to_string(),
            environment: "prod".to_string(),
            description: None,
            payload: None,
            production_environment: None,
            transient_environment: false,
        },
    )
    .unwrap();
    repo
}

fn assert_moved(core: &ForgeCore, owner: &str, name: &str) {
    assert_eq!(core.list_labels(owner, name).unwrap().len(), 1);
    let issues = core.list_issues(owner, name, None).unwrap();
    // Pull requests are listed as issues too, as on GitHub.
    assert!(issues.iter().any(|issue| issue.title == "move me"));
    for issue in &issues {
        assert_eq!((issue.owner.as_str(), issue.repo.as_str()), (owner, name));
    }
    let pulls = core.list_pull_requests(owner, name, None).unwrap();
    assert_eq!(pulls.len(), 1);
    assert_eq!(pulls[0].source_repository, format!("{owner}/{name}"));
    assert_eq!(
        core.combined_status(owner, name, SHA).unwrap().total_count,
        1
    );
    assert_eq!(core.list_webhooks(owner, name).unwrap().len(), 1);
    assert!(core.get_branch_protection(owner, name, "main").is_ok());
    assert_eq!(core.list_repo_access(owner, name).len(), 1);
    assert_eq!(
        core.get_repository_readme(owner, name).unwrap().as_deref(),
        Some("# Todo\n")
    );
    let deployments = core
        .list_deployments(owner, name, &Default::default())
        .unwrap();
    assert_eq!(deployments.len(), 1);
    assert_eq!(
        (deployments[0].owner.as_str(), deployments[0].repo.as_str()),
        (owner, name)
    );
}

fn assert_nothing_left(core: &ForgeCore, owner: &str, name: &str) {
    assert!(matches!(
        core.list_labels(owner, name),
        Err(ForgeError::NotFound(_))
    ));
    assert!(core.list_repo_access(owner, name).is_empty());
}

#[test]
fn transfer_rekeys_every_scoped_map_and_redirects_the_old_name() {
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("forge.sqlite");
    let original = {
        let core = ForgeCore::open_sqlite(&database).unwrap();
        create_org(&core, "veox");
        let original = seed(&core);
        let moved = core
            .rename_repository("alton", "jain-split", "jain-todo", "veox", "jain-todo")
            .unwrap();
        assert_eq!(moved.id, original.id);
        assert_eq!(moved.full_name, "veox/jain-todo");
        assert!(moved.updated_at > original.updated_at);
        assert_moved(&core, "veox", "jain-todo");
        assert_nothing_left(&core, "jain-split", "jain-todo");

        let audit = core.list_audit("jain-split/jain-todo").unwrap();
        let renamed: Vec<_> = audit
            .iter()
            .filter(|entry| entry.action == "repository.renamed")
            .collect();
        assert_eq!(renamed.len(), 2);
        assert_eq!(renamed[0].phase, "requested");
        assert_eq!(renamed[1].phase, "completed");
        assert_eq!(renamed[1].actor, "alton");
        assert_eq!(
            renamed[1].detail,
            serde_json::json!({ "from": "jain-split/jain-todo", "to": "veox/jain-todo" })
        );
        original
    };

    // Everything, including the redirect, survives a reopen.
    let core = ForgeCore::open_sqlite(&database).unwrap();
    assert_moved(&core, "veox", "jain-todo");
    let via_old = core.get_repository("jain-split", "jain-todo").unwrap();
    assert_eq!(via_old.id, original.id);
    assert_eq!(via_old.full_name, "veox/jain-todo");
    let alias = core
        .get_repository_alias("jain-split", "jain-todo")
        .unwrap();
    assert_eq!(alias.origin, RepositoryAliasOrigin::Rename);
    assert_eq!(
        (
            alias.canonical_owner.as_str(),
            alias.canonical_name.as_str()
        ),
        ("veox", "jain-todo")
    );
    // Writes through the old name are resolved the same way at the git edge.
    core.ensure_repository_writable("jain-split", "jain-todo")
        .unwrap();
}

#[test]
fn rename_within_owner_keeps_state_and_redirects() {
    let core = ForgeCore::new();
    seed(&core);
    let renamed = core
        .rename_repository("alton", "jain-split", "jain-todo", "jain-split", "todo")
        .unwrap();
    assert_eq!(renamed.full_name, "jain-split/todo");
    assert_moved(&core, "jain-split", "todo");
    assert_eq!(
        core.get_repository("jain-split", "jain-todo")
            .unwrap()
            .full_name,
        "jain-split/todo"
    );
    let listed: Vec<_> = core
        .list_repositories(None)
        .into_iter()
        .map(|repo| repo.full_name)
        .collect();
    assert_eq!(listed, vec!["jain-split/todo".to_string()]);
}

#[test]
fn rename_refusals_are_typed_and_change_nothing() {
    let core = ForgeCore::new();
    create_org(&core, "veox");
    create_repo(&core, "jain-split", "jain-todo");
    create_repo(&core, "veox", "taken");

    let refused = |owner: &str, name: &str| {
        core.rename_repository("alton", "jain-split", "jain-todo", owner, name)
            .unwrap_err()
    };
    for (owner, name) in [
        ("veox", "taken"),
        ("nobody", "jain-todo"),
        ("veox", ""),
        ("veox", "   "),
        ("veox", "bad name"),
        ("veox", "bad/name"),
        ("veox", ".hidden"),
        ("veox", "repo.git"),
        ("jain-split", "jain-todo"),
        ("", "jain-todo"),
    ] {
        let err = refused(owner, name);
        assert!(
            matches!(err, ForgeError::Validation(_)),
            "{owner}/{name}: {err:?}"
        );
    }
    assert!(matches!(
        refused("veox", &"a".repeat(101)),
        ForgeError::Validation(_)
    ));

    assert!(matches!(
        core.rename_repository("alton", "jain-split", "missing", "veox", "x"),
        Err(ForgeError::NotFound(_))
    ));

    core.set_repository_archived("alton", "jain-split", "jain-todo", true)
        .unwrap();
    let err = refused("veox", "jain-todo");
    assert!(
        matches!(&err, ForgeError::Validation(message) if message.contains("unarchive")),
        "{err:?}"
    );
    core.set_repository_archived("alton", "jain-split", "jain-todo", false)
        .unwrap();

    assert!(core.get_repository("jain-split", "jain-todo").is_ok());
    assert!(
        core.get_repository_alias("jain-split", "jain-todo")
            .is_none()
    );
    assert!(core.get_repository("veox", "jain-todo").is_err());
}

#[derive(Debug, Default)]
struct RecordingRelocator {
    fail: bool,
    moves: Mutex<Vec<String>>,
}

impl RepoRelocator for RecordingRelocator {
    fn relocate(
        &self,
        from_owner: &str,
        from_name: &str,
        to_owner: &str,
        to_name: &str,
    ) -> jeryu_core::Result<()> {
        if self.fail {
            return Err(ForgeError::Storage("disk move failed".to_string()));
        }
        self.moves
            .lock()
            .unwrap()
            .push(format!("{from_owner}/{from_name} -> {to_owner}/{to_name}"));
        Ok(())
    }
}

#[test]
fn rename_moves_the_bare_directory_through_the_relocator() {
    let relocator = Arc::new(RecordingRelocator::default());
    let core = ForgeCore::new().with_repo_relocator(relocator.clone());
    create_org(&core, "veox");
    create_repo(&core, "jain-split", "jain-todo");
    core.rename_repository("alton", "jain-split", "jain-todo", "veox", "jain-todo")
        .unwrap();
    assert_eq!(
        *relocator.moves.lock().unwrap(),
        vec!["jain-split/jain-todo -> veox/jain-todo".to_string()]
    );
}

#[test]
fn failed_disk_move_rolls_the_state_back() {
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("forge.sqlite");
    let relocator = Arc::new(RecordingRelocator {
        fail: true,
        ..Default::default()
    });
    let core = ForgeCore::open_sqlite(&database)
        .unwrap()
        .with_repo_relocator(relocator);
    create_org(&core, "veox");
    let original = seed(&core);

    let err = core
        .rename_repository("alton", "jain-split", "jain-todo", "veox", "jain-todo")
        .unwrap_err();
    assert!(matches!(err, ForgeError::Storage(_)), "{err:?}");
    assert_eq!(
        core.get_repository("jain-split", "jain-todo").unwrap(),
        original
    );
    assert_moved(&core, "jain-split", "jain-todo");
    assert!(core.get_repository("veox", "jain-todo").is_err());
    assert!(
        core.get_repository_alias("jain-split", "jain-todo")
            .is_none()
    );
    let phases: Vec<_> = core
        .list_audit("jain-split/jain-todo")
        .unwrap()
        .into_iter()
        .filter(|entry| entry.action == "repository.renamed")
        .map(|entry| entry.phase)
        .collect();
    assert_eq!(phases, vec!["requested".to_string(), "failed".to_string()]);

    let reopened = ForgeCore::open_sqlite(&database).unwrap();
    assert_moved(&reopened, "jain-split", "jain-todo");
    assert!(reopened.get_repository("veox", "jain-todo").is_err());
}

#[test]
fn repository_created_at_the_old_name_takes_precedence_over_the_alias() {
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("forge.sqlite");
    let (moved, fresh) = {
        let core = ForgeCore::open_sqlite(&database).unwrap();
        create_org(&core, "veox");
        let moved = create_repo(&core, "jain-split", "jain-todo");
        core.rename_repository("alton", "jain-split", "jain-todo", "veox", "jain-todo")
            .unwrap();
        let fresh = create_repo(&core, "jain-split", "jain-todo");
        assert_ne!(fresh.id, moved.id);
        (moved, fresh)
    };
    let core = ForgeCore::open_sqlite(&database).unwrap();
    assert_eq!(
        core.get_repository("jain-split", "jain-todo").unwrap().id,
        fresh.id
    );
    assert_eq!(
        core.get_repository("veox", "jain-todo").unwrap().id,
        moved.id
    );
}

#[test]
fn two_hop_rename_chain_resolves_every_old_name_to_the_final_one() {
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("forge.sqlite");
    let original = {
        let core = ForgeCore::open_sqlite(&database).unwrap();
        core.create_user(CreateUserRequest {
            login: "alton".to_string(),
            name: None,
            email: None,
        })
        .unwrap();
        create_org(&core, "veox");
        let original = create_repo(&core, "jain-split", "jain-todo");
        core.rename_repository("alton", "jain-split", "jain-todo", "alton", "todo")
            .unwrap();
        core.rename_repository("alton", "alton", "todo", "veox", "jain-todo")
            .unwrap();
        original
    };
    let core = ForgeCore::open_sqlite(&database).unwrap();
    for (owner, name) in [
        ("jain-split", "jain-todo"),
        ("alton", "todo"),
        ("veox", "jain-todo"),
    ] {
        let repo = core.get_repository(owner, name).unwrap();
        assert_eq!(repo.id, original.id, "{owner}/{name}");
        assert_eq!(repo.full_name, "veox/jain-todo", "{owner}/{name}");
    }

    // Renaming back onto an old name reclaims it instead of looping.
    core.rename_repository("alton", "veox", "jain-todo", "alton", "todo")
        .unwrap();
    assert!(core.get_repository_alias("alton", "todo").is_none());
    for (owner, name) in [("jain-split", "jain-todo"), ("veox", "jain-todo")] {
        assert_eq!(
            core.get_repository(owner, name).unwrap().full_name,
            "alton/todo",
            "{owner}/{name}"
        );
    }
}

#[test]
fn deleting_a_renamed_repository_drops_its_redirects() {
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("forge.sqlite");
    let core = ForgeCore::open_sqlite(&database).unwrap();
    create_org(&core, "veox");
    create_repo(&core, "jain-split", "jain-todo");
    core.rename_repository("alton", "jain-split", "jain-todo", "veox", "jain-todo")
        .unwrap();
    core.delete_repository("veox", "jain-todo").unwrap();
    assert!(
        core.get_repository_alias("jain-split", "jain-todo")
            .is_none()
    );
    assert!(matches!(
        core.get_repository("jain-split", "jain-todo"),
        Err(ForgeError::NotFound(_))
    ));
    let reopened = ForgeCore::open_sqlite(&database).unwrap();
    assert!(reopened.get_repository("jain-split", "jain-todo").is_err());
}
