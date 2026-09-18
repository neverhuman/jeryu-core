//! Deployments and their append-only status trail (GitHub Deployments API).

use jeryu_core::{
    CreateDeploymentRequest, CreateDeploymentStatusRequest, CreateIssueRequest,
    CreateRepositoryRequest, CreateUserRequest, DeploymentFilter, DeploymentState, ForgeCore,
    ForgeError,
};

const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SHA_C: &str = "cccccccccccccccccccccccccccccccccccccccc";

fn seed(core: &ForgeCore) {
    core.create_user(CreateUserRequest {
        login: "alice".to_string(),
        ..Default::default()
    })
    .unwrap();
    core.create_repository(
        "alice",
        CreateRepositoryRequest {
            name: "jeryu".to_string(),
            ..Default::default()
        },
    )
    .unwrap();
}

fn core_with_repo() -> ForgeCore {
    let core = ForgeCore::new();
    seed(&core);
    core
}

fn deploy(core: &ForgeCore, sha: &str, environment: &str) -> u64 {
    core.create_deployment(
        "alice",
        "jeryu",
        "deployer",
        CreateDeploymentRequest {
            sha: sha.to_string(),
            ref_name: None,
            task: "deploy".to_string(),
            environment: environment.to_string(),
            description: None,
            payload: Some(serde_json::json!({ "release": format!("rel-{}", &sha[..7]) })),
            production_environment: None,
            transient_environment: false,
        },
    )
    .unwrap()
    .id
}

fn set_state(core: &ForgeCore, id: u64, state: DeploymentState) {
    core.create_deployment_status(
        "alice",
        "jeryu",
        id,
        "deployer",
        CreateDeploymentStatusRequest {
            state,
            description: None,
            environment_url: Some("https://git.neverhuman.org".to_string()),
            log_url: None,
            auto_inactive: true,
        },
    )
    .unwrap();
}

fn states(core: &ForgeCore, id: u64) -> Vec<DeploymentState> {
    core.list_deployment_statuses("alice", "jeryu", id)
        .unwrap()
        .into_iter()
        .map(|status| status.state)
        .collect()
}

#[test]
fn deployment_records_the_exact_commit_and_defaults_like_github() {
    let core = core_with_repo();
    let id = deploy(&core, SHA_A, "production");
    let deployment = core.get_deployment("alice", "jeryu", id).unwrap();
    assert_eq!(deployment.id, 1);
    assert_eq!(deployment.sha, SHA_A);
    assert_eq!(deployment.ref_name, SHA_A, "ref defaults to the sha");
    assert!(
        deployment.production_environment,
        "production is a production environment"
    );
    assert_eq!(deployment.payload["release"], "rel-aaaaaaa");

    let canary = deploy(&core, SHA_B, "canary");
    assert_eq!(canary, 2, "ids increase across environments");
    assert!(
        !core
            .get_deployment("alice", "jeryu", canary)
            .unwrap()
            .production_environment
    );
}

#[test]
fn deployment_rejects_a_moving_ref_or_malformed_sha() {
    let core = core_with_repo();
    for sha in [
        "main",
        "ABCDEF",
        &SHA_A[..39],
        &"g".repeat(40),
        &SHA_A.to_uppercase(),
    ] {
        let err = core
            .create_deployment(
                "alice",
                "jeryu",
                "deployer",
                CreateDeploymentRequest {
                    sha: sha.to_string(),
                    ref_name: None,
                    task: "deploy".to_string(),
                    environment: "production".to_string(),
                    description: None,
                    payload: None,
                    production_environment: None,
                    transient_environment: false,
                },
            )
            .unwrap_err();
        assert!(
            matches!(err, ForgeError::Validation(_)),
            "{sha:?} must be rejected"
        );
    }
    assert!(
        core.list_deployments("alice", "jeryu", &DeploymentFilter::default())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn deployments_are_scoped_to_their_repository() {
    let core = core_with_repo();
    let id = deploy(&core, SHA_A, "production");
    core.create_repository(
        "alice",
        CreateRepositoryRequest {
            name: "other".to_string(),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(matches!(
        core.get_deployment("alice", "other", id),
        Err(ForgeError::NotFound(_))
    ));
    assert!(matches!(
        core.list_deployments("alice", "missing", &DeploymentFilter::default()),
        Err(ForgeError::NotFound(_))
    ));
}

#[test]
fn list_is_newest_first_and_filters_by_environment_sha_and_ref() {
    let core = core_with_repo();
    let first = deploy(&core, SHA_A, "production");
    let canary = deploy(&core, SHA_B, "canary");
    let second = deploy(&core, SHA_B, "production");

    let all: Vec<u64> = core
        .list_deployments("alice", "jeryu", &DeploymentFilter::default())
        .unwrap()
        .iter()
        .map(|d| d.id)
        .collect();
    assert_eq!(all, vec![second, canary, first]);

    let production = core
        .list_deployments(
            "alice",
            "jeryu",
            &DeploymentFilter {
                environment: Some("production".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        production.iter().map(|d| d.id).collect::<Vec<_>>(),
        vec![second, first]
    );

    let at_b = core
        .list_deployments(
            "alice",
            "jeryu",
            &DeploymentFilter {
                sha: Some(SHA_B.to_string()),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        at_b.iter().map(|d| d.id).collect::<Vec<_>>(),
        vec![second, canary]
    );

    let by_ref = core
        .list_deployments(
            "alice",
            "jeryu",
            &DeploymentFilter {
                ref_name: Some(SHA_A.to_string()),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(by_ref.iter().map(|d| d.id).collect::<Vec<_>>(), vec![first]);
}

#[test]
fn statuses_append_and_read_newest_first() {
    let core = core_with_repo();
    let id = deploy(&core, SHA_A, "production");
    assert!(states(&core, id).is_empty());
    set_state(&core, id, DeploymentState::InProgress);
    set_state(&core, id, DeploymentState::Success);
    assert_eq!(
        states(&core, id),
        vec![DeploymentState::Success, DeploymentState::InProgress]
    );
    assert!(matches!(
        core.create_deployment_status(
            "alice",
            "jeryu",
            99,
            "deployer",
            CreateDeploymentStatusRequest {
                state: DeploymentState::Success,
                description: None,
                environment_url: None,
                log_url: None,
                auto_inactive: true,
            },
        ),
        Err(ForgeError::NotFound(_))
    ));
}

#[test]
fn a_success_inactivates_the_live_deployment_it_replaces_only() {
    let core = core_with_repo();
    let old = deploy(&core, SHA_A, "production");
    set_state(&core, old, DeploymentState::Success);
    let canary = deploy(&core, SHA_B, "canary");
    set_state(&core, canary, DeploymentState::Success);
    let failed = deploy(&core, SHA_C, "production");
    set_state(&core, failed, DeploymentState::Failure);

    assert_eq!(
        states(&core, old),
        vec![DeploymentState::Success],
        "a failed deploy must not retire what is still running"
    );

    let new = deploy(&core, SHA_B, "production");
    set_state(&core, new, DeploymentState::Success);
    assert_eq!(
        states(&core, old),
        vec![DeploymentState::Inactive, DeploymentState::Success],
        "the replaced deployment gets an appended inactive status, its success is kept"
    );
    assert_eq!(states(&core, failed), vec![DeploymentState::Failure]);
    assert_eq!(
        states(&core, canary),
        vec![DeploymentState::Success],
        "other environments are untouched"
    );
}

#[test]
fn transient_deployments_are_never_auto_inactivated() {
    let core = core_with_repo();
    let preview = core
        .create_deployment(
            "alice",
            "jeryu",
            "deployer",
            CreateDeploymentRequest {
                sha: SHA_A.to_string(),
                ref_name: None,
                task: "deploy".to_string(),
                environment: "preview".to_string(),
                description: None,
                payload: None,
                production_environment: None,
                transient_environment: true,
            },
        )
        .unwrap()
        .id;
    set_state(&core, preview, DeploymentState::Success);
    let next = deploy(&core, SHA_B, "preview");
    set_state(&core, next, DeploymentState::Success);
    assert_eq!(states(&core, preview), vec![DeploymentState::Success]);
}

#[test]
fn environments_report_current_previous_and_latest_attempt() {
    let core = core_with_repo();
    let first = deploy(&core, SHA_A, "production");
    set_state(&core, first, DeploymentState::Success);
    let second = deploy(&core, SHA_B, "production");
    set_state(&core, second, DeploymentState::Success);
    let attempt = deploy(&core, SHA_C, "production");
    set_state(&core, attempt, DeploymentState::Failure);
    let canary = deploy(&core, SHA_C, "canary");

    let environments = core.deployment_environments("alice", "jeryu").unwrap();
    let names: Vec<&str> = environments
        .iter()
        .map(|e| e.environment.as_str())
        .collect();
    assert_eq!(names, vec!["canary", "production"]);

    let canary_env = &environments[0];
    assert_eq!(canary_env.latest.as_ref().unwrap().deployment.id, canary);
    assert!(
        canary_env.current.is_none(),
        "a deploy with no success is not live"
    );

    let production = &environments[1];
    assert_eq!(production.latest.as_ref().unwrap().deployment.id, attempt);
    let current = production.current.as_ref().unwrap();
    assert_eq!(
        current.deployment.id, second,
        "the failed attempt did not replace it"
    );
    assert_eq!(
        current.status.as_ref().unwrap().state,
        DeploymentState::Success
    );
    let previous = production.previous.as_ref().unwrap();
    assert_eq!(previous.deployment.id, first);
    assert!(previous.succeeded);
    assert_eq!(
        previous.status.as_ref().unwrap().state,
        DeploymentState::Inactive
    );
}

#[test]
fn sqlite_store_keeps_deployments_across_unrelated_writes() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("forge.sqlite");
    let (first, second) = {
        let core = ForgeCore::open_sqlite(&db).unwrap();
        seed(&core);
        let first = deploy(&core, SHA_A, "production");
        set_state(&core, first, DeploymentState::Success);
        // Every one of these runs the full-state rewrite, which deletes and
        // reinserts `repositories`. The deploy history must not ride that path.
        core.create_issue(
            "alice",
            "jeryu",
            "alice",
            CreateIssueRequest {
                title: "unrelated".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
        let second = deploy(&core, SHA_B, "production");
        set_state(&core, second, DeploymentState::Success);
        core.create_repository(
            "alice",
            CreateRepositoryRequest {
                name: "later".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
        (first, second)
    };

    let reopened = ForgeCore::open_sqlite(&db).unwrap();
    let ids: Vec<u64> = reopened
        .list_deployments("alice", "jeryu", &DeploymentFilter::default())
        .unwrap()
        .iter()
        .map(|d| d.id)
        .collect();
    assert_eq!(ids, vec![second, first]);
    assert_eq!(
        states(&reopened, first),
        vec![DeploymentState::Inactive, DeploymentState::Success]
    );
    assert_eq!(states(&reopened, second), vec![DeploymentState::Success]);

    let third = deploy(&reopened, SHA_C, "production");
    assert_eq!(third, second + 1, "ids continue after a reopen");
}
