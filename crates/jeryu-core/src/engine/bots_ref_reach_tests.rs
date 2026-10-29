//! Ref writes use the same credentials and repository rights as other bot calls.

use super::ForgeCore;
use crate::errors::ForgeError;
use crate::model::*;
use serde_json::json;

fn reach(refs: Option<Vec<String>>) -> BotReach {
    BotReach::Repositories {
        repos: vec![BotRepoRef {
            owner: "acme".into(),
            name: "widgets".into(),
        }],
        refs,
    }
}

fn patterns() -> Vec<String> {
    [
        "refs/tags/*-split.*",
        "refs/heads/preserve/hosted-cargo/*",
        "refs/heads/releasebot/*",
    ]
    .map(str::to_string)
    .to_vec()
}

fn fixture(core: &ForgeCore, reach: BotReach) -> BotCall {
    core.create_account("alice", "correct-horse-battery", UserRole::User)
        .unwrap();
    core.create_organization(CreateOrganizationRequest {
        login: "acme".into(),
        display_name: None,
    })
    .unwrap();
    core.create_repository(
        "acme",
        CreateRepositoryRequest {
            name: "widgets".into(),
            private: true,
            description: None,
            default_branch: None,
        },
    )
    .unwrap();
    core.grant_repo_access("root", "alice", "acme", "widgets", RepoAccessLevel::Write)
        .unwrap();
    let bot = core
        .enroll_bot("alice", "releasebot", "Release bot", BotKind::AGENT, reach)
        .unwrap();
    let session = core
        .exchange_bot_enrollment_key(&bot.enrollment_key)
        .unwrap();
    BotCall {
        bot_id: session.bot.id,
        generation: session.generation,
        key_id: session.key_id,
        owner: "acme".into(),
        repo: "widgets".into(),
        effect: BotEffect::Read,
        task_kind: None,
        task_id: None,
    }
}

fn refusal(core: &ForgeCore, call: &BotCall, reference: &str, expected: &str) {
    match core.authorize_bot_ref_write(call, reference) {
        Err(ForgeError::Forbidden(message)) => {
            assert_eq!(ForgeError::machine_text(&message), expected)
        }
        other => panic!("expected {expected}, got {other:?}"),
    }
}

#[test]
fn ref_limits_persist_and_intersect_non_owner_grants() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("forge.sqlite");
    let core = ForgeCore::open_sqlite(&path).unwrap();
    let call = fixture(&core, reach(Some(patterns())));
    drop(core);
    let core = ForgeCore::open_sqlite(&path).unwrap();
    for reference in [
        "refs/tags/core-v5-split.1",
        "refs/heads/releasebot/cut",
        "refs/heads/preserve/hosted-cargo/core/v5",
    ] {
        assert!(
            core.authorize_bot_ref_write(&call, reference).is_ok(),
            "{reference}"
        );
    }
    for reference in [
        "refs/heads/main",
        "refs/heads/feature",
        "refs/tags/v5",
        "refs/tags/core-split.1/../main",
        "main",
        "refs/heads/releasebot/a.lock",
        "refs/heads/releasebot/*",
    ] {
        refusal(&core, &call, reference, "ref_not_granted");
    }
    assert!(core.authorize_bot(&call).is_ok());
    let audit = core.list_audit("alice/releasebot").unwrap();
    assert!(
        audit
            .iter()
            .any(|entry| entry.action == "bot.authorize"
                && entry.detail["code"] == "ref_not_granted")
    );
    let mut elsewhere = call.clone();
    elsewhere.repo = "missing".into();
    refusal(
        &core,
        &elsewhere,
        "refs/tags/core-split.1",
        "repo_not_granted",
    );
    core.grant_repo_access("root", "alice", "acme", "widgets", RepoAccessLevel::Read)
        .unwrap();
    // Even a call marked Read must require Write when checking a destination ref.
    refusal(&core, &call, "refs/tags/core-split.1", "insufficient_scope");
    core.suspend_bot("alice", call.bot_id).unwrap();
    assert!(
        core.authorize_bot_ref_write(&call, "refs/tags/core-split.1")
            .is_err()
    );
}

#[test]
fn absent_refs_preserve_writes_and_empty_refs_deny_them() {
    for refs in [None, Some(vec![])] {
        let core = ForgeCore::new();
        let call = fixture(&core, reach(refs.clone()));
        for reference in ["refs/heads/main", "refs/heads/feature", "refs/tags/v5"] {
            if refs.is_none() {
                assert!(core.authorize_bot_ref_write(&call, reference).is_ok());
            } else {
                refusal(&core, &call, reference, "ref_not_granted");
            }
        }
    }
}

#[test]
fn reach_json_round_trips_with_and_without_refs_in_every_mode() {
    for value in [
        json!({"mode":"general"}),
        json!({"mode":"owners","owners":["acme"]}),
        json!({"mode":"repositories","repos":[{"owner":"acme","name":"widgets"}]}),
        json!({"mode":"task","repo":{"owner":"acme","name":"widgets"},"task_kind":"branch","task_id":"releasebot/cut"}),
    ] {
        let without: BotReach = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(without.refs(), None);
        assert_eq!(serde_json::to_value(&without).unwrap(), value);
        for refs in [vec![], patterns()] {
            let mut with = value.clone();
            with["refs"] = json!(refs);
            let parsed: BotReach = serde_json::from_value(with.clone()).unwrap();
            parsed.validate_refs().unwrap();
            assert_eq!(serde_json::to_value(&parsed).unwrap(), with);
        }
    }
}

#[test]
fn enrollment_validates_ref_patterns() {
    let core = ForgeCore::new();
    fixture(&core, reach(None));
    let mut invalid = vec![
        vec!["refs/heads/main".to_string(); BotReach::MAX_REFS + 1],
        vec![format!("refs/tags/{}", "a".repeat(1024))],
    ];
    for pattern in [
        "",
        "*",
        "main",
        "refs/*",
        "refs/remotes/*",
        "refs/tags/",
        "refs/tags/a..b",
        "refs/tags/a?b",
        "refs/tags/[ab]",
        "refs/tags/a b",
        "refs/tags/a\\b",
        "refs/tags/a@{b",
        "refs/tags/.hidden",
        "refs/tags/a.lock",
        "refs/tags/a//b",
        "refs/tags/a.",
    ] {
        invalid.push(vec![pattern.into()]);
    }
    for refs in invalid {
        let result = core.enroll_bot(
            "alice",
            "invalid",
            "Invalid",
            BotKind::AGENT,
            reach(Some(refs)),
        );
        assert!(
            matches!(result, Err(ForgeError::Validation(message)) if message.split_once(": ").map(|(code, _)| code) == Some("invalid_reach_refs"))
        );
    }
    for pattern in [
        "refs/tags/v5",
        "refs/tags/*-split.*",
        "refs/heads/releasebot/*",
    ] {
        reach(Some(vec![pattern.into()])).validate_refs().unwrap();
    }
}

#[test]
fn full_ref_matching_is_anchored_and_keeps_task_restrictions() {
    let core = ForgeCore::new();
    let call = fixture(
        &core,
        BotReach::Task {
            repo: BotRepoRef {
                owner: "acme".into(),
                name: "widgets".into(),
            },
            task_kind: BotTaskKind::Branch,
            task_id: "releasebot/cut".into(),
            refs: Some(vec!["refs/heads/releasebot/cut".into()]),
        },
    );
    refusal(
        &core,
        &call,
        "refs/heads/releasebot/cut",
        "task_not_granted",
    );
    let mut bound = call;
    bound.task_kind = Some(BotTaskKind::Branch);
    bound.task_id = Some("releasebot/cut".into());
    assert!(
        core.authorize_bot_ref_write(&bound, "refs/heads/releasebot/cut")
            .is_ok()
    );
    refusal(
        &core,
        &bound,
        "refs/heads/releasebot/cut-extra",
        "ref_not_granted",
    );
}

#[test]
fn general_and_owners_reach_keep_ref_limits_after_enrollment() {
    for reach in [
        BotReach::General {
            refs: Some(patterns()),
        },
        BotReach::Owners {
            owners: vec!["acme".into()],
            refs: Some(patterns()),
        },
    ] {
        let core = ForgeCore::new();
        let call = fixture(&core, reach);
        assert!(
            core.authorize_bot_ref_write(&call, "refs/tags/core-split.1")
                .is_ok()
        );
        refusal(&core, &call, "refs/heads/main", "ref_not_granted");
        let roster = core
            .list_repository_bots("alice", "acme", "widgets")
            .unwrap();
        assert_eq!(roster[0].reach.refs(), Some(patterns().as_slice()));
    }
}
