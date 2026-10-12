//! Owners (family) reach and the free-form bot kind.

use super::ForgeCore;
use crate::errors::ForgeError;
use crate::model::*;

const PASSWORD: &str = "correct-horse-battery";

fn repo(core: &ForgeCore, owner: &str, name: &str, private: bool) {
    core.create_repository(
        owner,
        CreateRepositoryRequest {
            name: name.to_string(),
            private,
            description: None,
            default_branch: Some("main".to_string()),
        },
    )
    .unwrap();
}

fn grant(core: &ForgeCore, owner: &str, name: &str, level: RepoAccessLevel) {
    core.grant_repo_access("root", "alice", owner, name, level)
        .unwrap();
}

/// alice may write acme/widgets, read acme/docs, and write globex/ledger.
/// acme/secret and the public acme/public carry no grant for her.
fn fixture() -> ForgeCore {
    let core = ForgeCore::new();
    core.create_account("alice", PASSWORD, UserRole::User)
        .unwrap();
    for login in ["acme", "globex"] {
        core.create_organization(CreateOrganizationRequest {
            login: login.to_string(),
            display_name: None,
        })
        .unwrap();
    }
    repo(&core, "acme", "widgets", true);
    repo(&core, "acme", "docs", true);
    repo(&core, "acme", "secret", true);
    repo(&core, "acme", "public", false);
    repo(&core, "globex", "ledger", true);
    grant(&core, "acme", "widgets", RepoAccessLevel::Write);
    grant(&core, "acme", "docs", RepoAccessLevel::Read);
    grant(&core, "globex", "ledger", RepoAccessLevel::Write);
    core
}

fn owners(names: &[&str]) -> BotReach {
    BotReach::Owners {
        owners: names.iter().map(|name| (*name).to_string()).collect(),
    }
}

fn enroll(core: &ForgeCore, reach: BotReach) -> BotAccessTokenAuth {
    let bot = core
        .enroll_bot("alice", "family", "Family", BotKind::default(), reach)
        .unwrap();
    let issued = core
        .issue_bot_access_token("alice", bot.bot.id, None, None)
        .unwrap();
    core.authenticate_bot_access_token(&issued.token).unwrap()
}

fn call(auth: &BotAccessTokenAuth, owner: &str, name: &str, effect: BotEffect) -> BotCall {
    BotCall {
        bot_id: auth.bot.id,
        generation: auth.generation,
        key_id: auth.key_id.clone(),
        owner: owner.to_string(),
        repo: name.to_string(),
        effect,
        task_kind: None,
        task_id: None,
    }
}

fn denied_code(core: &ForgeCore, call: &BotCall) -> String {
    match core.authorize_bot(call) {
        Err(ForgeError::Forbidden(message)) => ForgeError::machine_text(&message).to_string(),
        other => panic!("expected a reach denial, got {other:?}"),
    }
}

fn validation(result: crate::errors::Result<BotEnrollment>) -> String {
    match result {
        Err(ForgeError::Validation(message)) => message,
        other => panic!("expected a validation error, got {other:?}"),
    }
}

#[test]
fn owners_reach_follows_the_owner_grants_inside_the_family() {
    let core = fixture();
    let auth = enroll(&core, owners(&["acme"]));

    assert!(
        core.authorize_bot(&call(&auth, "acme", "widgets", BotEffect::Write))
            .is_ok()
    );
    assert!(
        core.authorize_bot(&call(&auth, "acme", "docs", BotEffect::Read))
            .is_ok()
    );
    assert_eq!(
        denied_code(&core, &call(&auth, "acme", "docs", BotEffect::Write)),
        "insufficient_scope"
    );
    // In the family but no grant for the bot's owner: denied, private or public.
    assert_eq!(
        denied_code(&core, &call(&auth, "acme", "secret", BotEffect::Read)),
        "repo_not_granted"
    );
    assert_eq!(
        denied_code(&core, &call(&auth, "acme", "public", BotEffect::Read)),
        "repo_not_granted"
    );
    // The owner can write globex/ledger, but globex is not in the reach.
    assert_eq!(
        denied_code(&core, &call(&auth, "globex", "ledger", BotEffect::Write)),
        "repo_not_granted"
    );
    assert_eq!(
        denied_code(&core, &call(&auth, "globex", "ledger", BotEffect::Read)),
        "repo_not_granted"
    );
}

#[test]
fn owners_reach_covers_a_repository_created_after_enrollment() {
    let core = fixture();
    let auth = enroll(&core, owners(&["acme", "globex"]));
    repo(&core, "acme", "fresh", true);
    assert_eq!(
        denied_code(&core, &call(&auth, "acme", "fresh", BotEffect::Read)),
        "repo_not_granted"
    );
    grant(&core, "acme", "fresh", RepoAccessLevel::Write);
    assert!(
        core.authorize_bot(&call(&auth, "acme", "fresh", BotEffect::Write))
            .is_ok()
    );
    assert!(
        core.authorize_bot(&call(&auth, "globex", "ledger", BotEffect::Write))
            .is_ok()
    );
    // Revoking the owner's grant takes the repository back out.
    core.revoke_repo_access("alice", "acme", "fresh").unwrap();
    assert_eq!(
        denied_code(&core, &call(&auth, "acme", "fresh", BotEffect::Read)),
        "repo_not_granted"
    );
}

#[test]
fn owners_reach_is_normalized_and_validated_at_enrollment() {
    let core = fixture();
    let bot = core
        .enroll_bot(
            "alice",
            "family",
            "Family",
            BotKind::default(),
            owners(&[" ACME ", "acme", "globex"]),
        )
        .unwrap();
    assert_eq!(bot.bot.reach, owners(&["acme", "globex"]));
    assert_eq!(bot.bot.kind, BotKind::AGENT);
    // An account owner counts, and so does an owner known only by a repository.
    repo(&core, "initech", "tps", true);
    for (slug, names) in [("self", vec!["alice"]), ("repo-only", vec!["initech"])] {
        assert!(
            core.enroll_bot("alice", slug, slug, BotKind::default(), owners(&names))
                .is_ok(),
            "{names:?}"
        );
    }

    let code = BotReach::INVALID_OWNERS_CODE;
    let empty = validation(core.enroll_bot("alice", "e", "E", BotKind::AGENT, owners(&[])));
    assert!(empty.starts_with(code), "{empty}");
    for index in 0..21 {
        core.create_organization(CreateOrganizationRequest {
            login: format!("org{index}"),
            display_name: None,
        })
        .unwrap();
    }
    let many: Vec<String> = (0..21).map(|index| format!("org{index}")).collect();
    let twenty_distinct: Vec<String> = many[..20].to_vec();
    assert!(
        core.enroll_bot(
            "alice",
            "twenty",
            "Twenty",
            BotKind::AGENT,
            BotReach::Owners {
                owners: twenty_distinct
            },
        )
        .is_ok()
    );
    let too_many = validation(core.enroll_bot(
        "alice",
        "m",
        "M",
        BotKind::AGENT,
        BotReach::Owners { owners: many },
    ));
    assert!(too_many.starts_with(code), "{too_many}");
    let unknown = validation(core.enroll_bot(
        "alice",
        "u",
        "U",
        BotKind::AGENT,
        owners(&["acme", "nobody"]),
    ));
    assert!(
        unknown.starts_with(code) && unknown.contains("nobody"),
        "{unknown}"
    );
    for bad in ["", "  ", "acme/widgets"] {
        let message =
            validation(core.enroll_bot("alice", "b", "B", BotKind::AGENT, owners(&[bad])));
        assert!(message.starts_with(code), "{bad:?}: {message}");
    }
    // Twenty distinct owners is the limit, duplicates do not count twice.
    let mut twenty: Vec<&str> = vec!["acme"; 30];
    twenty.push("globex");
    assert!(
        core.enroll_bot("alice", "dups", "Dups", BotKind::AGENT, owners(&twenty))
            .is_ok()
    );
}

#[test]
fn repository_roster_lists_an_owners_bot_only_where_it_reaches() {
    let core = fixture();
    let auth = enroll(&core, owners(&["acme"]));
    let roster = core
        .list_repository_bots("alice", "acme", "widgets")
        .unwrap();
    assert_eq!(roster.len(), 1);
    assert_eq!(roster[0].id, auth.bot.id);
    // The viewer learns this repository only, never the other owners listed.
    assert_eq!(
        roster[0].reach,
        BotReach::Repositories {
            repos: vec![BotRepoRef {
                owner: "acme".to_string(),
                name: "widgets".to_string(),
            }],
        }
    );
    assert!(
        core.list_repository_bots("alice", "globex", "ledger")
            .unwrap()
            .is_empty()
    );
    let account = core.list_account_bots("alice").unwrap();
    assert_eq!(account[0].reach, owners(&["acme"]));
}

#[test]
fn bot_kind_is_a_validated_free_form_label() {
    for good in [
        "agent",
        "grok",
        "muse",
        "claude-code",
        "a",
        "x9",
        &"k".repeat(32),
    ] {
        let kind = BotKind::parse(good).unwrap();
        assert_eq!(kind.as_str(), good);
    }
    for bad in [
        "",
        "Agent",
        "9x",
        "-x",
        "a b",
        " agent",
        "agent_1",
        &"k".repeat(33),
    ] {
        let error = BotKind::parse(bad).unwrap_err();
        assert!(
            matches!(&error, ForgeError::Validation(message) if message.starts_with(BotKind::INVALID_CODE)),
            "{bad:?}: {error:?}"
        );
        assert!(serde_json::from_value::<BotKind>(serde_json::json!(bad)).is_err());
    }
    assert_eq!(BotKind::GROK.label(), "Grokbot");
    assert_eq!(BotKind::MUSE.label(), "Musebot");
    assert_eq!(
        BotKind::parse("claude-code").unwrap().label(),
        "claude-code"
    );
    assert_eq!(BotKind::default(), BotKind::AGENT);
    assert_eq!(
        serde_json::to_value(BotKind::parse("claude-code").unwrap()).unwrap(),
        serde_json::json!("claude-code")
    );
    assert_eq!(
        serde_json::from_value::<BotKind>(serde_json::json!("grok")).unwrap(),
        BotKind::GROK
    );
    assert_eq!(
        serde_json::from_value::<BotReach>(serde_json::json!({"mode":"owners","owners":["acme"]}))
            .unwrap(),
        owners(&["acme"])
    );
}

#[test]
fn free_form_kind_survives_sqlite_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("forge.sqlite");
    let id = {
        let core = ForgeCore::open_sqlite(&path).unwrap();
        core.create_account("alice", PASSWORD, UserRole::User)
            .unwrap();
        core.create_organization(CreateOrganizationRequest {
            login: "acme".to_string(),
            display_name: None,
        })
        .unwrap();
        let bot = core
            .enroll_bot(
                "alice",
                "coder",
                "Coder",
                BotKind::parse("claude-code").unwrap(),
                owners(&["acme"]),
            )
            .unwrap();
        bot.bot.id
    };
    let core = ForgeCore::open_sqlite(&path).unwrap();
    let bots = core.list_account_bots("alice").unwrap();
    assert_eq!(bots.len(), 1);
    assert_eq!(bots[0].id, id);
    assert_eq!(bots[0].kind.as_str(), "claude-code");
    assert_eq!(bots[0].reach, owners(&["acme"]));
}
