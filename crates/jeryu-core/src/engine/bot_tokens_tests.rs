//! Agent tokens: issue, verify, revoke, and their lifetime against the bot.

use chrono::{Duration, Utc};

use super::ForgeCore;
use crate::errors::ForgeError;
use crate::model::*;

const PASSWORD: &str = "correct-horse-battery";

fn fixture() -> (ForgeCore, BotEnrollment) {
    let core = ForgeCore::new();
    seed(&core);
    let bot = core
        .enroll_bot("alice", "atlas", "Atlas", BotKind::Grok, BotReach::General)
        .unwrap();
    (core, bot)
}

fn seed(core: &ForgeCore) {
    core.create_account("alice", PASSWORD, UserRole::User)
        .unwrap();
    core.create_repository(
        "alice",
        CreateRepositoryRequest {
            name: "widgets".to_string(),
            private: true,
            description: None,
            default_branch: Some("main".to_string()),
        },
    )
    .unwrap();
    core.grant_repo_access("alice", "alice", "alice", "widgets", RepoAccessLevel::Write)
        .unwrap();
}

fn call(auth: &BotAccessTokenAuth, repo: &str, effect: BotEffect) -> BotCall {
    BotCall {
        bot_id: auth.bot.id,
        generation: auth.generation,
        key_id: auth.key_id.clone(),
        owner: "alice".to_string(),
        repo: repo.to_string(),
        effect,
        task_kind: None,
        task_id: None,
    }
}

#[test]
fn issued_token_authenticates_and_carries_the_bot_grant() {
    let (core, bot) = fixture();
    let issued = core
        .issue_bot_access_token("alice", bot.bot.id, Some("laptop"), None)
        .unwrap();
    assert!(issued.token.starts_with(crate::AGENT_TOKEN_PREFIX));
    assert!(!format!("{issued:?}").contains(&issued.token));
    let auth = core.authenticate_bot_access_token(&issued.token).unwrap();
    assert_eq!(auth.bot.id, bot.bot.id);
    assert_eq!(auth.token_id, issued.token_id);
    assert!(
        core.authorize_bot(&call(&auth, "widgets", BotEffect::Write))
            .is_ok()
    );
    assert!(
        core.authorize_bot(&call(&auth, "missing", BotEffect::Read))
            .is_err()
    );

    let listed = core.list_bot_access_tokens("alice", bot.bot.id).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].label.as_deref(), Some("laptop"));
    assert!(listed[0].last_used_at.is_some());
    assert!(!format!("{listed:?}").contains(&issued.token));
}

#[test]
fn unknown_malformed_and_foreign_tokens_are_one_error() {
    let (core, bot) = fixture();
    let issued = core
        .issue_bot_access_token("alice", bot.bot.id, None, None)
        .unwrap();
    let tampered = format!("{}x", issued.token);
    for token in [
        "jat_",
        "jat_nope.nope",
        tampered.as_str(),
        bot.enrollment_key.as_str(),
        "jpat_not-an-agent-token",
    ] {
        let error = core.authenticate_bot_access_token(token).unwrap_err();
        assert!(error.to_string().contains("invalid agent token"), "{error}");
    }
}

#[test]
fn revoked_and_expired_tokens_stop_working() {
    let (core, bot) = fixture();
    let first = core
        .issue_bot_access_token("alice", bot.bot.id, None, None)
        .unwrap();
    let second = core
        .issue_bot_access_token("alice", bot.bot.id, None, Some(1))
        .unwrap();
    core.revoke_bot_access_token("alice", bot.bot.id, &first.token_id)
        .unwrap();
    core.revoke_bot_access_token("alice", bot.bot.id, &first.token_id)
        .unwrap();
    assert!(core.authenticate_bot_access_token(&first.token).is_err());
    assert!(core.authenticate_bot_access_token(&second.token).is_ok());
    {
        let mut state = core.state.write();
        for record in state.bot_access_tokens.values_mut() {
            record.expires_at = Utc::now() - Duration::seconds(1);
        }
    }
    assert!(core.authenticate_bot_access_token(&second.token).is_err());
}

#[test]
fn agent_token_dies_with_its_bot_credential_generation() {
    let (core, bot) = fixture();
    let before = core
        .issue_bot_access_token("alice", bot.bot.id, None, None)
        .unwrap();
    // Rotating the enrollment key is not a token event: the token keeps
    // working, authorized under the bot's new live key.
    core.rotate_bot_key("alice", bot.bot.id).unwrap();
    let auth = core.authenticate_bot_access_token(&before.token).unwrap();
    assert!(
        core.authorize_bot(&call(&auth, "widgets", BotEffect::Read))
            .is_ok()
    );
    core.suspend_bot("alice", bot.bot.id).unwrap();
    assert!(core.authenticate_bot_access_token(&before.token).is_err());

    let (core, bot) = fixture();
    let token = core
        .issue_bot_access_token("alice", bot.bot.id, None, None)
        .unwrap();
    core.lock_account("alice").unwrap();
    assert!(core.authenticate_bot_access_token(&token.token).is_err());

    let (core, bot) = fixture();
    let token = core
        .issue_bot_access_token("alice", bot.bot.id, None, None)
        .unwrap();
    core.revoke_bot("alice", bot.bot.id).unwrap();
    assert!(core.authenticate_bot_access_token(&token.token).is_err());
    assert!(
        core.issue_bot_access_token("alice", bot.bot.id, None, None)
            .is_err()
    );
}

#[test]
fn only_the_owner_manages_tokens_and_limits_hold() {
    let (core, bot) = fixture();
    core.create_account("bob", PASSWORD, UserRole::User)
        .unwrap();
    assert!(matches!(
        core.issue_bot_access_token("bob", bot.bot.id, None, None),
        Err(ForgeError::NotFound(_))
    ));
    assert!(matches!(
        core.list_bot_access_tokens("bob", bot.bot.id),
        Err(ForgeError::NotFound(_))
    ));
    for ttl in [0, 366] {
        assert!(matches!(
            core.issue_bot_access_token("alice", bot.bot.id, None, Some(ttl)),
            Err(ForgeError::Validation(_))
        ));
    }
    let long = "x".repeat(81);
    assert!(matches!(
        core.issue_bot_access_token("alice", bot.bot.id, Some(&long), None),
        Err(ForgeError::Validation(_))
    ));
    let issued: Vec<_> = (0..10)
        .map(|_| {
            core.issue_bot_access_token("alice", bot.bot.id, None, None)
                .unwrap()
        })
        .collect();
    assert!(matches!(
        core.issue_bot_access_token("alice", bot.bot.id, None, None),
        Err(ForgeError::Conflict(_))
    ));
    let one = &issued[0];
    core.revoke_bot_access_token("bob", bot.bot.id, &one.token_id)
        .unwrap_err();
    core.revoke_bot_access_token("alice", bot.bot.id, &one.token_id)
        .unwrap();
    assert!(
        core.issue_bot_access_token("alice", bot.bot.id, None, None)
            .is_ok()
    );
}

#[test]
fn agent_tokens_survive_sqlite_reopen_without_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("forge.sqlite");
    let token = {
        let core = ForgeCore::open_sqlite(&path).unwrap();
        seed(&core);
        let bot = core
            .enroll_bot("alice", "atlas", "Atlas", BotKind::Muse, BotReach::General)
            .unwrap();
        core.issue_bot_access_token("alice", bot.bot.id, Some("ci"), None)
            .unwrap()
            .token
    };
    let core = ForgeCore::open_sqlite(&path).unwrap();
    let auth = core.authenticate_bot_access_token(&token).unwrap();
    assert_eq!(auth.bot.slug, "atlas");
    let bytes = std::fs::read(&path).unwrap();
    let secret = token.split_once('.').unwrap().1.as_bytes();
    assert!(
        !bytes.windows(secret.len()).any(|window| window == secret),
        "the token secret must not be stored"
    );
}
