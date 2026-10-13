//! Team bots owned by an organization (record 0008).

use super::ForgeCore;
use crate::errors::ForgeError;
use crate::model::*;

const PASSWORD: &str = "correct-horse-battery";

fn names(logins: &[&str]) -> Vec<String> {
    logins.iter().map(|login| (*login).to_string()).collect()
}

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

/// root administers the forge. alice owns organization acme; bob and carol
/// are its `stewards` team. dave administers acme/widgets; erin is nobody's.
/// acme/widgets and acme/docs are private, acme/public is public.
fn seed(core: &ForgeCore) {
    core.create_account("root", PASSWORD, UserRole::Admin)
        .unwrap();
    for login in ["alice", "bob", "carol", "dave", "erin"] {
        core.create_account(login, PASSWORD, UserRole::User)
            .unwrap();
    }
    core.create_organization_as("root", "acme", None, &names(&["alice"]))
        .unwrap();
    core.create_team_as("alice", "acme", "Stewards", None, &names(&["bob", "carol"]))
        .unwrap();
    repo(core, "acme", "widgets", true);
    repo(core, "acme", "docs", true);
    repo(core, "acme", "public", false);
    core.grant_repo_access("root", "dave", "acme", "widgets", RepoAccessLevel::Admin)
        .unwrap();
    core.grant_repo_access("root", "alice", "acme", "widgets", RepoAccessLevel::Write)
        .unwrap();
}

fn fixture() -> ForgeCore {
    let core = ForgeCore::new();
    seed(&core);
    core
}

fn enroll(core: &ForgeCore) -> BotSummary {
    core.enroll_team_bot(
        "alice",
        "acme",
        "stewards",
        "reviewer",
        "Reviewer",
        BotKind::default(),
        BotReach::General,
    )
    .unwrap()
    .bot
}

fn token(core: &ForgeCore, issuer: &str, bot: &BotSummary) -> String {
    core.issue_bot_access_token(issuer, bot.id, None, None)
        .unwrap()
        .token
}

fn call(auth: &BotAccessTokenAuth, name: &str, effect: BotEffect) -> BotCall {
    BotCall {
        bot_id: auth.bot.id,
        generation: auth.generation,
        key_id: auth.key_id.clone(),
        owner: "acme".to_string(),
        repo: name.to_string(),
        effect,
        task_kind: None,
        task_id: None,
    }
}

#[test]
fn an_owner_enrolls_a_team_bot_that_acts_as_its_own_name() {
    let core = fixture();
    let bot = enroll(&core);
    assert_eq!(bot.owner, "acme");
    assert_eq!(bot.owner_kind, BotOwnerKind::Organization);
    assert_eq!(bot.steward_team.as_deref(), Some("stewards"));
    assert_eq!(bot.acting_login, "acme.reviewer[bot]");
    let acting = core.bot_acting_account(bot.id).unwrap();
    assert_eq!(acting.login, "acme.reviewer[bot]");
    assert_eq!(acting.role, UserRole::User);
    assert!(core.get_account("acme.reviewer[bot]").is_err());
    // A steward who does not own the organization cannot enroll one.
    let error = core
        .enroll_team_bot(
            "bob",
            "acme",
            "stewards",
            "other",
            "Other",
            BotKind::default(),
            BotReach::General,
        )
        .unwrap_err();
    assert!(matches!(error, ForgeError::Forbidden(_)), "{error:?}");
    let error = core
        .enroll_team_bot(
            "alice",
            "acme",
            "nobody",
            "other",
            "Other",
            BotKind::default(),
            BotReach::General,
        )
        .unwrap_err();
    assert!(matches!(error, ForgeError::Validation(_)), "{error:?}");
    let error = core
        .enroll_team_bot(
            "alice",
            "acme",
            "stewards",
            "reviewer",
            "Again",
            BotKind::default(),
            BotReach::General,
        )
        .unwrap_err();
    assert!(matches!(error, ForgeError::Conflict(_)), "{error:?}");
}

#[test]
fn a_team_bot_holds_only_its_own_grants_never_its_people() {
    let core = fixture();
    let bot = enroll(&core);
    let auth = core
        .authenticate_bot_access_token(&token(&core, "bob", &bot))
        .unwrap();
    // alice, who enrolled it, may write acme/widgets; the bot may not.
    let error = core
        .authorize_bot(&call(&auth, "widgets", BotEffect::Read))
        .unwrap_err();
    assert!(error.to_string().contains("repo_not_granted"), "{error}");
    assert!(
        core.authorize_bot(&call(&auth, "public", BotEffect::Read))
            .is_ok()
    );
    assert!(
        core.authorize_bot(&call(&auth, "public", BotEffect::Write))
            .is_err()
    );
    // Only an administrator of the repository grants.
    for actor in ["alice", "bob", "erin"] {
        let error = core
            .grant_bot_repository(actor, bot.id, "acme", "widgets", BotRepoAccess::Write)
            .unwrap_err();
        assert!(
            matches!(error, ForgeError::Forbidden(_)),
            "{actor}: {error:?}"
        );
    }
    core.grant_bot_repository("dave", bot.id, "acme", "widgets", BotRepoAccess::Read)
        .unwrap();
    assert!(
        core.authorize_bot(&call(&auth, "widgets", BotEffect::Read))
            .is_ok()
    );
    let error = core
        .authorize_bot(&call(&auth, "widgets", BotEffect::Write))
        .unwrap_err();
    assert!(error.to_string().contains("insufficient_scope"), "{error}");
    core.grant_bot_repository("dave", bot.id, "acme", "widgets", BotRepoAccess::Write)
        .unwrap();
    assert!(
        core.authorize_bot(&call(&auth, "widgets", BotEffect::Write))
            .is_ok()
    );
    assert!(
        core.authorize_bot(&call(&auth, "docs", BotEffect::Read))
            .is_err()
    );
    let grants = core.list_bot_repo_grants("carol", bot.id).unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(
        (grants[0].access, grants[0].granted_by.as_str()),
        (BotRepoAccess::Write, "dave")
    );
    core.revoke_bot_repository_grant("dave", bot.id, "acme", "widgets")
        .unwrap();
    assert!(
        core.authorize_bot(&call(&auth, "widgets", BotEffect::Read))
            .is_err()
    );
}

#[test]
fn the_acting_login_resolves_to_the_bot_grant_and_never_to_admin() {
    let core = fixture();
    let bot = enroll(&core);
    let login = bot.acting_login.as_str();
    assert_eq!(core.repo_access_for(login, "acme", "widgets"), None);
    core.grant_bot_repository("root", bot.id, "acme", "widgets", BotRepoAccess::Write)
        .unwrap();
    assert_eq!(
        core.repo_access_for(login, "acme", "widgets"),
        Some(RepoAccessLevel::Write)
    );
    assert!(core.user_can_write_repo(login, "acme", "widgets"));
    assert!(!core.user_can_admin_repo(login, "acme", "widgets"));
    assert!(!core.is_global_admin(login));
    // A team bot cannot grant itself, or anyone, anything.
    assert!(
        core.grant_bot_repository(login, bot.id, "acme", "docs", BotRepoAccess::Write)
            .is_err()
    );
    assert!(
        core.grant_repo_access_checked(login, "erin", "acme", "widgets", RepoAccessLevel::Write)
            .is_err()
    );
    core.suspend_bot("bob", bot.id).unwrap();
    assert_eq!(core.repo_access_for(login, "acme", "widgets"), None);
    // Look-alikes of the shape are not team bots.
    assert_eq!(
        core.repo_access_for("acme.ghost[bot]", "acme", "widgets"),
        None
    );
}

#[test]
fn stewards_and_administrators_manage_and_nobody_else_does() {
    let core = fixture();
    let bot = enroll(&core);
    for steward in ["bob", "carol", "root"] {
        assert!(
            core.list_bot_access_tokens(steward, bot.id).is_ok(),
            "{steward}"
        );
        assert_eq!(core.list_team_bots(steward).unwrap().len(), 1, "{steward}");
    }
    // The organization's owner is not a steward unless on the team.
    for outsider in ["alice", "dave", "erin"] {
        let error = core
            .issue_bot_access_token(outsider, bot.id, None, None)
            .unwrap_err();
        assert!(
            matches!(error, ForgeError::NotFound(_)),
            "{outsider}: {error:?}"
        );
        assert!(core.list_team_bots(outsider).unwrap().is_empty());
    }
    // A team bot belongs to no person's roster.
    assert!(core.list_account_bots("alice").unwrap().is_empty());
}

#[test]
fn leaving_the_team_or_losing_the_account_takes_only_that_stewards_tokens() {
    let core = fixture();
    let bot = enroll(&core);
    let from_bob = token(&core, "bob", &bot);
    let from_carol = token(&core, "carol", &bot);
    let from_root = token(&core, "root", &bot);
    // A password change is not a departure.
    core.change_account_password("bob", PASSWORD, "another-horse-battery")
        .unwrap();
    assert!(core.authenticate_bot_access_token(&from_bob).is_ok());
    core.remove_team_member("alice", "acme", "stewards", "bob")
        .unwrap();
    assert!(core.authenticate_bot_access_token(&from_bob).is_err());
    assert!(core.authenticate_bot_access_token(&from_carol).is_ok());
    let revoked = core
        .list_bot_access_tokens("carol", bot.id)
        .unwrap()
        .into_iter()
        .filter(|summary| summary.revoked_at.is_some())
        .map(|summary| summary.issued_by)
        .collect::<Vec<_>>();
    assert_eq!(revoked, vec![Some("bob".to_string())]);
    // Rejoining does not revive a revoked token.
    core.add_team_member("alice", "acme", "stewards", "bob")
        .unwrap();
    assert!(core.authenticate_bot_access_token(&from_bob).is_err());
    core.lock_account("carol").unwrap();
    assert!(core.authenticate_bot_access_token(&from_carol).is_err());
    core.reactivate_account("carol").unwrap();
    assert!(core.authenticate_bot_access_token(&from_carol).is_err());
    assert!(core.authenticate_bot_access_token(&from_root).is_ok());
}

#[test]
fn a_steward_revokes_every_token_they_issued_in_one_action() {
    let core = fixture();
    let bot = enroll(&core);
    let first = token(&core, "bob", &bot);
    let second = token(&core, "bob", &bot);
    let other = token(&core, "carol", &bot);
    assert_eq!(core.revoke_issued_team_bot_tokens("bob").unwrap(), 2);
    assert_eq!(core.revoke_issued_team_bot_tokens("bob").unwrap(), 0);
    assert!(core.authenticate_bot_access_token(&first).is_err());
    assert!(core.authenticate_bot_access_token(&second).is_err());
    assert!(core.authenticate_bot_access_token(&other).is_ok());
}

#[test]
fn a_team_bot_enrollment_key_is_never_exchangeable() {
    let core = fixture();
    let enrollment = core
        .enroll_team_bot(
            "alice",
            "acme",
            "stewards",
            "ci",
            "CI",
            BotKind::default(),
            BotReach::General,
        )
        .unwrap();
    let error = core
        .exchange_bot_enrollment_key(&enrollment.enrollment_key)
        .unwrap_err();
    assert!(
        error.to_string().contains("invalid bot credential"),
        "{error}"
    );
    let rotated = core.rotate_bot_key("bob", enrollment.bot.id).unwrap();
    assert!(
        core.exchange_bot_enrollment_key(&rotated.enrollment_key)
            .is_err()
    );
    // Tokens still work after a rotation, as for any bot.
    let issued = token(&core, "bob", &enrollment.bot);
    assert!(core.authenticate_bot_access_token(&issued).is_ok());
}

#[test]
fn deleting_a_repository_drops_the_grants_on_it() {
    let dir = tempfile::tempdir().unwrap();
    let core = ForgeCore::open_sqlite(dir.path().join("forge.sqlite")).unwrap();
    seed(&core);
    let bot = enroll(&core);
    core.grant_bot_repository("root", bot.id, "acme", "docs", BotRepoAccess::Read)
        .unwrap();
    core.delete_repository("acme", "docs").unwrap();
    assert!(core.list_bot_repo_grants("bob", bot.id).unwrap().is_empty());
}

#[test]
fn team_bot_survives_sqlite_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("forge.sqlite");
    let (bot_id, issued) = {
        let core = ForgeCore::open_sqlite(&path).unwrap();
        seed(&core);
        let bot = enroll(&core);
        core.grant_bot_repository("dave", bot.id, "acme", "widgets", BotRepoAccess::Write)
            .unwrap();
        (bot.id, token(&core, "carol", &bot))
    };
    let core = ForgeCore::open_sqlite(&path).unwrap();
    let auth = core.authenticate_bot_access_token(&issued).unwrap();
    assert_eq!(auth.bot.acting_login, "acme.reviewer[bot]");
    assert!(
        core.authorize_bot(&call(&auth, "widgets", BotEffect::Write))
            .is_ok()
    );
    let tokens = core.list_bot_access_tokens("bob", bot_id).unwrap();
    assert_eq!(tokens[0].issued_by.as_deref(), Some("carol"));
    let grants = core.list_bot_repo_grants("bob", bot_id).unwrap();
    assert_eq!(
        (grants[0].repo.as_str(), grants[0].access),
        ("widgets", BotRepoAccess::Write)
    );
}
