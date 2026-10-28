//! Self-service recovery: a core-issued, single-use secret that sets a new
//! password and revokes every session and API credential of the account, and
//! of no other account (docs/adr/0001).

use chrono::{Duration, Utc};

use super::ForgeCore;
use super::password_recovery::RECOVERY_AUDIT_ACTION;
use crate::errors::ForgeError;
use crate::model::*;

const PASSWORD: &str = "correct-horse-battery";
const NEW_PASSWORD: &str = "another-long-password";
const REFUSED: &str = "validation failed: password recovery could not be completed";

fn names(logins: &[&str]) -> Vec<String> {
    logins.iter().map(|login| (*login).to_string()).collect()
}

/// root administers the forge and owns root/app, where bob has write access.
/// bob is root's `stewards` team in organization acme. eve is unrelated.
fn seed(core: &ForgeCore) {
    core.create_account("root", PASSWORD, UserRole::Admin)
        .unwrap();
    for login in ["bob", "eve"] {
        core.create_account(login, PASSWORD, UserRole::User)
            .unwrap();
    }
    core.create_repository(
        "root",
        CreateRepositoryRequest {
            name: "app".to_string(),
            private: true,
            description: None,
            default_branch: Some("main".to_string()),
        },
    )
    .unwrap();
    core.grant_repo_access("root", "bob", "root", "app", RepoAccessLevel::Write)
        .unwrap();
    core.create_organization_as("root", "acme", None, &names(&["root"]))
        .unwrap();
    core.create_team_as("root", "acme", "Stewards", None, &names(&["bob"]))
        .unwrap();
}

fn sqlite_core() -> (tempfile::TempDir, ForgeCore) {
    let dir = tempfile::tempdir().unwrap();
    let core = ForgeCore::open_sqlite(dir.path().join("forge.sqlite")).unwrap();
    seed(&core);
    (dir, core)
}

fn refused<T: std::fmt::Debug>(result: crate::errors::Result<T>) -> String {
    match result {
        Err(error @ ForgeError::Validation(_)) => error.to_string(),
        other => panic!("expected a validation refusal, got {other:?}"),
    }
}

fn recovery_actions(core: &ForgeCore, login: &str) -> Vec<(String, String)> {
    core.list_audit(&format!("account:{login}"))
        .unwrap()
        .into_iter()
        .map(|entry| (entry.action, entry.phase))
        .collect()
}

/// A wrong secret with the same id as `token`.
fn forged(token: &str) -> String {
    let (head, _) = token.split_once('.').unwrap();
    format!("{head}.{}", "x".repeat(43))
}

/// Every credential a recovery must end, plus one that belongs to someone else.
struct Credentials {
    session: String,
    pat: String,
    bot_key: String,
    bot_token: String,
}

/// A browser session, a personal access token, and one of `login`'s own bots
/// with its enrollment key and an agent token.
fn credentials_of(core: &ForgeCore, login: &str) -> Credentials {
    let session = core.create_session(login).unwrap().token;
    let pat = core
        .create_personal_access_token(login, "ci", None)
        .unwrap()
        .secret;
    let bot = core
        .enroll_bot(login, "helper", "Helper", BotKind::GROK, BotReach::General)
        .unwrap();
    let bot_token = core
        .issue_bot_access_token(login, bot.bot.id, Some("ci"), None)
        .unwrap()
        .token;
    Credentials {
        session,
        pat,
        bot_key: bot.enrollment_key,
        bot_token,
    }
}

fn assert_all_revoked(core: &ForgeCore, credentials: &Credentials) {
    assert!(core.authenticate_session(&credentials.session).is_none());
    assert!(
        core.authenticate_personal_access_token(&credentials.pat)
            .is_none()
    );
    assert!(
        core.authenticate_bot_access_token(&credentials.bot_token)
            .is_err()
    );
    assert!(
        core.exchange_bot_enrollment_key(&credentials.bot_key)
            .is_err()
    );
}

fn assert_all_valid(core: &ForgeCore, credentials: &Credentials) {
    assert!(core.authenticate_session(&credentials.session).is_some());
    assert!(
        core.authenticate_personal_access_token(&credentials.pat)
            .is_some()
    );
    assert!(
        core.authenticate_bot_access_token(&credentials.bot_token)
            .is_ok()
    );
    assert!(
        core.exchange_bot_enrollment_key(&credentials.bot_key)
            .is_ok()
    );
}

#[test]
fn recovery_ends_every_session_of_the_account() {
    let (_dir, core) = sqlite_core();
    let first = core.create_session("bob").unwrap();
    let second = core.create_session("bob").unwrap();
    let issued = core.issue_password_recovery("bob").unwrap();
    assert!(issued.token.starts_with(crate::PASSWORD_RECOVERY_PREFIX));
    assert_eq!(issued.login, "bob");

    let receipt = core.recover_password(&issued.token, NEW_PASSWORD).unwrap();

    assert_eq!(receipt.sessions_ended, 2);
    assert!(core.authenticate_session(&first.token).is_none());
    assert!(core.authenticate_session(&second.token).is_none());
    assert!(core.authenticate_password("bob", PASSWORD).is_err());
    assert!(core.authenticate_password("bob", NEW_PASSWORD).is_ok());
    let fresh = core.create_session("bob").unwrap();
    assert!(core.authenticate_session(&fresh.token).is_some());
}

#[test]
fn recovery_revokes_every_api_token_of_the_account() {
    let (_dir, core) = sqlite_core();
    let bob = credentials_of(&core, "bob");
    let second_pat = core
        .create_personal_access_token("bob", "deploy", None)
        .unwrap();
    let issued = core.issue_password_recovery("bob").unwrap();

    let receipt = core.recover_password(&issued.token, NEW_PASSWORD).unwrap();

    assert_eq!(receipt.personal_access_tokens_revoked, 2);
    assert_eq!(receipt.account.auth_epoch, 1);
    assert!(!receipt.account.must_change_password);
    assert_all_revoked(&core, &bob);
    assert!(
        core.authenticate_personal_access_token(&second_pat.secret)
            .is_none()
    );
    // Grants are the account's permissions, not credentials: they stay.
    assert_eq!(
        core.repo_access_for("bob", "root", "app"),
        Some(RepoAccessLevel::Write)
    );

    let audit = core.list_audit("account:bob").unwrap();
    let phases: Vec<_> = audit
        .iter()
        .map(|entry| (entry.action.as_str(), entry.phase.as_str()))
        .collect();
    assert_eq!(
        phases,
        [
            ("account.password_recovery.issue", "completed"),
            (RECOVERY_AUDIT_ACTION, "completed"),
        ]
    );
    let completed = &audit[1];
    assert_eq!(completed.actor, "bob");
    assert_eq!(completed.detail["token_id"], issued.token_id.as_str());
    assert_eq!(completed.detail["auth_epoch_before"], 0);
    assert_eq!(completed.detail["auth_epoch"], 1);
    assert_eq!(completed.detail["sessions_ended"], 1);
    assert_eq!(completed.detail["personal_access_tokens_revoked"], 2);
    assert_eq!(completed.detail["bot_credentials_revoked"], true);
}

#[test]
fn recovery_leaves_other_accounts_and_team_bots_untouched() {
    let (_dir, core) = sqlite_core();
    let bob = credentials_of(&core, "bob");
    let eve = credentials_of(&core, "eve");
    let root = credentials_of(&core, "root");
    // A team bot belongs to its organization. bob is a steward and issues a
    // token for it; as with a steward's password change, it keeps working.
    let team_bot = core
        .enroll_team_bot(
            "root",
            "acme",
            "stewards",
            "reviewer",
            "Reviewer",
            BotKind::default(),
            BotReach::General,
        )
        .unwrap()
        .bot;
    let team_token = core
        .issue_bot_access_token("bob", team_bot.id, None, None)
        .unwrap()
        .token;
    let eve_epoch = core.state.read().accounts["eve"].auth_epoch;
    let root_epoch = core.state.read().accounts["root"].auth_epoch;
    let issued = core.issue_password_recovery("bob").unwrap();

    core.recover_password(&issued.token, NEW_PASSWORD).unwrap();

    assert_all_revoked(&core, &bob);
    assert_all_valid(&core, &eve);
    assert_all_valid(&core, &root);
    assert!(core.authenticate_bot_access_token(&team_token).is_ok());
    assert_eq!(core.state.read().accounts["eve"].auth_epoch, eve_epoch);
    assert_eq!(core.state.read().accounts["root"].auth_epoch, root_epoch);
    assert!(core.authenticate_password("eve", PASSWORD).is_ok());
    assert!(
        recovery_actions(&core, "eve")
            .iter()
            .all(|(action, _)| !action.starts_with("account.password_recovery"))
    );
}

#[test]
fn recovery_tokens_survive_sqlite_reopen_without_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("forge.sqlite");
    let issued = {
        let core = ForgeCore::open_sqlite(&path).unwrap();
        seed(&core);
        core.issue_password_recovery("bob").unwrap()
    };
    let conn = rusqlite::Connection::open(&path).unwrap();
    let (login, secret_hash): (String, String) = conn
        .query_row(
            "SELECT login, secret_hash FROM password_recovery_tokens WHERE token_id = ?1",
            [&issued.token_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(login, "bob");
    assert_eq!(secret_hash, super::bots::token_hash(&issued.token));
    let dump: Vec<String> = conn
        .prepare("SELECT token_id || login || secret_hash FROM password_recovery_tokens")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(dump.iter().all(|row| !row.contains(&issued.token)));
    drop(conn);

    let core = ForgeCore::open_sqlite(&path).unwrap();
    let receipt = core.recover_password(&issued.token, NEW_PASSWORD).unwrap();
    assert_eq!(receipt.account.auth_epoch, 1);
}

#[test]
fn a_secret_is_spent_once_and_a_new_one_retires_the_old() {
    let (_dir, core) = sqlite_core();
    let first = core.issue_password_recovery("bob").unwrap();
    let second = core.issue_password_recovery("bob").unwrap();
    assert_ne!(first.token_id, second.token_id);
    assert_eq!(
        refused(core.recover_password(&first.token, NEW_PASSWORD)),
        REFUSED
    );
    core.recover_password(&second.token, NEW_PASSWORD).unwrap();
    assert_eq!(
        refused(core.recover_password(&second.token, PASSWORD)),
        REFUSED
    );
    assert!(core.authenticate_password("bob", NEW_PASSWORD).is_ok());
}

#[test]
fn an_expired_secret_is_refused() {
    let (_dir, core) = sqlite_core();
    let issued = core.issue_password_recovery("bob").unwrap();
    core.state
        .write()
        .password_recoveries
        .get_mut(&issued.token_id)
        .unwrap()
        .expires_at = Utc::now() - Duration::seconds(1);
    assert_eq!(
        refused(core.recover_password(&issued.token, NEW_PASSWORD)),
        REFUSED
    );
    assert!(core.authenticate_password("bob", PASSWORD).is_ok());
}

#[test]
fn wrong_secrets_count_attempts_until_the_secret_dies() {
    let (_dir, core) = sqlite_core();
    let issued = core.issue_password_recovery("bob").unwrap();
    for _ in 0..5 {
        assert_eq!(
            refused(core.recover_password(&forged(&issued.token), NEW_PASSWORD)),
            REFUSED
        );
    }
    assert_eq!(
        core.state.read().password_recoveries[&issued.token_id].attempt_count,
        5
    );
    assert_eq!(
        refused(core.recover_password(&issued.token, NEW_PASSWORD)),
        REFUSED
    );
    assert!(core.authenticate_password("bob", PASSWORD).is_ok());
    let audit = core.list_audit("account:bob").unwrap();
    assert_eq!(audit.len(), 6);
    for (attempt, entry) in audit[1..].iter().enumerate() {
        assert_eq!(entry.action, RECOVERY_AUDIT_ACTION);
        assert_eq!(entry.phase, "failed");
        assert_eq!(entry.actor, "local");
        assert_eq!(entry.detail["reason"], "wrong secret");
        assert_eq!(entry.detail["attempt_count"], attempt + 1);
    }
}

#[test]
fn malformed_secrets_and_short_passwords_spend_nothing() {
    let (_dir, core) = sqlite_core();
    let issued = core.issue_password_recovery("bob").unwrap();
    let long = format!("jrr_{}", "a".repeat(200));
    for bad in [
        "",
        "jrr_",
        "jpat_abcdefghjkmn.0123456789012345678901234567890123",
        "jrr_short.0123456789012345678901234567890123",
        "jrr_abcdefghjkmn.short",
        "jrr_abcdefghjkmn0123456789012345678901234567890123",
        long.as_str(),
    ] {
        assert_eq!(refused(core.recover_password(bad, NEW_PASSWORD)), REFUSED);
    }
    let short = refused(core.recover_password(&issued.token, "short"));
    assert!(short.contains("at least 12 bytes"));
    assert_eq!(
        core.state.read().password_recoveries[&issued.token_id].attempt_count,
        0
    );
    core.recover_password(&issued.token, NEW_PASSWORD).unwrap();
}

#[test]
fn unknown_and_inactive_logins_get_one_answer_and_change_nothing() {
    let (_dir, core) = sqlite_core();
    core.create_account("carol", PASSWORD, UserRole::User)
        .unwrap();
    let eve_secret = core.issue_password_recovery("eve").unwrap();
    let carol_secret = core.issue_password_recovery("carol").unwrap();
    let bob_session = core.create_session("bob").unwrap();
    core.disable_account("eve").unwrap();
    core.lock_account("carol").unwrap();
    let records_before = core.state.read().password_recoveries.clone();
    let accounts_before = core.list_accounts();

    let unknown = refused(core.issue_password_recovery("nobody"));
    assert_eq!(unknown, REFUSED);
    assert_eq!(refused(core.issue_password_recovery("eve")), unknown);
    assert_eq!(refused(core.issue_password_recovery("carol")), unknown);
    for secret in [&eve_secret.token, &carol_secret.token] {
        assert_eq!(
            refused(core.recover_password(secret, NEW_PASSWORD)),
            unknown
        );
    }

    assert_eq!(core.state.read().password_recoveries, records_before);
    assert_eq!(core.list_accounts(), accounts_before);
    assert!(core.authenticate_session(&bob_session.token).is_some());
    // Unknown and inactive logins leave the same trace: one `failed` row by
    // the control plane with no detail, written with the same snapshot.
    let refusal = (
        "account.password_recovery.issue".to_string(),
        "failed".to_string(),
    );
    assert_eq!(
        recovery_actions(&core, "nobody"),
        std::slice::from_ref(&refusal)
    );
    for login in ["eve", "carol"] {
        assert_eq!(recovery_actions(&core, login).last(), Some(&refusal));
    }
    let traces: Vec<_> = ["nobody", "eve", "carol"]
        .iter()
        .map(|login| {
            let entry = core
                .list_audit(&format!("account:{login}"))
                .unwrap()
                .pop()
                .unwrap();
            (entry.actor, entry.detail)
        })
        .collect();
    assert!(traces.iter().all(|trace| *trace == traces[0]));
    assert_eq!(traces[0].0, "local");
    assert_eq!(
        refused(core.issue_password_recovery("Not A Login")),
        REFUSED
    );
    assert!(recovery_actions(&core, "Not A Login").is_empty());
}

#[test]
fn a_secret_dies_when_the_account_epoch_moves() {
    let (_dir, core) = sqlite_core();
    let issued = core.issue_password_recovery("bob").unwrap();
    core.change_account_password("bob", PASSWORD, NEW_PASSWORD)
        .unwrap();
    assert_eq!(
        refused(core.recover_password(&issued.token, "third-long-password")),
        REFUSED
    );
    assert!(core.authenticate_password("bob", NEW_PASSWORD).is_ok());
}

#[test]
fn a_forced_change_account_recovers_and_clears_the_flag() {
    let (_dir, core) = sqlite_core();
    core.force_password_change("bob", true).unwrap();
    let bob = credentials_of(&core, "bob");
    let issued = core.issue_password_recovery("bob").unwrap();

    let receipt = core.recover_password(&issued.token, NEW_PASSWORD).unwrap();

    assert!(!receipt.account.must_change_password);
    assert_eq!(receipt.account.auth_epoch, 2);
    assert_all_revoked(&core, &bob);
    assert!(core.authenticate_password("bob", NEW_PASSWORD).is_ok());
    let audit = core.list_audit("account:bob").unwrap();
    let completed = audit.last().unwrap();
    assert_eq!(completed.phase, "completed");
    assert_eq!(completed.detail["auth_epoch"], 2);
}

#[test]
fn administrative_reset_still_revokes_everything() {
    let (_dir, core) = sqlite_core();
    let session = core.create_session("bob").unwrap();
    let pat = core
        .create_personal_access_token("bob", "ci", None)
        .unwrap();
    let bot = core
        .enroll_bot("bob", "helper", "Helper", BotKind::GROK, BotReach::General)
        .unwrap();
    let bot_token = core
        .issue_bot_access_token("bob", bot.bot.id, Some("ci"), None)
        .unwrap()
        .token;

    let account = core.reset_account_password("bob", NEW_PASSWORD).unwrap();

    assert_eq!(account.auth_epoch, 1);
    assert!(account.must_change_password);
    assert!(core.authenticate_session(&session.token).is_none());
    assert!(
        core.authenticate_personal_access_token(&pat.secret)
            .is_none()
    );
    assert!(core.authenticate_bot_access_token(&bot_token).is_err());
    assert!(
        core.exchange_bot_enrollment_key(&bot.enrollment_key)
            .is_err()
    );
}

#[test]
fn the_issued_secret_is_redacted_from_debug_output() {
    let (_dir, core) = sqlite_core();
    let issued = core.issue_password_recovery("bob").unwrap();
    let shown = format!("{issued:?}");
    assert!(shown.contains(&issued.token_id));
    assert!(!shown.contains(&issued.token));
    assert!(shown.contains("[REDACTED]"));
}

fn sqlite_core_at() -> (tempfile::TempDir, std::path::PathBuf, ForgeCore) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("forge.sqlite");
    let core = ForgeCore::open_sqlite(&path).unwrap();
    seed(&core);
    (dir, path, core)
}

fn add_trigger(path: &std::path::Path, sql: &str) {
    rusqlite::Connection::open(path)
        .unwrap()
        .execute_batch(sql)
        .unwrap();
}

#[test]
fn a_recovery_whose_audit_row_cannot_be_written_changes_nothing() {
    let (_dir, path, core) = sqlite_core_at();
    let session = core.create_session("bob").unwrap();
    let issued = core.issue_password_recovery("bob").unwrap();
    add_trigger(
        &path,
        "CREATE TRIGGER reject_completed BEFORE INSERT ON forge_audit_log \
         WHEN NEW.phase = 'completed' BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;",
    );

    assert!(matches!(
        core.recover_password(&issued.token, NEW_PASSWORD),
        Err(ForgeError::Storage(_))
    ));

    assert!(core.authenticate_password("bob", PASSWORD).is_ok());
    assert!(core.authenticate_session(&session.token).is_some());
    assert!(
        core.state.read().password_recoveries[&issued.token_id]
            .consumed_at
            .is_none()
    );
    assert_eq!(recovery_actions(&core, "bob").len(), 1);
}

#[test]
fn a_failed_issue_keeps_the_previous_secret() {
    let (_dir, path, core) = sqlite_core_at();
    let first = core.issue_password_recovery("bob").unwrap();
    add_trigger(
        &path,
        "CREATE TRIGGER reject_issue BEFORE INSERT ON forge_audit_log \
         WHEN NEW.phase = 'completed' BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;",
    );

    assert!(core.issue_password_recovery("bob").is_err());

    let records = core.state.read().password_recoveries.clone();
    assert_eq!(records.len(), 1);
    assert!(records[&first.token_id].consumed_at.is_none());
}

#[test]
fn a_storage_failure_on_a_wrong_secret_still_gets_the_uniform_answer() {
    let (_dir, path, core) = sqlite_core_at();
    let issued = core.issue_password_recovery("bob").unwrap();
    add_trigger(
        &path,
        "CREATE TRIGGER reject_failed BEFORE INSERT ON forge_audit_log \
         WHEN NEW.phase = 'failed' BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;",
    );

    assert_eq!(
        refused(core.recover_password(&forged(&issued.token), NEW_PASSWORD)),
        REFUSED
    );
    assert_eq!(
        core.state.read().password_recoveries[&issued.token_id].attempt_count,
        0
    );
}

#[test]
fn dead_secrets_are_pruned_on_issue_spend_and_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("forge.sqlite");
    let core = ForgeCore::open_sqlite(&path).unwrap();
    seed(&core);
    let first = core.issue_password_recovery("bob").unwrap();
    let second = core.issue_password_recovery("bob").unwrap();
    let ids: Vec<String> = core
        .state
        .read()
        .password_recoveries
        .keys()
        .cloned()
        .collect();
    assert_eq!(ids, std::slice::from_ref(&second.token_id));
    assert!(!ids.contains(&first.token_id));

    core.recover_password(&second.token, NEW_PASSWORD).unwrap();
    assert!(core.state.read().password_recoveries.is_empty());

    let expiring = core.issue_password_recovery("eve").unwrap();
    {
        let mut state = core.state.write();
        state
            .password_recoveries
            .get_mut(&expiring.token_id)
            .unwrap()
            .expires_at = Utc::now() - Duration::seconds(1);
        let previous = state.clone();
        core.persist_after_mutation(&mut state, previous).unwrap();
    }
    drop(core);
    let reopened = ForgeCore::open_sqlite(&path).unwrap();
    assert!(reopened.state.read().password_recoveries.is_empty());
    let rows: i64 = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM password_recovery_tokens", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(rows, 0);
}
