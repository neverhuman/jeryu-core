//! Direct tests for the credential and repository-access decision paths.

use super::*;
use chrono::Duration;

const PASSWORD: &str = "correct-horse-battery";
const OTHER_PASSWORD: &str = "another-long-password";

fn core() -> ForgeCore {
    ForgeCore::new()
}

fn core_with_repo() -> ForgeCore {
    let core = core();
    core.create_user(CreateUserRequest {
        login: "alice".to_string(),
        name: None,
        email: None,
    })
    .unwrap();
    core.create_repository(
        "alice",
        CreateRepositoryRequest {
            name: "jeryu".to_string(),
            private: true,
            description: None,
            default_branch: Some("main".to_string()),
        },
    )
    .unwrap();
    core
}

fn core_with_team() -> ForgeCore {
    let core = core();
    core.create_organization(CreateOrganizationRequest {
        login: "acme".to_string(),
        display_name: None,
    })
    .unwrap();
    core.create_team(
        "acme",
        CreateTeamRequest {
            name: "Core".to_string(),
            slug: Some("core".to_string()),
            members: Vec::new(),
        },
    )
    .unwrap();
    core
}

fn user_bindings() -> InvitationBindings {
    InvitationBindings {
        role: UserRole::User,
        teams: Vec::new(),
    }
}

fn soon() -> DateTime<Utc> {
    Utc::now() + Duration::hours(1)
}

fn is_validation(result: &Result<impl std::fmt::Debug>) -> bool {
    matches!(result, Err(ForgeError::Validation(_)))
}

fn is_activation_error<T: std::fmt::Debug>(result: Result<T>) -> bool {
    matches!(result, Err(ForgeError::Validation(message)) if message == ACTIVATION_ERROR)
}

// --- helpers -------------------------------------------------------------

#[test]
fn require_login_accepts_only_canonical_logins() {
    for login in ["alice", "a-b_c", "user42"] {
        assert!(require_login(login).is_ok(), "{login}");
    }
    for login in [
        "", "Alice", " alice", "alice ", "al ice", "al/ice", "élan", "a.b",
    ] {
        assert!(require_login(login).is_err(), "{login:?}");
    }
}

#[test]
fn require_password_enforces_minimum_length() {
    assert!(require_password("12345678901").is_err());
    assert!(require_password("123456789012").is_ok());
}

#[test]
fn team_bindings_are_normalized_and_validated() {
    let normalized = normalize_team_bindings(&[
        " acme/core ".to_string(),
        "acme/core".to_string(),
        "acme/alpha".to_string(),
    ])
    .unwrap();
    assert_eq!(normalized, vec!["acme/alpha", "acme/core"]);
    for binding in ["acme", "/core", "acme/", "acme/core/x", "Acme/core"] {
        assert!(
            normalize_team_bindings(&[binding.to_string()]).is_err(),
            "{binding}"
        );
    }
}

#[test]
fn next_auth_epoch_rejects_overflow() {
    assert_eq!(next_auth_epoch(0).unwrap(), 1);
    assert!(matches!(
        next_auth_epoch(u64::MAX),
        Err(ForgeError::Storage(_))
    ));
}

#[test]
fn constant_time_eq_compares_length_and_content() {
    assert!(constant_time_eq(b"abc", b"abc"));
    assert!(!constant_time_eq(b"abc", b"abd"));
    assert!(!constant_time_eq(b"abc", b"abcd"));
    assert!(constant_time_eq(b"", b""));
}

#[test]
fn pat_expiry_defaults_and_bounds() {
    let now = Utc::now();
    let defaulted = validate_pat_expiry(None).unwrap().unwrap();
    assert!(defaulted > now + Duration::days(PAT_DEFAULT_TTL_DAYS - 1));
    assert!(validate_pat_expiry(Some(now - Duration::seconds(1))).is_err());
    assert!(validate_pat_expiry(Some(now + Duration::days(PAT_MAX_TTL_DAYS + 1))).is_err());
    assert!(validate_pat_expiry(Some(now + Duration::days(30))).is_ok());
}

#[test]
fn password_hash_is_argon2id_and_verifies() {
    let hash = hash_password(PASSWORD).unwrap();
    assert!(hash.starts_with("$argon2id$"));
    assert!(verify_password(PASSWORD, &hash).is_ok());
    assert!(verify_password(OTHER_PASSWORD, &hash).is_err());
    assert!(verify_password(PASSWORD, "not-a-phc-string").is_err());
}

#[test]
fn one_time_password_and_token_hash_shapes() {
    let otp = core().generate_one_time_password().unwrap();
    assert!(otp.starts_with("jeryu-"));
    assert_eq!(otp.len(), "jeryu-".len() + 32);
    assert_eq!(token_hash("x"), token_hash("x"));
    assert_ne!(token_hash("x"), token_hash("y"));
    assert_eq!(token_hash("x").len(), 64);
}

// --- accounts and passwords ---------------------------------------------

#[test]
fn create_account_validates_and_rejects_duplicates() {
    let core = core();
    assert!(is_validation(&core.create_account(
        "Bad",
        PASSWORD,
        UserRole::User
    )));
    assert!(is_validation(&core.create_account(
        "bob",
        "short",
        UserRole::User
    )));
    let account = core
        .create_account("bob", PASSWORD, UserRole::User)
        .unwrap();
    assert_eq!(account.status, AccountStatus::Active);
    assert_eq!(account.auth_epoch, 0);
    assert!(!account.must_change_password);
    assert!(matches!(
        core.create_account("bob", PASSWORD, UserRole::User),
        Err(ForgeError::Conflict(_))
    ));
    assert!(matches!(
        core.get_account("nobody"),
        Err(ForgeError::NotFound(_))
    ));
}

#[test]
fn list_accounts_is_sorted_by_login() {
    let core = core();
    core.create_account("zed", PASSWORD, UserRole::User)
        .unwrap();
    core.create_account("amy", PASSWORD, UserRole::User)
        .unwrap();
    let logins: Vec<_> = core.list_accounts().into_iter().map(|a| a.login).collect();
    assert_eq!(logins, vec!["amy", "zed"]);
}

#[test]
fn temporary_account_must_change_password() {
    let core = core();
    let account = core
        .create_temporary_account("bob", PASSWORD, UserRole::User)
        .unwrap();
    assert!(account.must_change_password);
    assert_eq!(account.auth_epoch, 1);
}

#[test]
fn authenticate_password_denies_unknown_wrong_and_inactive() {
    let core = core();
    core.create_account("bob", PASSWORD, UserRole::User)
        .unwrap();
    assert!(core.authenticate_password("bob", PASSWORD).is_ok());
    assert!(is_validation(
        &core.authenticate_password("bob", OTHER_PASSWORD)
    ));
    assert!(is_validation(
        &core.authenticate_password("nobody", PASSWORD)
    ));
    core.lock_account("bob").unwrap();
    assert!(is_validation(&core.authenticate_password("bob", PASSWORD)));
}

#[test]
fn reset_password_revokes_credentials_and_forces_change() {
    let core = core();
    core.create_account("bob", PASSWORD, UserRole::User)
        .unwrap();
    let session = core.create_session("bob").unwrap();
    let pat = core
        .create_personal_access_token("bob", "ci", None)
        .unwrap();
    assert!(matches!(
        core.reset_account_password("nobody", OTHER_PASSWORD),
        Err(ForgeError::NotFound(_))
    ));
    assert!(is_validation(&core.reset_account_password("bob", "short")));
    let account = core.reset_account_password("bob", OTHER_PASSWORD).unwrap();
    assert!(account.must_change_password);
    assert_eq!(account.auth_epoch, 1);
    assert!(core.authenticate_session(&session.token).is_none());
    assert!(
        core.authenticate_personal_access_token(&pat.secret)
            .is_none()
    );
    assert!(core.list_personal_access_tokens("bob").unwrap().is_empty());
    assert!(core.authenticate_password("bob", PASSWORD).is_err());
    assert!(core.authenticate_password("bob", OTHER_PASSWORD).is_ok());
}

#[test]
fn change_password_requires_current_password_and_active_status() {
    let core = core();
    core.create_temporary_account("bob", PASSWORD, UserRole::User)
        .unwrap();
    assert!(is_validation(&core.change_account_password(
        "bob",
        OTHER_PASSWORD,
        OTHER_PASSWORD
    )));
    assert!(is_validation(
        &core.change_account_password("bob", PASSWORD, "short")
    ));
    assert!(matches!(
        core.change_account_password("nobody", PASSWORD, OTHER_PASSWORD),
        Err(ForgeError::NotFound(_))
    ));
    let session = core.create_session("bob").unwrap();
    let account = core
        .change_account_password("bob", PASSWORD, OTHER_PASSWORD)
        .unwrap();
    assert!(!account.must_change_password);
    assert_eq!(account.auth_epoch, 2);
    assert!(core.authenticate_session(&session.token).is_none());

    core.disable_account("bob").unwrap();
    assert!(is_validation(&core.change_account_password(
        "bob",
        OTHER_PASSWORD,
        PASSWORD
    )));
}

#[test]
fn clearing_forced_change_keeps_credentials() {
    let core = core();
    core.create_account("bob", PASSWORD, UserRole::User)
        .unwrap();
    let session = core.create_session("bob").unwrap();
    let cleared = core.force_password_change("bob", false).unwrap();
    assert_eq!(cleared.auth_epoch, 0);
    assert!(core.authenticate_session(&session.token).is_some());
    let forced = core.force_password_change("bob", true).unwrap();
    assert_eq!(forced.auth_epoch, 1);
    assert!(core.authenticate_session(&session.token).is_none());
    assert!(matches!(
        core.force_password_change("nobody", true),
        Err(ForgeError::NotFound(_))
    ));
}

// --- sessions ------------------------------------------------------------

#[test]
fn session_round_trip_csrf_and_revoke() {
    let core = core();
    core.create_account("bob", PASSWORD, UserRole::User)
        .unwrap();
    let receipt = core.create_session("bob").unwrap();
    assert_ne!(receipt.session.token_hash, receipt.token);
    assert_eq!(receipt.session.token_hash, token_hash(&receipt.token));
    assert_eq!(
        core.authenticate_session(&receipt.token).unwrap().login,
        "bob"
    );
    assert!(core.session_csrf_matches(&receipt.token, &receipt.session.csrf_token));
    assert!(!core.session_csrf_matches(&receipt.token, "wrong"));
    assert!(!core.session_csrf_matches("unknown", &receipt.session.csrf_token));
    assert!(core.authenticate_session("unknown").is_none());
    core.revoke_session(&receipt.token).unwrap();
    assert!(core.authenticate_session(&receipt.token).is_none());
}

#[test]
fn session_creation_rejects_bad_ttl_and_inactive_accounts() {
    let core = core();
    core.create_account("bob", PASSWORD, UserRole::User)
        .unwrap();
    assert!(is_validation(
        &core.create_session_with_ttl("bob", Duration::zero())
    ));
    assert!(is_validation(
        &core.create_session_with_ttl("bob", Duration::seconds(-1))
    ));
    assert!(matches!(
        core.create_session("nobody"),
        Err(ForgeError::NotFound(_))
    ));
    core.disable_account("bob").unwrap();
    assert!(is_validation(&core.create_session("bob")));
}

#[test]
fn expired_session_is_rejected() {
    let core = core();
    core.create_account("bob", PASSWORD, UserRole::User)
        .unwrap();
    let receipt = core.create_session("bob").unwrap();
    core.state
        .write()
        .sessions
        .get_mut(&receipt.session.token_hash)
        .unwrap()
        .expires_at = Utc::now() - Duration::seconds(1);
    assert!(core.authenticate_session(&receipt.token).is_none());
}

#[test]
fn session_with_stale_epoch_is_rejected() {
    let core = core();
    core.create_account("bob", PASSWORD, UserRole::User)
        .unwrap();
    let receipt = core.create_session("bob").unwrap();
    core.state
        .write()
        .accounts
        .get_mut("bob")
        .unwrap()
        .auth_epoch = 7;
    assert!(core.authenticate_session(&receipt.token).is_none());
}

// --- personal access tokens ----------------------------------------------

#[test]
fn pat_round_trip_listing_and_owner_scoped_revoke() {
    let core = core();
    core.create_account("bob", PASSWORD, UserRole::User)
        .unwrap();
    core.create_account("eve", PASSWORD, UserRole::User)
        .unwrap();
    let receipt = core
        .create_personal_access_token("bob", "  ci  ", None)
        .unwrap();
    assert!(receipt.secret.starts_with("jpat_"));
    assert_eq!(receipt.token.name, "ci");
    assert_eq!(receipt.token.token_hash, token_hash(&receipt.secret));
    assert_eq!(
        core.authenticate_personal_access_token(&receipt.secret)
            .unwrap()
            .login,
        "bob"
    );
    assert!(
        core.authenticate_personal_access_token("jpat_unknown")
            .is_none()
    );
    assert_eq!(core.list_personal_access_tokens("bob").unwrap().len(), 1);
    assert!(core.list_personal_access_tokens("eve").unwrap().is_empty());
    assert!(matches!(
        core.list_personal_access_tokens("nobody"),
        Err(ForgeError::NotFound(_))
    ));

    assert!(
        !core
            .revoke_personal_access_token("eve", receipt.token.id)
            .unwrap()
    );
    assert!(
        core.authenticate_personal_access_token(&receipt.secret)
            .is_some()
    );
    assert!(
        core.revoke_personal_access_token("bob", receipt.token.id)
            .unwrap()
    );
    assert!(
        !core
            .revoke_personal_access_token("bob", receipt.token.id)
            .unwrap()
    );
    assert!(
        core.authenticate_personal_access_token(&receipt.secret)
            .is_none()
    );
}

#[test]
fn pat_creation_validates_inputs() {
    let core = core();
    core.create_account("bob", PASSWORD, UserRole::User)
        .unwrap();
    assert!(
        core.create_personal_access_token("bob", "  ", None)
            .is_err()
    );
    assert!(
        core.create_personal_access_token("bob", "ci", Some(Utc::now() - Duration::days(1)))
            .is_err()
    );
    assert!(
        core.create_personal_access_token("nobody", "ci", None)
            .is_err()
    );
    core.lock_account("bob").unwrap();
    assert!(is_validation(
        &core.create_personal_access_token("bob", "ci", None)
    ));
}

#[test]
fn pat_expired_or_stale_epoch_is_rejected() {
    let core = core();
    core.create_account("bob", PASSWORD, UserRole::User)
        .unwrap();
    let expired = core
        .create_personal_access_token("bob", "old", None)
        .unwrap();
    core.state
        .write()
        .personal_tokens
        .get_mut(&expired.token.id)
        .unwrap()
        .expires_at = Some(Utc::now() - Duration::seconds(1));
    assert!(
        core.authenticate_personal_access_token(&expired.secret)
            .is_none()
    );

    let stale = core
        .create_personal_access_token("bob", "stale", None)
        .unwrap();
    core.state
        .write()
        .accounts
        .get_mut("bob")
        .unwrap()
        .auth_epoch = 3;
    assert!(
        core.authenticate_personal_access_token(&stale.secret)
            .is_none()
    );
}

// --- account status transitions -------------------------------------------

#[test]
fn status_transitions_follow_the_lifecycle() {
    let core = core();
    core.create_account("bob", PASSWORD, UserRole::User)
        .unwrap();

    assert!(is_validation(&core.reactivate_account("bob")));
    assert!(is_validation(&core.mark_account_mfa_active("bob")));

    let session = core.create_session("bob").unwrap();
    let locked = core.lock_account("bob").unwrap();
    assert_eq!(locked.status, AccountStatus::Locked);
    assert_eq!(locked.auth_epoch, 1);
    assert!(core.authenticate_session(&session.token).is_none());

    // Repeating the same transition is a no-op that does not bump the epoch.
    assert_eq!(core.lock_account("bob").unwrap().auth_epoch, 1);

    let disabled = core.disable_account("bob").unwrap();
    assert_eq!(disabled.status, AccountStatus::Disabled);
    assert_eq!(disabled.auth_epoch, 2);

    let pending = core.reactivate_account("bob").unwrap();
    assert_eq!(pending.status, AccountStatus::PendingMfa);
    assert!(is_validation(&core.create_session("bob")));

    let active = core.mark_account_mfa_active("bob").unwrap();
    assert_eq!(active.status, AccountStatus::Active);
    assert_eq!(active.auth_epoch, 4);
    assert!(core.create_session("bob").is_ok());

    assert!(matches!(
        core.lock_account("nobody"),
        Err(ForgeError::NotFound(_))
    ));
}

// --- invitations and activation --------------------------------------------

#[test]
fn invitation_validates_inputs() {
    let core = core_with_team();
    let invite = |login: &str, name: &str, teams: Vec<String>, expires_at| {
        core.create_account_invitation(
            "admin",
            login,
            name,
            InvitationBindings {
                role: UserRole::User,
                teams,
            },
            expires_at,
        )
    };
    assert!(invite("Bob", "Bob", Vec::new(), soon()).is_err());
    assert!(invite("bob", " ", Vec::new(), soon()).is_err());
    assert!(invite("bob", "Bob", vec!["bad".to_string()], soon()).is_err());
    assert!(invite("bob", "Bob", Vec::new(), Utc::now() - Duration::minutes(1)).is_err());
    assert!(
        invite(
            "bob",
            "Bob",
            Vec::new(),
            Utc::now() + Duration::hours(INVITATION_MAX_TTL_HOURS + 1)
        )
        .is_err()
    );
    assert!(matches!(
        invite("bob", "Bob", vec!["acme/missing".to_string()], soon()),
        Err(ForgeError::NotFound(_))
    ));
    assert!(
        core.create_account_invitation("  ", "bob", "Bob", user_bindings(), soon())
            .is_err()
    );
    core.create_account("taken", PASSWORD, UserRole::User)
        .unwrap();
    assert!(matches!(
        invite("taken", "Taken", Vec::new(), soon()),
        Err(ForgeError::Conflict(_))
    ));
}

#[test]
fn only_one_active_invitation_per_login() {
    let core = core();
    let first = core
        .create_account_invitation("admin", "bob", " Bob ", user_bindings(), soon())
        .unwrap();
    assert_eq!(first.invitation.display_name, "Bob");
    assert_ne!(first.activation_secret, "");
    assert!(matches!(
        core.create_account_invitation("admin", "bob", "Bob", user_bindings(), soon()),
        Err(ForgeError::Conflict(_))
    ));
    assert!(core.revoke_account_invitation(first.invitation.id).unwrap());
    assert!(!core.revoke_account_invitation(first.invitation.id).unwrap());
    assert!(!core.revoke_account_invitation(Uuid::new_v4()).unwrap());
    assert!(
        core.create_account_invitation("admin", "bob", "Bob", user_bindings(), soon())
            .is_ok()
    );
    assert_eq!(core.list_account_invitations().len(), 2);
}

#[test]
fn expired_invitations_are_swept_on_new_invitation() {
    let core = core();
    let first = core
        .create_account_invitation("admin", "bob", "Bob", user_bindings(), soon())
        .unwrap();
    core.state
        .write()
        .invitations
        .get_mut(&first.invitation.id)
        .unwrap()
        .expires_at = Utc::now() - Duration::seconds(1);
    core.create_account_invitation("admin", "bob", "Bob", user_bindings(), soon())
        .unwrap();
    let swept = core
        .list_account_invitations()
        .into_iter()
        .find(|invitation| invitation.id == first.invitation.id)
        .unwrap();
    assert!(swept.revoked_at.is_some());
}

#[test]
fn activation_happy_path_joins_teams_and_leaves_mfa_pending() {
    let core = core_with_team();
    let receipt = core
        .create_account_invitation(
            "admin",
            "bob",
            "Bob",
            InvitationBindings {
                role: UserRole::User,
                teams: vec!["acme/core".to_string()],
            },
            soon(),
        )
        .unwrap();
    let start = core
        .start_account_activation("bob", &receipt.activation_secret)
        .unwrap();
    let account = core
        .complete_account_activation(&start.challenge, PASSWORD)
        .unwrap();
    assert_eq!(account.status, AccountStatus::PendingMfa);
    assert_eq!(account.display_name, "Bob");
    assert!(core.authenticate_password("bob", PASSWORD).is_err());
    let team = core.state.read().teams[&("acme".to_string(), "core".to_string())].clone();
    assert_eq!(team.members, vec!["bob"]);

    // Challenge and invitation are single-use.
    assert!(is_activation_error(
        core.complete_account_activation(&start.challenge, PASSWORD)
    ));
    assert!(is_activation_error(
        core.start_account_activation("bob", &receipt.activation_secret)
    ));
}

#[test]
fn activation_start_rejects_bad_login_and_secret_with_uniform_error() {
    let core = core();
    let receipt = core
        .create_account_invitation("admin", "bob", "Bob", user_bindings(), soon())
        .unwrap();
    assert!(is_activation_error(
        core.start_account_activation("Bob", &receipt.activation_secret)
    ));
    assert!(is_activation_error(
        core.start_account_activation("carol", &receipt.activation_secret)
    ));
    assert!(is_activation_error(
        core.start_account_activation("bob", "wrong")
    ));
    // Failed attempts are counted and persisted.
    assert_eq!(core.list_account_invitations()[0].attempt_count, 1);
}

#[test]
fn activation_locks_out_after_max_attempts() {
    let core = core();
    let receipt = core
        .create_account_invitation("admin", "bob", "Bob", user_bindings(), soon())
        .unwrap();
    for _ in 0..ACTIVATION_MAX_ATTEMPTS {
        assert!(is_activation_error(
            core.start_account_activation("bob", "wrong")
        ));
    }
    assert!(is_activation_error(
        core.start_account_activation("bob", &receipt.activation_secret)
    ));
    assert_eq!(
        core.list_account_invitations()[0].attempt_count,
        ACTIVATION_MAX_ATTEMPTS
    );
}

#[test]
fn activation_rejects_revoked_invitation_and_expired_challenge() {
    let core = core();
    let receipt = core
        .create_account_invitation("admin", "bob", "Bob", user_bindings(), soon())
        .unwrap();
    let start = core
        .start_account_activation("bob", &receipt.activation_secret)
        .unwrap();
    assert!(is_validation(
        &core.complete_account_activation(&start.challenge, "short")
    ));

    core.state
        .write()
        .activation_challenges
        .get_mut(&token_hash(&start.challenge))
        .unwrap()
        .expires_at = Utc::now() - Duration::seconds(1);
    assert!(is_activation_error(
        core.complete_account_activation(&start.challenge, PASSWORD)
    ));

    let start = core
        .start_account_activation("bob", &receipt.activation_secret)
        .unwrap();
    core.revoke_account_invitation(receipt.invitation.id)
        .unwrap();
    assert!(is_activation_error(
        core.complete_account_activation(&start.challenge, PASSWORD)
    ));
    assert!(is_activation_error(
        core.complete_account_activation("unknown", PASSWORD)
    ));
}

#[test]
fn activation_fails_when_login_was_taken_meanwhile() {
    let core = core();
    let receipt = core
        .create_account_invitation("admin", "bob", "Bob", user_bindings(), soon())
        .unwrap();
    let start = core
        .start_account_activation("bob", &receipt.activation_secret)
        .unwrap();
    core.create_account("bob", PASSWORD, UserRole::User)
        .unwrap();
    assert!(is_activation_error(
        core.complete_account_activation(&start.challenge, PASSWORD)
    ));
}

#[test]
fn bootstrap_owner_is_single_use() {
    let core = core();
    let receipt = core
        .create_bootstrap_owner_invitation("root", "Root", soon())
        .unwrap();
    assert_eq!(receipt.invitation.issuer_principal, "local-operator");
    assert_eq!(receipt.invitation.intended_bindings.role, UserRole::Admin);
    assert!(matches!(
        core.create_bootstrap_owner_invitation("root2", "Root", soon()),
        Err(ForgeError::Conflict(_))
    ));
    assert!(!core.bootstrap_owner_consumed());
    let start = core
        .start_account_activation("root", &receipt.activation_secret)
        .unwrap();
    let owner = core
        .complete_account_activation(&start.challenge, PASSWORD)
        .unwrap();
    assert_eq!(owner.role, UserRole::Admin);
    assert!(core.bootstrap_owner_consumed());
    assert!(matches!(
        core.create_bootstrap_owner_invitation("root2", "Root", soon()),
        Err(ForgeError::Conflict(_))
    ));
}

#[test]
fn bootstrap_owner_refused_once_an_admin_exists() {
    let core = core();
    let receipt = core
        .create_bootstrap_owner_invitation("root", "Root", soon())
        .unwrap();
    let start = core
        .start_account_activation("root", &receipt.activation_secret)
        .unwrap();
    core.create_account("admin", PASSWORD, UserRole::Admin)
        .unwrap();
    assert!(is_activation_error(
        core.complete_account_activation(&start.challenge, PASSWORD)
    ));
    assert!(matches!(
        core.create_bootstrap_owner_invitation("root2", "Root", soon()),
        Err(ForgeError::Conflict(_))
    ));
}

// --- repository access -----------------------------------------------------

#[test]
fn repo_access_levels_gate_read_write_admin() {
    let core = core_with_repo();
    for (login, level) in [
        ("reader", RepoAccessLevel::Read),
        ("writer", RepoAccessLevel::Write),
        ("maintainer", RepoAccessLevel::Admin),
    ] {
        core.create_account(login, PASSWORD, UserRole::User)
            .unwrap();
        core.grant_repo_access("alice", login, "alice", "jeryu", level)
            .unwrap();
    }
    core.create_account("stranger", PASSWORD, UserRole::User)
        .unwrap();
    let check = |login| {
        (
            core.user_can_read_repo(login, "alice", "jeryu"),
            core.user_can_write_repo(login, "alice", "jeryu"),
            core.user_can_admin_repo(login, "alice", "jeryu"),
        )
    };
    assert_eq!(check("reader"), (true, false, false));
    assert_eq!(check("writer"), (true, true, false));
    assert_eq!(check("maintainer"), (true, true, true));
    assert_eq!(check("stranger"), (false, false, false));
    assert_eq!(check("nobody"), (false, false, false));
    // Grants are scoped to one repository.
    assert!(!core.user_can_read_repo("maintainer", "alice", "other"));
}

#[test]
fn global_admin_has_admin_on_every_repo_while_active() {
    let core = core_with_repo();
    core.create_account("root", PASSWORD, UserRole::Admin)
        .unwrap();
    assert!(core.is_global_admin("root"));
    assert_eq!(
        core.repo_access_for("root", "alice", "any"),
        Some(RepoAccessLevel::Admin)
    );
    core.lock_account("root").unwrap();
    assert!(!core.is_global_admin("root"));
    assert_eq!(core.repo_access_for("root", "alice", "any"), None);
    assert!(!core.is_global_admin("nobody"));
}

#[test]
fn inactive_account_loses_repo_grants() {
    let core = core_with_repo();
    core.create_account("writer", PASSWORD, UserRole::User)
        .unwrap();
    core.grant_repo_access("alice", "writer", "alice", "jeryu", RepoAccessLevel::Write)
        .unwrap();
    core.disable_account("writer").unwrap();
    assert!(!core.user_can_read_repo("writer", "alice", "jeryu"));
    core.reactivate_account("writer").unwrap();
    assert!(!core.user_can_read_repo("writer", "alice", "jeryu"));
    core.mark_account_mfa_active("writer").unwrap();
    assert!(core.user_can_write_repo("writer", "alice", "jeryu"));
}

#[test]
fn grant_requires_existing_account_and_repository() {
    let core = core_with_repo();
    core.create_account("bob", PASSWORD, UserRole::User)
        .unwrap();
    assert!(matches!(
        core.grant_repo_access("alice", "nobody", "alice", "jeryu", RepoAccessLevel::Read),
        Err(ForgeError::NotFound(_))
    ));
    assert!(
        core.grant_repo_access("alice", "bob", "alice", "missing", RepoAccessLevel::Read)
            .is_err()
    );
    let grant = core
        .grant_repo_access("alice", "bob", "alice", "jeryu", RepoAccessLevel::Read)
        .unwrap();
    assert_eq!(grant.granted_by, "alice");
    // Re-granting replaces the level.
    core.grant_repo_access("alice", "bob", "alice", "jeryu", RepoAccessLevel::Write)
        .unwrap();
    let grants = core.list_repo_access("alice", "jeryu");
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].access, RepoAccessLevel::Write);
    assert!(core.revoke_repo_access("bob", "alice", "jeryu").unwrap());
    assert!(!core.revoke_repo_access("bob", "alice", "jeryu").unwrap());
    assert!(!core.user_can_read_repo("bob", "alice", "jeryu"));
}

#[test]
fn checked_grant_operations_require_repo_admin() {
    let core = core_with_repo();
    core.create_account("maintainer", PASSWORD, UserRole::User)
        .unwrap();
    core.create_account("writer", PASSWORD, UserRole::User)
        .unwrap();
    core.create_account("bob", PASSWORD, UserRole::User)
        .unwrap();
    core.grant_repo_access(
        "alice",
        "maintainer",
        "alice",
        "jeryu",
        RepoAccessLevel::Admin,
    )
    .unwrap();
    core.grant_repo_access("alice", "writer", "alice", "jeryu", RepoAccessLevel::Write)
        .unwrap();

    assert!(matches!(
        core.grant_repo_access_checked("writer", "bob", "alice", "jeryu", RepoAccessLevel::Read),
        Err(ForgeError::BranchProtection(_))
    ));
    assert!(matches!(
        core.list_repo_access_checked("writer", "alice", "jeryu"),
        Err(ForgeError::BranchProtection(_))
    ));
    assert!(matches!(
        core.revoke_repo_access_checked("writer", "maintainer", "alice", "jeryu"),
        Err(ForgeError::BranchProtection(_))
    ));
    assert!(matches!(
        core.grant_repo_access_checked(
            "maintainer",
            "bob",
            "alice",
            "missing",
            RepoAccessLevel::Read
        ),
        Err(ForgeError::NotFound(_))
    ));

    core.grant_repo_access_checked("maintainer", "bob", "alice", "jeryu", RepoAccessLevel::Read)
        .unwrap();
    let logins: Vec<_> = core
        .list_repo_access_checked("maintainer", "alice", "jeryu")
        .unwrap()
        .into_iter()
        .map(|grant| grant.login)
        .collect();
    assert_eq!(logins, vec!["bob", "maintainer", "writer"]);
    assert!(
        core.revoke_repo_access_checked("maintainer", "bob", "alice", "jeryu")
            .unwrap()
    );
}
