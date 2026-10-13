//! Connect-once vault: sealing, fencing, refresh ordering, and durability.

use std::sync::{Arc, Barrier};
use std::time::Duration;

use super::*;

const CANARY: &[u8] = b"canary-refresh-token-7f3a9c";

fn key(byte: u8) -> VaultKey {
    VaultKey::from_bytes(&[byte; 32]).expect("vault key")
}

fn core_with_vault() -> ForgeCore {
    let core = ForgeCore::new().with_vault_key(key(7));
    core.create_account("alice", "vault-test-password", UserRole::User)
        .expect("alice");
    core.create_account("bob", "vault-test-password", UserRole::User)
        .expect("bob");
    core
}

fn connect(core: &ForgeCore, owner: &str, account: &str) -> ProviderConnection {
    core.connect_provider(
        owner,
        AgentProvider::Claude,
        account,
        CredentialKind::OauthRefresh,
        &ProviderSecret::new(CANARY.to_vec()),
    )
    .expect("connect")
}

fn code(error: ForgeError) -> String {
    error.to_string()
}

/// The provider rotated the secret to `secret` and minted `access`.
fn rotated_to<A>(secret: &[u8], access: A) -> TokenExchange<A> {
    TokenExchange::Rotated {
        secret: ProviderSecret::new(secret.to_vec()),
        access,
    }
}

#[test]
fn connect_once_binds_many_sessions_and_never_exposes_the_secret() {
    let core = core_with_vault();
    let connection = connect(&core, "user/alice", "alice.example.com");
    assert_eq!(connection.state, ConnectionState::Connected);
    assert_eq!(connection.connection_generation, 1);
    let listed = core.list_provider_connections("user/alice");
    assert_eq!(listed, vec![connection.clone()]);
    let json = serde_json::to_string(&listed).expect("json");
    assert!(!json.contains("canary"), "summaries carry no secret");

    // One connection serves every later session for that owner.
    let bindings: Vec<_> = (0..3)
        .map(|_| {
            core.resolve_provider_binding("user/alice", AgentProvider::Claude, None)
                .expect("binding")
        })
        .collect();
    assert!(bindings.iter().all(|b| b.connection_id == connection.id));
    for binding in &bindings {
        let secret = core
            .unseal_provider_secret("user/alice", binding)
            .expect("unseal");
        assert_eq!(secret.expose(), CANARY);
        assert_eq!(format!("{secret:?}"), "ProviderSecret(<redacted>)");
    }
}

#[test]
fn a_connect_whose_authority_ran_out_under_the_lock_changes_nothing() {
    let core = core_with_vault();
    let first = connect(&core, "user/alice", "alice.example.com");
    let replacement = ProviderSecret::new(b"a-later-refresh-token".to_vec());
    let connect_admitted = |admit: bool| {
        core.connect_provider_admitted(
            "user/alice",
            AgentProvider::Claude,
            "alice.example.com",
            CredentialKind::OauthRefresh,
            &replacement,
            || admit,
        )
    };
    // Refused: the same account keeps its generation, and no account is added.
    let refused = connect_admitted(false).expect_err("refused");
    assert!(matches!(refused, ForgeError::Conflict(_)), "{refused}");
    assert!(code(refused).contains("provider_connect_refused"));
    assert_eq!(
        core.list_provider_connections("user/alice"),
        vec![first.clone()]
    );
    let refused = core
        .connect_provider_admitted(
            "user/alice",
            AgentProvider::Claude,
            "another.example.com",
            CredentialKind::OauthRefresh,
            &replacement,
            || false,
        )
        .expect_err("refused");
    assert!(matches!(refused, ForgeError::Conflict(_)), "{refused}");
    assert_eq!(
        core.list_provider_connections("user/alice"),
        vec![first.clone()]
    );
    // Admitted: the next generation, as connect_provider gives.
    let second = connect_admitted(true).expect("admitted");
    assert_eq!((second.id, second.connection_generation), (first.id, 2));
}

#[test]
fn bindings_never_fall_back_to_another_owner_or_provider() {
    let core = core_with_vault();
    let connection = connect(&core, "user/alice", "alice.example.com");
    let not_connected = core
        .resolve_provider_binding("user/bob", AgentProvider::Claude, None)
        .unwrap_err();
    assert!(code(not_connected).contains("provider_not_connected"));
    let codex = core
        .resolve_provider_binding("user/alice", AgentProvider::Codex, None)
        .unwrap_err();
    assert!(code(codex).contains("provider_not_connected"));
    let stolen = core
        .resolve_provider_binding("user/bob", AgentProvider::Claude, Some(&connection.id))
        .unwrap_err();
    assert!(code(stolen).contains("connection_owner_mismatch"));
    let binding = core
        .resolve_provider_binding("user/alice", AgentProvider::Claude, None)
        .expect("binding");
    let unsealed_by_bob = core
        .unseal_provider_secret("user/bob", &binding)
        .unwrap_err();
    assert!(code(unsealed_by_bob).contains("connection_owner_mismatch"));
    assert!(code(AgentProvider::parse("jekko").unwrap_err()).contains("provider_unknown"));
}

#[test]
fn disconnect_drops_the_secret_and_fences_the_generation() {
    let core = core_with_vault();
    let connection = connect(&core, "user/alice", "alice.example.com");
    let binding = core
        .resolve_provider_binding("user/alice", AgentProvider::Claude, None)
        .expect("binding");
    let disconnected = core
        .disconnect_provider("user/alice", &connection.id)
        .expect("disconnect");
    assert_eq!(disconnected.state, ConnectionState::Disconnected);
    assert_eq!(disconnected.connection_generation, 2);
    let refused = core
        .unseal_provider_secret("user/alice", &binding)
        .unwrap_err();
    assert!(code(refused).contains("provider_not_connected"));
    let new_session = core
        .resolve_provider_binding("user/alice", AgentProvider::Claude, None)
        .unwrap_err();
    assert!(code(new_session).contains("provider_not_connected"));

    // Reconnecting the same account bumps the generation again; the binding
    // from before the disconnect stays fenced.
    let reconnected = connect(&core, "user/alice", "alice.example.com");
    assert_eq!(reconnected.id, connection.id);
    assert_eq!(reconnected.connection_generation, 3);
    let stale = core
        .unseal_provider_secret("user/alice", &binding)
        .unwrap_err();
    assert!(code(stale).contains("connection_generation_stale"));
}

#[test]
fn refresh_rotates_within_a_generation_and_serializes() {
    let core = core_with_vault();
    connect(&core, "user/alice", "alice.example.com");
    let binding = core
        .resolve_provider_binding("user/alice", AgentProvider::Claude, None)
        .expect("binding");
    let (refreshed, access) = core
        .refresh_provider_secret("user/alice", &binding, REFRESH_LOCK_TIMEOUT, |current| {
            assert_eq!(current.expose(), CANARY);
            rotated_to(b"rotated-refresh-token", "access-1")
        })
        .expect("refresh");
    assert_eq!(access, "access-1", "access is handed over after the commit");
    assert_eq!(refreshed.secret_version, 1);
    assert_eq!(
        refreshed.connection_generation, binding.connection_generation,
        "a refresh does not fence running sessions"
    );
    let rotated = core
        .unseal_provider_secret("user/alice", &binding)
        .expect("unseal");
    assert_eq!(rotated.expose(), b"rotated-refresh-token");

    // A second refresh waiting on the first gives up with connection_busy.
    let core = Arc::new(core);
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let holder = {
        let (core, binding) = (core.clone(), binding.clone());
        let (entered, release) = (entered.clone(), release.clone());
        std::thread::spawn(move || {
            core.refresh_provider_secret("user/alice", &binding, REFRESH_LOCK_TIMEOUT, |_| {
                entered.wait();
                release.wait();
                rotated_to(b"third", "access-2")
            })
        })
    };
    entered.wait();
    let busy = core
        .refresh_provider_secret(
            "user/alice",
            &binding,
            Duration::from_millis(50),
            |_| -> TokenExchange<()> { panic!("a busy refresh must not call the provider") },
        )
        .unwrap_err();
    assert!(code(busy).contains("connection_busy"));
    release.wait();
    assert_eq!(
        holder
            .join()
            .expect("join")
            .expect("refresh")
            .0
            .secret_version,
        2
    );
}

#[test]
fn an_answer_that_rotated_nothing_keeps_the_stored_secret_current() {
    let core = core_with_vault();
    connect(&core, "user/alice", "alice.example.com");
    let binding = core
        .resolve_provider_binding("user/alice", AgentProvider::Claude, None)
        .expect("binding");
    let failed = core
        .refresh_provider_secret("user/alice", &binding, REFRESH_LOCK_TIMEOUT, |_| {
            TokenExchange::<()>::Unchanged("429 rate limited".into())
        })
        .unwrap_err();
    assert!(code(failed).contains("provider_refresh_failed"));
    let secret = core
        .unseal_provider_secret("user/alice", &binding)
        .expect("unseal");
    assert_eq!(secret.expose(), CANARY);
    let row = &core.list_provider_connections("user/alice")[0];
    assert_eq!(row.state, ConnectionState::Connected);
    assert_eq!(row.secret_version, 0);
    // The marker is gone, so the next refresh runs instead of fencing.
    let (next, ()) = core
        .refresh_provider_secret("user/alice", &binding, REFRESH_LOCK_TIMEOUT, |_| {
            rotated_to(b"rotated", ())
        })
        .expect("a later refresh");
    assert_eq!(next.secret_version, 1);
}

#[test]
fn owners_without_a_vault_or_with_bad_ids_are_refused() {
    let core = ForgeCore::new();
    let refused = core
        .connect_provider(
            "service/redteam",
            AgentProvider::Grok,
            "xai-org",
            CredentialKind::ApiKey,
            &ProviderSecret::new(b"k".to_vec()),
        )
        .unwrap_err();
    assert!(code(refused).contains("vault_unavailable"));
    let core = core_with_vault();
    for owner in ["alice", "user/ghost", "service/", "service/../x", "team/x"] {
        let error = core
            .connect_provider(
                owner,
                AgentProvider::Grok,
                "xai-org",
                CredentialKind::ApiKey,
                &ProviderSecret::new(b"k".to_vec()),
            )
            .unwrap_err();
        assert!(code(error).contains("connection_owner_invalid"), "{owner}");
    }
    core.register_service_namespace("redteam")
        .expect("register");
    let service = core
        .connect_provider(
            "service/redteam",
            AgentProvider::Grok,
            "xai-org",
            CredentialKind::ApiKey,
            &ProviderSecret::new(b"k".to_vec()),
        )
        .expect("service account connection");
    assert_eq!(service.owner_id, "service/redteam");
}

#[test]
fn sealed_secrets_are_bound_to_their_row_and_key() {
    let core = core_with_vault();
    let alice = connect(&core, "user/alice", "alice.example.com");
    let bob = connect(&core, "user/bob", "bob.example.com");
    {
        // Copy alice's sealed secret onto bob's row: it must not open.
        let mut state = core.state.write();
        let sealed = state.provider_connections[&alice.id].sealed.clone();
        state
            .provider_connections
            .get_mut(&bob.id)
            .expect("bob")
            .sealed = sealed;
    }
    let binding = core
        .resolve_provider_binding("user/bob", AgentProvider::Claude, None)
        .expect("binding");
    let swapped = core
        .unseal_provider_secret("user/bob", &binding)
        .unwrap_err();
    assert!(code(swapped).contains("vault_secret_unreadable"));

    let other_key = ForgeCore {
        vault: Some(Arc::new(key(9))),
        ..core.clone()
    };
    let binding = core
        .resolve_provider_binding("user/alice", AgentProvider::Claude, None)
        .expect("binding");
    let wrong_key = other_key
        .unseal_provider_secret("user/alice", &binding)
        .unwrap_err();
    assert!(code(wrong_key).contains("vault_key_mismatch"));
}

#[test]
fn provider_connections_survive_sqlite_reopen_without_plaintext() {
    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("forge.sqlite");
    let id = {
        let core = ForgeCore::open_sqlite(&path)
            .expect("open")
            .with_vault_key(key(7));
        core.create_account("alice", "vault-test-password", UserRole::User)
            .expect("alice");
        connect(&core, "user/alice", "alice.example.com").id
    };
    let bytes = std::fs::read(&path).expect("db bytes");
    assert!(
        !bytes.windows(CANARY.len()).any(|window| window == CANARY),
        "the database file never holds the plaintext secret"
    );
    let core = ForgeCore::open_sqlite(&path)
        .expect("reopen")
        .with_vault_key(key(7));
    let binding = core
        .resolve_provider_binding("user/alice", AgentProvider::Claude, Some(&id))
        .expect("binding after reopen");
    let secret = core
        .unseal_provider_secret("user/alice", &binding)
        .expect("unseal");
    assert_eq!(secret.expose(), CANARY);
    // An unrelated write must not drop the connection from the snapshot.
    core.create_account("carol", "vault-test-password", UserRole::User)
        .expect("carol");
    drop(core);
    let core = ForgeCore::open_sqlite(&path).expect("reopen again");
    assert_eq!(core.list_provider_connections("user/alice").len(), 1);
}

#[test]
fn vault_key_files_must_be_private() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("vault.key");
    std::fs::write(&path, hex::encode([3_u8; 32])).expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let open = VaultKey::from_file(&path).unwrap_err();
    assert!(code(open).contains("vault_key_custody_denied"));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    let loaded = VaultKey::from_file(&path).expect("private key loads");
    assert_eq!(loaded.id(), key(3).id());
    assert!(VaultKey::from_bytes(&[1; 16]).is_err());
}

#[test]
fn a_secret_sealed_before_a_rotation_does_not_open_after_it() {
    let core = core_with_vault();
    connect(&core, "user/alice", "alice.example.com");
    let binding = core
        .resolve_provider_binding("user/alice", AgentProvider::Claude, None)
        .expect("binding");
    let before = core.state.read().provider_connections[&binding.connection_id]
        .sealed
        .clone();
    core.refresh_provider_secret("user/alice", &binding, REFRESH_LOCK_TIMEOUT, |_| {
        rotated_to(b"rotated", ())
    })
    .expect("refresh");
    core.state
        .write()
        .provider_connections
        .get_mut(&binding.connection_id)
        .expect("row")
        .sealed = before;
    let replayed = core
        .unseal_provider_secret("user/alice", &binding)
        .unwrap_err();
    assert!(code(replayed).contains("vault_secret_unreadable"));
}

// Regressions from the lane C red-team review of the vault.

#[test]
fn api_keys_do_not_rotate_on_refresh() {
    let core = core_with_vault();
    core.connect_provider(
        "user/alice",
        AgentProvider::Grok,
        "xai-org",
        CredentialKind::ApiKey,
        &ProviderSecret::new(CANARY.to_vec()),
    )
    .expect("connect");
    let binding = core
        .resolve_provider_binding("user/alice", AgentProvider::Grok, None)
        .expect("binding");
    let refused = core
        .refresh_provider_secret(
            "user/alice",
            &binding,
            REFRESH_LOCK_TIMEOUT,
            |_| -> TokenExchange<()> { panic!("an API key is never sent to a token endpoint") },
        )
        .unwrap_err();
    assert!(code(refused).contains("credential_not_refreshable"));
    assert_eq!(
        core.list_provider_connections("user/alice")[0].secret_version,
        0
    );
}

#[test]
fn owner_ids_follow_the_contract_identifier_rules() {
    let core = core_with_vault();
    for owner in [
        "service/..",
        "service/-x",
        "service/a..b",
        "service/x-",
        "service/a/b",
    ] {
        let error = core
            .connect_provider(
                owner,
                AgentProvider::Codex,
                "acct",
                CredentialKind::ApiKey,
                &ProviderSecret::new(b"k".to_vec()),
            )
            .unwrap_err();
        assert!(code(error).contains("connection_owner_invalid"), "{owner}");
    }
    for name in ["..", "-x", "a..b", "x-", "a/b"] {
        assert!(
            core.register_service_namespace(name).is_err(),
            "{name} is no service account name"
        );
    }
    for owner in ["service/pr-redteam", "service/ci.repair:1"] {
        core.register_service_namespace(owner.trim_start_matches("service/"))
            .expect("register");
        core.connect_provider(
            owner,
            AgentProvider::Codex,
            "acct",
            CredentialKind::ApiKey,
            &ProviderSecret::new(b"k".to_vec()),
        )
        .unwrap_or_else(|error| panic!("{owner}: {error}"));
    }
}

#[test]
fn a_stranger_refresh_is_refused_by_ownership_not_busyness() {
    let core = core_with_vault();
    connect(&core, "user/alice", "alice.example.com");
    let binding = core
        .resolve_provider_binding("user/alice", AgentProvider::Claude, None)
        .expect("binding");
    let stranger = core
        .refresh_provider_secret(
            "user/bob",
            &binding,
            REFRESH_LOCK_TIMEOUT,
            |_| -> TokenExchange<()> { panic!("a stranger must not reach the provider") },
        )
        .unwrap_err();
    assert!(code(stranger).contains("connection_owner_mismatch"));
    core.refresh_provider_secret("user/alice", &binding, REFRESH_LOCK_TIMEOUT, |_| {
        rotated_to(b"rotated", ())
    })
    .expect("refresh");
    assert!(
        core.refresh_locks.is_empty(),
        "refresh locks are dropped when no refresh holds them"
    );
}

#[test]
fn a_disabled_owner_loses_access_to_their_connections() {
    let core = core_with_vault();
    connect(&core, "user/alice", "alice.example.com");
    let binding = core
        .resolve_provider_binding("user/alice", AgentProvider::Claude, None)
        .expect("binding");
    assert_eq!(
        core.check_provider_binding("user/alice", &binding)
            .expect("live")
            .id,
        binding.connection_id
    );
    core.disable_account("alice").expect("disable");
    let refused = core
        .unseal_provider_secret("user/alice", &binding)
        .unwrap_err();
    assert!(code(refused).contains("provider_not_connected"));
    // The metadata check a gateway makes before using access it keeps says
    // the same, without opening anything.
    let refused = core
        .check_provider_binding("user/alice", &binding)
        .unwrap_err();
    assert!(code(refused).contains("provider_not_connected"));
}

#[test]
fn a_symlinked_vault_key_file_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().expect("root");
    let real = root.path().join("real.key");
    std::fs::write(&real, [5_u8; 32]).expect("write");
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    let link = root.path().join("vault.key");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    assert!(code(VaultKey::from_file(&link).unwrap_err()).contains("vault_key_unavailable"));
    let raw = VaultKey::from_file(&real).expect("a raw 32-byte key loads");
    assert_eq!(raw.id(), key(5).id());
}

#[test]
fn vault_errors_classify_into_typed_codes_with_repair_hints() {
    let core = core_with_vault();
    let error = core
        .resolve_provider_binding("user/alice", AgentProvider::Claude, None)
        .unwrap_err();
    let code = ConnectionErrorCode::from_error(&error).expect("vault code");
    assert_eq!(code, ConnectionErrorCode::ProviderNotConnected);
    assert_eq!(code.http_status(), 404);
    let hint = code.repair_hint();
    assert_eq!(hint.reason, "provider_not_connected");
    assert!(hint.docs_url.starts_with("contracts/connection-v1/"));
    for code in ConnectionErrorCode::ALL {
        assert_eq!(
            code.repair_hint().reason,
            code.to_string(),
            "reason names the code"
        );
        assert!(!code.repair_hint().common_fixes.is_empty());
    }
    assert_eq!(
        ConnectionErrorCode::from_error(&ForgeError::Validation("something else".into())),
        None
    );
}

// connection-v1 §3: a rotation whose outcome is in doubt fences the
// connection as auth_required, and access is only ever handed over after the
// rotated secret is durable.

fn binding_of(core: &ForgeCore) -> ConnectionBinding {
    core.resolve_provider_binding("user/alice", AgentProvider::Claude, None)
        .expect("binding")
}

fn state_of(core: &ForgeCore) -> ConnectionState {
    core.list_provider_connections("user/alice")[0].state
}

#[test]
fn a_revoked_or_unknown_answer_fences_the_connection_until_it_is_connected_again() {
    for outcome in ["revoked", "unknown"] {
        let core = core_with_vault();
        connect(&core, "user/alice", "alice.example.com");
        let binding = binding_of(&core);
        let fenced = core
            .refresh_provider_secret("user/alice", &binding, REFRESH_LOCK_TIMEOUT, |_| {
                if outcome == "revoked" {
                    TokenExchange::<()>::Revoked("invalid_grant".into())
                } else {
                    TokenExchange::<()>::Unknown("timed out after the request was sent".into())
                }
            })
            .unwrap_err();
        assert!(code(fenced).contains("provider_auth_required"), "{outcome}");
        assert_eq!(state_of(&core), ConnectionState::AuthRequired, "{outcome}");
        let unseal = core
            .unseal_provider_secret("user/alice", &binding)
            .unwrap_err();
        assert!(code(unseal).contains("provider_auth_required"), "{outcome}");
        let lease = core
            .resolve_provider_binding("user/alice", AgentProvider::Claude, None)
            .unwrap_err();
        assert_eq!(
            ConnectionErrorCode::from_error(&lease),
            Some(ConnectionErrorCode::ProviderAuthRequired)
        );
        assert!(code(lease).contains("provider_auth_required"), "{outcome}");
        // Connecting again is the way back: a new generation, a fresh secret.
        let again = connect(&core, "user/alice", "alice.example.com");
        assert_eq!(again.state, ConnectionState::Connected);
        assert_eq!(
            again.connection_generation,
            binding.connection_generation + 1
        );
        assert_eq!(again.secret_version, 0);
    }
}

#[test]
fn a_rotation_left_in_flight_is_auth_required_after_a_restart() {
    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("forge.sqlite");
    let core = ForgeCore::open_sqlite(&path)
        .expect("open")
        .with_vault_key(key(7));
    core.create_account("alice", "vault-test-password", UserRole::User)
        .expect("alice");
    connect(&core, "user/alice", "alice.example.com");
    let binding = binding_of(&core);
    let mut after_restart = None;
    core.refresh_provider_secret("user/alice", &binding, REFRESH_LOCK_TIMEOUT, |_| {
        // A simulated restart, not a real crash: after the provider was called,
        // a copy of the store as it is on disk stands for what a restarted
        // server would find. (This process still has the store open, and one
        // store writes a database.) Real crash and restart acceptance is not
        // claimed here.
        let on_disk = root.path().join("simulated-restart.sqlite");
        std::fs::copy(&path, &on_disk).expect("copy the store as it is on disk");
        let restarted = ForgeCore::open_sqlite(&on_disk)
            .expect("reopen")
            .with_vault_key(key(7));
        after_restart = Some((
            restarted.list_provider_connections("user/alice")[0].state,
            restarted
                .resolve_provider_binding("user/alice", AgentProvider::Claude, None)
                .map(|_| ())
                .map_err(code),
        ));
        rotated_to(b"rotated", ())
    })
    .expect("this process still commits");
    let (state, lease) = after_restart.expect("the provider was called");
    assert_eq!(state, ConnectionState::AuthRequired);
    assert!(lease.unwrap_err().contains("provider_auth_required"));
}

#[test]
fn a_rotated_secret_that_cannot_be_saved_fences_the_connection_and_mints_nothing() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("forge.sqlite");
    let core = ForgeCore::open_sqlite(&path)
        .expect("open")
        .with_vault_key(key(7));
    core.create_account("alice", "vault-test-password", UserRole::User)
        .expect("alice");
    connect(&core, "user/alice", "alice.example.com");
    let binding = binding_of(&core);
    let failed = core
        .refresh_provider_secret("user/alice", &binding, REFRESH_LOCK_TIMEOUT, |_| {
            // Storage stops taking writes after the rotation was recorded.
            // The store keeps its connection open: a directory it cannot
            // create its rollback journal in stops its writes.
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o500))
                .expect("read-only");
            rotated_to(b"rotated", "access-never-handed-over")
        })
        .unwrap_err();
    assert!(code(failed).contains("refresh_persist_failed"));
    assert_eq!(
        state_of(&core),
        ConnectionState::AuthRequired,
        "fenced in memory"
    );
    assert!(
        core.unseal_provider_secret("user/alice", &binding).is_err(),
        "neither the old secret nor the rotated one is used"
    );
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("writable");
    drop(core);
    let restarted = ForgeCore::open_sqlite(&path)
        .expect("reopen")
        .with_vault_key(key(7));
    assert_eq!(
        restarted.list_provider_connections("user/alice")[0].state,
        ConnectionState::AuthRequired,
        "the rotation marker fences it after a restart"
    );
}

#[test]
fn a_rotation_that_cannot_be_recorded_never_reaches_the_provider() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("forge.sqlite");
    let core = ForgeCore::open_sqlite(&path)
        .expect("open")
        .with_vault_key(key(7));
    core.create_account("alice", "vault-test-password", UserRole::User)
        .expect("alice");
    connect(&core, "user/alice", "alice.example.com");
    let binding = binding_of(&core);
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o500))
        .expect("read-only");
    let failed = core
        .refresh_provider_secret(
            "user/alice",
            &binding,
            REFRESH_LOCK_TIMEOUT,
            |_| -> TokenExchange<()> {
                panic!("an unrecorded rotation must not call the provider")
            },
        )
        .unwrap_err();
    assert!(code(failed).contains("refresh_persist_failed"));
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("writable");
    assert_eq!(state_of(&core), ConnectionState::Connected);
    let secret = core
        .unseal_provider_secret("user/alice", &binding)
        .expect("the stored secret stays current");
    assert_eq!(secret.expose(), CANARY);
}

#[test]
fn a_disconnect_during_the_exchange_discards_the_rotated_secret() {
    let core = Arc::new(core_with_vault());
    let id = connect(&core, "user/alice", "alice.example.com").id;
    let binding = binding_of(&core);
    let racer = core.clone();
    let refused = core
        .refresh_provider_secret("user/alice", &binding, REFRESH_LOCK_TIMEOUT, |_| {
            racer
                .disconnect_provider("user/alice", &id)
                .expect("disconnect wins the race");
            rotated_to(b"rotated", "access")
        })
        .unwrap_err();
    assert!(code(refused).contains("provider_not_connected"));
    let row = &core.list_provider_connections("user/alice")[0];
    assert_eq!(row.state, ConnectionState::Disconnected);
    assert_eq!(row.secret_version, 0, "the rotated secret was not stored");
    assert!(core.state.read().provider_connections[&id].sealed.is_none());
}

#[test]
fn a_service_owner_needs_a_registered_namespace_and_loses_its_connections_on_revocation() {
    let core = core_with_vault();
    let connect = || {
        core.connect_provider(
            "service/agent",
            AgentProvider::Codex,
            "ci-account",
            CredentialKind::OauthRefresh,
            &ProviderSecret::new(CANARY.to_vec()),
        )
    };
    let refused = connect().unwrap_err();
    assert!(code(refused).contains("not a registered service namespace"));
    core.register_service_namespace("agent").expect("register");
    assert_eq!(core.service_namespaces(), ["agent"]);
    connect().expect("a registered service account connects");
    let binding = core
        .resolve_provider_binding("service/agent", AgentProvider::Codex, None)
        .expect("binding");
    assert_eq!(
        core.unseal_provider_secret("service/agent", &binding)
            .expect("unseal")
            .expose(),
        CANARY
    );

    // A revocation reaches every handle on the same forge at once.
    assert!(core.clone().revoke_service_namespace("agent"));
    for refused in [
        core.resolve_provider_binding("service/agent", AgentProvider::Codex, None)
            .map(|_| ()),
        core.unseal_provider_secret("service/agent", &binding)
            .map(|_| ()),
        core.check_provider_binding("service/agent", &binding)
            .map(|_| ()),
        core.refresh_provider_secret(
            "service/agent",
            &binding,
            REFRESH_LOCK_TIMEOUT,
            |_| -> TokenExchange<()> { panic!("a revoked service account is never refreshed") },
        )
        .map(|_| ()),
    ] {
        assert!(
            code(refused.unwrap_err()).contains("connection_owner_invalid"),
            "revoked"
        );
    }
    assert_eq!(
        core.list_provider_connections("service/agent").len(),
        1,
        "its connections stay stored"
    );
    core.register_service_namespace("agent")
        .expect("register again");
    core.unseal_provider_secret("service/agent", &binding)
        .expect("usable again");
}
