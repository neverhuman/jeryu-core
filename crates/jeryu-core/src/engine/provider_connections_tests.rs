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
    let refreshed = core
        .refresh_provider_secret("user/alice", &binding, REFRESH_LOCK_TIMEOUT, |current| {
            assert_eq!(current.expose(), CANARY);
            Ok(ProviderSecret::new(b"rotated-refresh-token".to_vec()))
        })
        .expect("refresh");
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
                Ok(ProviderSecret::new(b"third".to_vec()))
            })
        })
    };
    entered.wait();
    let busy = core
        .refresh_provider_secret("user/alice", &binding, Duration::from_millis(50), |_| {
            panic!("a busy refresh must not call the provider")
        })
        .unwrap_err();
    assert!(code(busy).contains("connection_busy"));
    release.wait();
    assert_eq!(
        holder
            .join()
            .expect("join")
            .expect("refresh")
            .secret_version,
        2
    );
}

#[test]
fn a_failed_exchange_keeps_the_previous_secret() {
    let core = core_with_vault();
    connect(&core, "user/alice", "alice.example.com");
    let binding = core
        .resolve_provider_binding("user/alice", AgentProvider::Claude, None)
        .expect("binding");
    let failed = core.refresh_provider_secret("user/alice", &binding, REFRESH_LOCK_TIMEOUT, |_| {
        Err(ForgeError::Validation("upstream refused".into()))
    });
    assert!(failed.is_err());
    let secret = core
        .unseal_provider_secret("user/alice", &binding)
        .expect("unseal");
    assert_eq!(secret.expose(), CANARY);
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
        Ok(ProviderSecret::new(b"rotated".to_vec()))
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
        .refresh_provider_secret("user/alice", &binding, REFRESH_LOCK_TIMEOUT, |_| {
            panic!("an API key is never sent to a token endpoint")
        })
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
    for owner in ["service/pr-redteam", "service/ci.repair:1"] {
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
        .refresh_provider_secret("user/bob", &binding, REFRESH_LOCK_TIMEOUT, |_| {
            panic!("a stranger must not reach the provider")
        })
        .unwrap_err();
    assert!(code(stranger).contains("connection_owner_mismatch"));
    core.refresh_provider_secret("user/alice", &binding, REFRESH_LOCK_TIMEOUT, |_| {
        Ok(ProviderSecret::new(b"rotated".to_vec()))
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
    core.disable_account("alice").expect("disable");
    let refused = core
        .unseal_provider_secret("user/alice", &binding)
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
