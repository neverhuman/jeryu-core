//! Drift guard between lane A's hand-authored connection-v1 schemas and the
//! vault's Rust types. The schemas are normative; when either side changes,
//! this test must change with it in the same commit.

use std::path::PathBuf;

use jeryu_core::{
    AgentProvider, ConnectionState, CredentialKind, ForgeCore, ProviderSecret, UserRole, VaultKey,
};
use serde_json::Value;

fn schema(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/connection-v1")
        .join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).expect("schema is JSON")
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("enum array")
        .iter()
        .map(|v| v.as_str().expect("string").to_string())
        .collect()
}

fn wire<T: serde::Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .expect("serialize")
        .as_str()
        .expect("string")
        .to_string()
}

#[test]
fn vault_enums_match_the_connection_v1_schema() {
    let defs = schema("connection-v1.schema.json")["$defs"].clone();
    let providers = [
        AgentProvider::Claude,
        AgentProvider::Codex,
        AgentProvider::Grok,
    ];
    assert_eq!(
        strings(&defs["provider"]["enum"]),
        providers.map(wire).to_vec()
    );
    let kinds = [CredentialKind::OauthRefresh, CredentialKind::ApiKey];
    assert_eq!(
        strings(&defs["credentialKind"]["enum"]),
        kinds.map(wire).to_vec()
    );
    let states = [
        ConnectionState::Pending,
        ConnectionState::Connected,
        ConnectionState::Disconnected,
    ];
    assert_eq!(
        strings(&defs["providerConnection"]["properties"]["state"]["enum"]),
        states.map(wire).to_vec()
    );
}

#[test]
fn every_vault_error_code_is_a_contract_code_and_relay_codes_agree() {
    let codes = strings(&schema("connection-v1.schema.json")["$defs"]["errorCode"]["enum"]);
    for code in [
        "provider_unknown",
        "connection_owner_mismatch",
        "provider_not_connected",
        "connection_generation_stale",
        "connection_busy",
        "refresh_persist_failed",
    ] {
        assert!(
            codes.contains(&code.to_string()),
            "{code} is not in connection-v1"
        );
    }
    let relay = schema("k3-relay-v1.schema.json");
    let frame = strings(&relay["$defs"]["errorFrame"]["properties"]["error"]["enum"]);
    for code in &frame {
        assert!(
            codes.contains(code),
            "k3 relay code {code} is not a connection-v1 code"
        );
    }
}

/// The vault accepts exactly the owner ids and account labels the schema's
/// patterns describe, checked on representative samples.
#[test]
fn vault_identifier_rules_follow_the_schema_samples() {
    let defs = schema("connection-v1.schema.json")["$defs"].clone();
    assert_eq!(
        defs["ownerId"]["pattern"].as_str(),
        Some("^(user|service)/[A-Za-z0-9]([A-Za-z0-9._:-]*[A-Za-z0-9])?$")
    );
    assert_eq!(defs["ownerId"]["maxLength"], 128);
    let core = ForgeCore::new().with_vault_key(VaultKey::from_bytes(&[4; 32]).expect("key"));
    core.create_account("alice", "contract-test-password", UserRole::User)
        .expect("alice");
    let connect = |owner: &str, account: &str| {
        core.connect_provider(
            owner,
            AgentProvider::Codex,
            account,
            CredentialKind::ApiKey,
            &ProviderSecret::new(b"k".to_vec()),
        )
    };
    for owner in ["user/alice", "service/pr-redteam", "service/a.b:c-d"] {
        assert!(
            connect(owner, "acct-1").is_ok(),
            "{owner} matches the pattern"
        );
    }
    for owner in [
        "alice",
        "user/",
        "service/-x",
        "service/x-",
        "service/a b",
        "team/x",
    ] {
        assert!(
            connect(owner, "acct-1").is_err(),
            "{owner} does not match the pattern"
        );
    }
    for account in ["org/team-1", "acct.example"] {
        assert!(connect("user/alice", account).is_ok(), "{account} is an id");
    }
    for account in ["-acct", "acct-", "a b", "a@b", ""] {
        assert!(
            connect("user/alice", account).is_err(),
            "{account} is not an id"
        );
    }
}
