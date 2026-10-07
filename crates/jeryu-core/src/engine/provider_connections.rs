//! Connect-once provider connections (contracts connection-v1 §1, §3, §4).
//!
//! A user or service account connects a provider once. Sessions bind the
//! connection id and generation; only the control-plane gateway unseals the
//! secret, and only for the live generation. Errors start with the stable
//! connection-v1 code so edges can surface it verbatim.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use parking_lot::Mutex;

use super::vault::{SealBinding, SealedSecret, VaultKey};
use super::{ForgeCore, State};
use crate::errors::{ForgeError, Result};
use crate::model::*;

/// How long a refresh waits for another refresh of the same connection.
pub const REFRESH_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// Durable row: the public connection plus its sealed secret, if connected.
#[derive(Debug, Clone)]
pub(super) struct ConnectionRecord {
    pub(super) connection: ProviderConnection,
    pub(super) sealed: Option<SealedSecret>,
}

/// Per-connection refresh locks, shared by clones of one `ForgeCore`.
#[derive(Debug, Clone, Default)]
pub(super) struct RefreshLocks(Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>);

impl RefreshLocks {
    fn for_connection(&self, id: &str) -> Arc<Mutex<()>> {
        self.0.lock().entry(id.to_string()).or_default().clone()
    }
}

impl ForgeCore {
    /// Enable the vault. Without a key every connect and unseal is refused.
    #[must_use]
    pub fn with_vault_key(mut self, key: VaultKey) -> Self {
        self.vault = Some(Arc::new(key));
        self
    }

    /// Connect (or reconnect) `provider` for `owner_id` with a refresh token or
    /// API key. Reconnecting the same account replaces the secret and bumps the
    /// generation, which fences sessions bound to the old credential.
    pub fn connect_provider(
        &self,
        owner_id: &str,
        provider: AgentProvider,
        provider_account: &str,
        credential_kind: CredentialKind,
        secret: &ProviderSecret,
    ) -> Result<ProviderConnection> {
        let vault = self.vault()?;
        self.require_owner(owner_id)?;
        let account = provider_account.trim();
        if account.is_empty() || account.len() > 256 || account.chars().any(char::is_control) {
            return Err(ForgeError::Validation(
                "provider_account_invalid: name the provider account in 1 to 256 printable characters".into(),
            ));
        }
        if secret.expose().is_empty() || secret.expose().len() > 16 * 1024 {
            return Err(ForgeError::Validation(
                "provider_secret_invalid: the credential must be 1 byte to 16 KiB".into(),
            ));
        }
        let now = Utc::now();
        let mut state = self.state.write();
        let previous = state.clone();
        let existing = state.provider_connections.values().find(|record| {
            record.connection.owner_id == owner_id
                && record.connection.provider == provider
                && record.connection.provider_account == account
        });
        let connection = match existing {
            Some(record) => ProviderConnection {
                credential_kind,
                state: ConnectionState::Connected,
                connection_generation: record.connection.connection_generation + 1,
                secret_version: 0,
                updated_at: now,
                refreshed_at: None,
                ..record.connection.clone()
            },
            None => ProviderConnection {
                id: format!("pc_{}", uuid::Uuid::new_v4().simple()),
                owner_id: owner_id.to_string(),
                provider,
                provider_account: account.to_string(),
                credential_kind,
                state: ConnectionState::Connected,
                connection_generation: 1,
                secret_version: 0,
                created_at: now,
                updated_at: now,
                refreshed_at: None,
            },
        };
        let sealed = vault.seal(&seal_binding(&connection), secret.expose())?;
        state.provider_connections.insert(
            connection.id.clone(),
            ConnectionRecord {
                connection: connection.clone(),
                sealed: Some(sealed),
            },
        );
        self.persist_after_mutation(&mut state, previous)?;
        Ok(connection)
    }

    /// Every connection `owner_id` holds, oldest first. Never includes secrets.
    #[must_use]
    pub fn list_provider_connections(&self, owner_id: &str) -> Vec<ProviderConnection> {
        let state = self.state.read();
        let mut connections: Vec<_> = state
            .provider_connections
            .values()
            .filter(|record| record.connection.owner_id == owner_id)
            .map(|record| record.connection.clone())
            .collect();
        connections.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
        connections
    }

    /// Disconnect: drop the secret and bump the generation in one commit, so
    /// every session and gateway call bound to it is refused from now on.
    pub fn disconnect_provider(
        &self,
        owner_id: &str,
        connection_id: &str,
    ) -> Result<ProviderConnection> {
        let mut state = self.state.write();
        let previous = state.clone();
        let record = owned_record(&mut state, owner_id, connection_id)?;
        if record.connection.state == ConnectionState::Disconnected {
            return Ok(record.connection.clone());
        }
        record.connection.state = ConnectionState::Disconnected;
        record.connection.connection_generation += 1;
        record.connection.updated_at = Utc::now();
        record.sealed = None;
        let connection = record.connection.clone();
        self.persist_after_mutation(&mut state, previous)?;
        Ok(connection)
    }

    /// The binding a new session lease carries. `connection_id` picks one
    /// connection; without it the owner must hold exactly one connected
    /// connection for `provider`. There is no fallback to another owner,
    /// provider, or credential kind.
    pub fn resolve_provider_binding(
        &self,
        owner_id: &str,
        provider: AgentProvider,
        connection_id: Option<&str>,
    ) -> Result<ConnectionBinding> {
        let state = self.state.read();
        let connection = match connection_id {
            Some(id) => {
                let record = state
                    .provider_connections
                    .get(id)
                    .ok_or_else(|| not_connected(provider))?;
                if record.connection.owner_id != owner_id || record.connection.provider != provider
                {
                    return Err(owner_mismatch());
                }
                &record.connection
            }
            None => {
                let mut connected = state.provider_connections.values().filter(|record| {
                    record.connection.owner_id == owner_id
                        && record.connection.provider == provider
                        && record.connection.state == ConnectionState::Connected
                });
                let first = connected.next().ok_or_else(|| not_connected(provider))?;
                if connected.next().is_some() {
                    return Err(ForgeError::Conflict(
                        "provider_connection_ambiguous: name the connection_id to use".into(),
                    ));
                }
                &first.connection
            }
        };
        if connection.state != ConnectionState::Connected {
            return Err(not_connected(provider));
        }
        Ok(ConnectionBinding {
            provider,
            connection_id: connection.id.clone(),
            connection_generation: connection.connection_generation,
        })
    }

    /// Gateway only: open the secret for a live binding. Re-checks the owner,
    /// state, and generation on every call (connection-v1 §4 precedence).
    pub fn unseal_provider_secret(
        &self,
        owner_id: &str,
        binding: &ConnectionBinding,
    ) -> Result<ProviderSecret> {
        let vault = self.vault()?;
        let state = self.state.read();
        let record = live_record(&state, owner_id, binding)?;
        let sealed = record
            .sealed
            .as_ref()
            .ok_or_else(|| not_connected(binding.provider))?;
        let opened = vault.open(&seal_binding(&record.connection), sealed)?;
        Ok(ProviderSecret::new(opened.to_vec()))
    }

    /// Rotate a refresh secret. One refresh runs per connection at a time; a
    /// waiter gives up after `timeout` with `connection_busy`. `exchange` calls
    /// the provider token endpoint with the current secret and returns the
    /// rotated one; it runs outside the state lock. The rotation is durable
    /// before this returns, and only then may the caller mint access material.
    pub fn refresh_provider_secret(
        &self,
        owner_id: &str,
        binding: &ConnectionBinding,
        timeout: Duration,
        exchange: impl FnOnce(&ProviderSecret) -> Result<ProviderSecret>,
    ) -> Result<ProviderConnection> {
        let vault = self.vault()?;
        let lock = self.refresh_locks.for_connection(&binding.connection_id);
        let Some(_guard) = lock.try_lock_for(timeout) else {
            return Err(ForgeError::Conflict(
                "connection_busy: another refresh of this connection is running".into(),
            ));
        };
        let current = self.unseal_provider_secret(owner_id, binding)?;
        let rotated = exchange(&current)?;
        let mut state = self.state.write();
        let previous = state.clone();
        // Re-check under the write lock: a disconnect may have won meanwhile.
        live_record(&state, owner_id, binding)?;
        let record = state
            .provider_connections
            .get_mut(&binding.connection_id)
            .ok_or_else(|| not_connected(binding.provider))?;
        record.connection.secret_version += 1;
        record.sealed = Some(vault.seal(&seal_binding(&record.connection), rotated.expose())?);
        record.connection.refreshed_at = Some(Utc::now());
        record.connection.updated_at = Utc::now();
        let connection = record.connection.clone();
        self.persist_after_mutation(&mut state, previous).map_err(|_| {
            ForgeError::Storage(
                "refresh_persist_failed: the rotated secret was not saved; the previous one stays valid".into(),
            )
        })?;
        Ok(connection)
    }

    fn vault(&self) -> Result<&VaultKey> {
        self.vault.as_deref().ok_or_else(|| {
            ForgeError::Validation(
                "vault_unavailable: this server has no vault key configured".into(),
            )
        })
    }

    /// `user/<login>` must name an active account; `service/<name>` must be a
    /// plain identifier. Callers authorize who may act for a service account.
    fn require_owner(&self, owner_id: &str) -> Result<()> {
        let invalid = || {
            ForgeError::Validation(
                "connection_owner_invalid: owner must be user/<login> or service/<name>".into(),
            )
        };
        if let Some(login) = owner_id.strip_prefix("user/") {
            self.require_active_account(login).map_err(|_| invalid())?;
            return Ok(());
        }
        let name = owner_id.strip_prefix("service/").ok_or_else(invalid)?;
        let valid = !name.is_empty()
            && name.len() <= 120
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        valid.then_some(()).ok_or_else(invalid)
    }
}

fn owned_record<'a>(
    state: &'a mut State,
    owner_id: &str,
    connection_id: &str,
) -> Result<&'a mut ConnectionRecord> {
    let record = state
        .provider_connections
        .get_mut(connection_id)
        .ok_or_else(|| ForgeError::NotFound(format!("provider connection {connection_id}")))?;
    if record.connection.owner_id != owner_id {
        return Err(owner_mismatch());
    }
    Ok(record)
}

/// The record behind a binding, if it is still the live, connected generation.
fn live_record<'a>(
    state: &'a State,
    owner_id: &str,
    binding: &ConnectionBinding,
) -> Result<&'a ConnectionRecord> {
    let record = state
        .provider_connections
        .get(&binding.connection_id)
        .ok_or_else(|| not_connected(binding.provider))?;
    let connection = &record.connection;
    if connection.owner_id != owner_id || connection.provider != binding.provider {
        return Err(owner_mismatch());
    }
    if connection.state != ConnectionState::Connected {
        return Err(not_connected(binding.provider));
    }
    if connection.connection_generation != binding.connection_generation {
        return Err(ForgeError::Conflict(
            "connection_generation_stale: the session is bound to an older connection generation"
                .into(),
        ));
    }
    Ok(record)
}

pub(super) fn seal_binding(connection: &ProviderConnection) -> SealBinding<'_> {
    SealBinding {
        connection_id: &connection.id,
        owner_id: &connection.owner_id,
        provider: connection.provider.as_str(),
        generation: connection.connection_generation,
        secret_version: connection.secret_version,
    }
}

fn not_connected(provider: AgentProvider) -> ForgeError {
    ForgeError::NotFound(format!(
        "provider_not_connected: connect {} once in Settings, then retry",
        provider.as_str()
    ))
}

fn owner_mismatch() -> ForgeError {
    ForgeError::Forbidden(
        "connection_owner_mismatch: the connection belongs to another owner".into(),
    )
}
