//! Connect-once provider connections (contracts connection-v1 §1, §3, §4).
//!
//! A user or service account connects a provider once. Sessions bind the
//! connection id and generation; only the control-plane gateway unseals the
//! secret, and only for the live generation. Errors start with the stable
//! connection-v1 code so edges can surface it verbatim.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;

use super::vault::{SealBinding, SealedSecret, VaultKey};
use super::{ForgeCore, State};
use crate::errors::{ForgeError, Result};
use crate::model::*;

/// How long a refresh waits for another refresh of the same connection.
pub const REFRESH_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SECRET_BYTES: usize = 16 * 1024;

/// Durable row: the public connection plus its sealed secret, if connected.
#[derive(Debug, Clone)]
pub(super) struct ConnectionRecord {
    pub(super) connection: ProviderConnection,
    pub(super) sealed: Option<SealedSecret>,
    /// A rotation in flight (connection-v1 §3 step 5).
    pub(super) rotation: Option<Rotation>,
}

/// A rotation in flight: durable before the provider sees the stored secret,
/// cleared by the commit that ends it. One that outlives its refresh (the
/// process died, or the commit failed) means the provider may have consumed
/// the stored secret, so the connection becomes `auth_required`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Rotation {
    /// The `secret_version` being rotated away from.
    pub(super) secret_version: u64,
    pub(super) started_at: DateTime<Utc>,
}

/// Per-connection refresh locks, shared by clones of one `ForgeCore`.
#[derive(Debug, Clone, Default)]
pub(super) struct RefreshLocks(Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>);

impl RefreshLocks {
    fn for_connection(&self, id: &str) -> Arc<Mutex<()>> {
        self.0.lock().entry(id.to_string()).or_default().clone()
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.0.lock().is_empty()
    }

    /// Drop the entry once no other refresh holds or waits on it.
    fn release(&self, id: &str, lock: Arc<Mutex<()>>) {
        let mut locks = self.0.lock();
        drop(lock);
        if locks
            .get(id)
            .is_some_and(|entry| Arc::strong_count(entry) == 1)
        {
            locks.remove(id);
        }
    }
}

/// The one holder of plaintext provider secrets (connection-v1 §1: only the
/// gateway unseals). A vault issues it once, and whoever builds the gateway
/// takes it at startup. Every other holder of the [`ForgeCore`] connects,
/// lists, binds and disconnects, and never reads a secret.
#[derive(Clone)]
pub struct ProviderBroker {
    core: ForgeCore,
}

impl std::fmt::Debug for ProviderBroker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProviderBroker")
    }
}

impl ProviderBroker {
    /// Open the secret of a live binding. The owner, state and generation
    /// are checked again on every call (connection-v1 §4 precedence).
    pub fn unseal_provider_secret(
        &self,
        owner_id: &str,
        binding: &ConnectionBinding,
    ) -> Result<ProviderSecret> {
        self.core.unseal_provider_secret(owner_id, binding)
    }

    /// Rotate a refresh secret (connection-v1 §3). `exchange` calls the
    /// provider with the stored secret and says how that ended; the access
    /// material it minted comes back only once the rotated secret is
    /// durable, and any outcome that leaves the stored secret in doubt makes
    /// the connection `auth_required`. One refresh runs per connection; a
    /// waiter gives up after `timeout` with `connection_busy`.
    pub fn refresh_provider_secret<A>(
        &self,
        owner_id: &str,
        binding: &ConnectionBinding,
        timeout: Duration,
        exchange: impl FnOnce(&ProviderSecret) -> TokenExchange<A>,
    ) -> Result<(ProviderConnection, A)> {
        self.core
            .refresh_provider_secret(owner_id, binding, timeout, exchange)
    }
}

impl ForgeCore {
    /// Enable the vault. Without a key every connect and unseal is refused.
    #[must_use]
    pub fn with_vault_key(mut self, key: VaultKey) -> Self {
        self.vault = Some(Arc::new(key));
        self.broker_issued = Arc::default();
        self
    }

    /// Let `service/<name>` own provider connections (connection-v1 §1).
    /// None is registered unless the deployment names it, so a mistyped or
    /// unexpected service owner is refused rather than given a vault entry.
    pub fn register_service_namespace(&self, name: &str) -> Result<()> {
        if !valid_owner_id(&format!("service/{name}")) {
            return Err(ForgeError::Validation(format!(
                "connection_owner_invalid: service/{name} is not a valid service account name"
            )));
        }
        self.service_namespaces.write().insert(name.to_string());
        Ok(())
    }

    /// Withdraw `service/<name>`: its connections stay stored, and none of
    /// them binds a lease, unseals or refreshes until it is registered again.
    /// Returns whether it was registered.
    pub fn revoke_service_namespace(&self, name: &str) -> bool {
        self.service_namespaces.write().remove(name)
    }

    /// The registered service account names, sorted.
    #[must_use]
    pub fn service_namespaces(&self) -> Vec<String> {
        self.service_namespaces.read().iter().cloned().collect()
    }

    /// This vault's [`ProviderBroker`]. `None` without a vault, and for every
    /// call after the first: the broker is issued once.
    pub fn issue_provider_broker(&self) -> Option<ProviderBroker> {
        self.vault.as_ref()?;
        (!self
            .broker_issued
            .swap(true, std::sync::atomic::Ordering::SeqCst))
        .then(|| ProviderBroker { core: self.clone() })
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
        self.connect_provider_admitted(
            owner_id,
            provider,
            provider_account,
            credential_kind,
            secret,
            || true,
        )
    }

    /// [`Self::connect_provider`], admitted only if `admit` still holds once
    /// the vault's write lock is taken, before anything changes. A caller
    /// whose authority to connect runs out (a sign-in's lifetime) passes it
    /// here, so no wait for the lock can carry the secret past it. A refusal
    /// is `Conflict` (`provider_connect_refused`), with nothing changed.
    pub fn connect_provider_admitted(
        &self,
        owner_id: &str,
        provider: AgentProvider,
        provider_account: &str,
        credential_kind: CredentialKind,
        secret: &ProviderSecret,
        admit: impl FnOnce() -> bool,
    ) -> Result<ProviderConnection> {
        let vault = self.vault()?;
        self.require_owner(owner_id)?;
        // connection-v1 types provider_account as an `id` (1 to 128 bytes of
        // [A-Za-z0-9._:/-], alphanumeric at both ends).
        let account = provider_account.trim();
        if !valid_contract_id(account) {
            return Err(ForgeError::Validation(
                "provider_account_invalid: use 1 to 128 characters of letters, digits, and ._:/- starting and ending with a letter or digit".into(),
            ));
        }
        if secret.expose().is_empty() || secret.expose().len() > MAX_SECRET_BYTES {
            return Err(ForgeError::Validation(
                "provider_secret_invalid: the credential must be 1 byte to 16 KiB".into(),
            ));
        }
        let mut state = self.state.write();
        // Decided under the lock that every connect and refresh takes: what
        // held when the caller asked may not hold after waiting for it.
        if !admit() {
            return Err(ForgeError::Conflict(
                "provider_connect_refused: the caller's authority to connect ran out before the vault took it; nothing changed".into(),
            ));
        }
        let now = Utc::now();
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
                rotation: None,
            },
        );
        self.persist_after_mutation(&mut state, previous)?;
        Ok(connection)
    }

    /// Whether `binding` may be used now, from metadata alone (connection-v1
    /// §4 precedence 2 to 5): the connection is `owner_id`'s for this
    /// provider, its owner may still authenticate (a disabled or locked
    /// account's connections stop with it), a service owner's namespace is
    /// still registered, and it is connected at this generation. The same
    /// checks every unseal and refresh make; nothing is opened. A caller that
    /// keeps short-lived access minted from a secret must pass this before
    /// each use, since that access never goes back through the vault.
    pub fn check_provider_binding(
        &self,
        owner_id: &str,
        binding: &ConnectionBinding,
    ) -> Result<ProviderConnection> {
        let state = self.state.read();
        live_record(&state, &self.service_namespaces.read(), owner_id, binding)
            .map(|record| record.connection.clone())
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
        record.rotation = None;
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
        if let Some(name) = owner_id.strip_prefix("service/")
            && !self.service_namespaces.read().contains(name)
        {
            return Err(unregistered_service(name));
        }
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
                let mine = || {
                    state.provider_connections.values().filter(|record| {
                        record.connection.owner_id == owner_id
                            && record.connection.provider == provider
                    })
                };
                let mut connected =
                    mine().filter(|record| record.connection.state == ConnectionState::Connected);
                let first = connected.next().ok_or_else(|| {
                    if mine().any(|record| record.connection.state == ConnectionState::AuthRequired)
                    {
                        auth_required(provider)
                    } else {
                        not_connected(provider)
                    }
                })?;
                if connected.next().is_some() {
                    return Err(ForgeError::Conflict(
                        "provider_connection_ambiguous: name the connection_id to use".into(),
                    ));
                }
                &first.connection
            }
        };
        match connection.state {
            ConnectionState::Connected => {}
            ConnectionState::AuthRequired => return Err(auth_required(provider)),
            ConnectionState::Pending | ConnectionState::Disconnected => {
                return Err(not_connected(provider));
            }
        }
        Ok(ConnectionBinding {
            provider,
            connection_id: connection.id.clone(),
            connection_generation: connection.connection_generation,
        })
    }

    /// Open the secret for a live binding, through the [`ProviderBroker`]
    /// only. Re-checks the owner, state, and generation on every call
    /// (connection-v1 §4 precedence).
    pub(crate) fn unseal_provider_secret(
        &self,
        owner_id: &str,
        binding: &ConnectionBinding,
    ) -> Result<ProviderSecret> {
        let vault = self.vault()?;
        let state = self.state.read();
        let record = live_record(&state, &self.service_namespaces.read(), owner_id, binding)?;
        let sealed = record
            .sealed
            .as_ref()
            .ok_or_else(|| not_connected(binding.provider))?;
        let opened = vault.open(&seal_binding(&record.connection), sealed)?;
        Ok(ProviderSecret::new(opened.to_vec()))
    }

    /// Rotate a refresh secret (connection-v1 §3). One refresh runs per
    /// connection at a time; a waiter gives up after `timeout` with
    /// `connection_busy`. `exchange` calls the provider token endpoint with the
    /// stored secret, outside the state lock, and says how that ended. The
    /// rotation is recorded durably before `exchange` runs, the rotated secret
    /// is durable before this returns, and only then does the caller get the
    /// access material `exchange` minted.
    ///
    /// An outcome that leaves the stored secret in doubt fences the connection
    /// as `auth_required`: an unknown or revoked answer, a rotated secret that
    /// could not be stored, and a rotation an earlier refresh never finished.
    /// Through the [`ProviderBroker`] only.
    pub(crate) fn refresh_provider_secret<A>(
        &self,
        owner_id: &str,
        binding: &ConnectionBinding,
        timeout: Duration,
        exchange: impl FnOnce(&ProviderSecret) -> TokenExchange<A>,
    ) -> Result<(ProviderConnection, A)> {
        let vault = self.vault()?;
        // Authorize before waiting: a stranger or a dead connection gets its
        // own error (connection-v1 §4), not connection_busy, and never adds a
        // lock entry.
        {
            let state = self.state.read();
            let record = live_record(&state, &self.service_namespaces.read(), owner_id, binding)?;
            if record.connection.credential_kind == CredentialKind::ApiKey {
                return Err(ForgeError::Validation(
                    "credential_not_refreshable: an API key does not rotate; reconnect to replace it"
                        .into(),
                ));
            }
        }
        let lock = self.refresh_locks.for_connection(&binding.connection_id);
        let result = match lock.try_lock_for(timeout) {
            Some(guard) => {
                let result = self.refresh_locked(vault, owner_id, binding, exchange);
                drop(guard);
                result
            }
            None => Err(ForgeError::Conflict(
                "connection_busy: another refresh of this connection is running".into(),
            )),
        };
        self.refresh_locks.release(&binding.connection_id, lock);
        result
    }

    fn refresh_locked<A>(
        &self,
        vault: &VaultKey,
        owner_id: &str,
        binding: &ConnectionBinding,
        exchange: impl FnOnce(&ProviderSecret) -> TokenExchange<A>,
    ) -> Result<(ProviderConnection, A)> {
        // Steps 2-5, under the state lock: re-read the row, fence a rotation an
        // earlier refresh never finished, and record this one durably before
        // the provider sees the stored secret.
        let (current, version) = {
            let mut state = self.state.write();
            let previous = state.clone();
            live_record(&state, &self.service_namespaces.read(), owner_id, binding)?;
            let record = state
                .provider_connections
                .get_mut(&binding.connection_id)
                .ok_or_else(|| not_connected(binding.provider))?;
            if record.rotation.is_some() {
                fence_auth_required(record);
                self.persist_after_mutation(&mut state, previous)?;
                return Err(auth_required(binding.provider));
            }
            let sealed = record
                .sealed
                .clone()
                .ok_or_else(|| not_connected(binding.provider))?;
            let opened = vault.open(&seal_binding(&record.connection), &sealed)?;
            let version = record.connection.secret_version;
            record.rotation = Some(Rotation {
                secret_version: version,
                started_at: Utc::now(),
            });
            self.persist_after_mutation(&mut state, previous)
                .map_err(|_| {
                    ForgeError::Storage(
                        "refresh_persist_failed: the rotation could not be recorded; nothing reached the provider and the stored credential stays current".into(),
                    )
                })?;
            (ProviderSecret::new(opened.to_vec()), version)
        };

        // Step 6: the provider, holding only this connection's refresh lock.
        let outcome = exchange(&current);
        drop(current);

        // Steps 7 and 8: compare the row with what step 2 read, then commit.
        let mut state = self.state.write();
        let previous = state.clone();
        let ours = state
            .provider_connections
            .get(&binding.connection_id)
            .is_some_and(|record| {
                record.connection.state == ConnectionState::Connected
                    && record.connection.connection_generation == binding.connection_generation
                    && record.connection.secret_version == version
                    && record
                        .rotation
                        .as_ref()
                        .is_some_and(|rotation| rotation.secret_version == version)
            });
        if !ours {
            // A disconnect or a replacement won while the provider answered.
            // It fenced this rotation and dropped its marker; whatever the
            // provider minted is discarded, and the row's own state answers.
            return Err(
                match live_record(&state, &self.service_namespaces.read(), owner_id, binding) {
                    Err(error) => error,
                    Ok(_) => stale_generation(),
                },
            );
        }
        let record = state
            .provider_connections
            .get_mut(&binding.connection_id)
            .ok_or_else(|| not_connected(binding.provider))?;
        match outcome {
            TokenExchange::Unchanged(reason) => {
                record.rotation = None;
                // A marker left by a failed write fences the next refresh:
                // cautious, never unsafe.
                let _ = self.persist_after_mutation(&mut state, previous);
                Err(ForgeError::Conflict(format!(
                    "provider_refresh_failed: the provider did not rotate the credential ({}); the stored one stays current",
                    reason.trim()
                )))
            }
            TokenExchange::Revoked(reason) | TokenExchange::Unknown(reason) => {
                fence_auth_required(record);
                self.persist_fence(&state);
                Err(ForgeError::Conflict(format!(
                    "provider_auth_required: sign in to {} again; the stored credential may no longer be valid ({})",
                    binding.provider.as_str(),
                    reason.trim()
                )))
            }
            TokenExchange::Rotated { secret, access } => {
                let sealed = (!secret.expose().is_empty()
                    && secret.expose().len() <= MAX_SECRET_BYTES)
                    .then(|| {
                        let mut next = record.connection.clone();
                        next.secret_version += 1;
                        vault.seal(&seal_binding(&next), secret.expose()).ok()
                    })
                    .flatten();
                drop(secret);
                let Some(sealed) = sealed else {
                    // The provider consumed the stored secret and what it sent
                    // back cannot be kept: nothing usable is left.
                    fence_auth_required(record);
                    self.persist_fence(&state);
                    return Err(ForgeError::Conflict(format!(
                        "provider_auth_required: sign in to {} again; the rotated credential could not be stored",
                        binding.provider.as_str()
                    )));
                };
                let now = Utc::now();
                record.connection.secret_version = version + 1;
                record.sealed = Some(sealed);
                record.rotation = None;
                record.connection.refreshed_at = Some(now);
                record.connection.updated_at = now;
                let connection = record.connection.clone();
                if self.persist_after_mutation(&mut state, previous).is_err() {
                    // The provider consumed the stored secret and the rotated
                    // one is not durable. Fence now; the durable marker fences
                    // it after a restart as well. The access material is
                    // dropped unused.
                    if let Some(record) = state.provider_connections.get_mut(&binding.connection_id)
                    {
                        fence_auth_required(record);
                    }
                    self.persist_fence(&state);
                    return Err(ForgeError::Storage(
                        "refresh_persist_failed: the rotated credential could not be saved; the connection is auth_required until it is connected again".into(),
                    ));
                }
                Ok((connection, access))
            }
        }
    }

    /// Persist a fence as far as storage allows. Unlike a mutation, a fence is
    /// not rolled back when the write fails: in memory it holds at once, and a
    /// rotation marker already on disk makes it hold after a restart too.
    fn persist_fence(&self, state: &State) {
        if let Some(storage) = &self.storage {
            let _ = storage.persist(state);
        }
    }

    fn vault(&self) -> Result<&VaultKey> {
        self.vault.as_deref().ok_or_else(|| {
            ForgeError::Validation(
                "vault_unavailable: this server has no vault key configured".into(),
            )
        })
    }

    /// `user/<login>` must name an active account; `service/<name>` must be a
    /// registered service namespace. Callers authorize who may act for one.
    fn require_owner(&self, owner_id: &str) -> Result<()> {
        let invalid = || {
            ForgeError::Validation(
                "connection_owner_invalid: owner must be user/<login> or service/<name>".into(),
            )
        };
        if !valid_owner_id(owner_id) {
            return Err(invalid());
        }
        if let Some(login) = owner_id.strip_prefix("user/") {
            self.require_active_account(login).map_err(|_| invalid())?;
        }
        if let Some(name) = owner_id.strip_prefix("service/")
            && !self.service_namespaces.read().contains(name)
        {
            return Err(unregistered_service(name));
        }
        Ok(())
    }
}

/// connection-v1 identifiers: `user/` or `service/` then a name of
/// `[A-Za-z0-9._:-]` that starts and ends alphanumeric; 6 to 128 bytes in
/// all, with no `..` and no second `/`.
fn valid_owner_id(owner_id: &str) -> bool {
    let Some(name) = owner_id
        .strip_prefix("user/")
        .or_else(|| owner_id.strip_prefix("service/"))
    else {
        return false;
    };
    let bytes = name.as_bytes();
    (6..=128).contains(&owner_id.len())
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(b))
        && !name.contains("..")
}

/// The connection-v1 `id` rule.
fn valid_contract_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(b))
        && !value.contains("..")
        && !value.contains("//")
}

fn owned_record<'a>(
    state: &'a mut State,
    owner_id: &str,
    connection_id: &str,
) -> Result<&'a mut ConnectionRecord> {
    let record = state
        .provider_connections
        .get_mut(connection_id)
        .ok_or_else(|| {
            ForgeError::NotFound("provider_not_connected: no such provider connection".into())
        })?;
    if record.connection.owner_id != owner_id {
        return Err(owner_mismatch());
    }
    Ok(record)
}

/// The record behind a binding, if it is still the live, connected generation.
fn live_record<'a>(
    state: &'a State,
    services: &std::collections::BTreeSet<String>,
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
    if let Some(name) = owner_id.strip_prefix("service/")
        && !services.contains(name)
    {
        return Err(unregistered_service(name));
    }
    if !owner_active(state, owner_id)
        || matches!(
            connection.state,
            ConnectionState::Pending | ConnectionState::Disconnected
        )
    {
        return Err(not_connected(binding.provider));
    }
    if connection.state == ConnectionState::AuthRequired {
        return Err(auth_required(binding.provider));
    }
    if connection.connection_generation != binding.connection_generation {
        return Err(stale_generation());
    }
    Ok(record)
}

/// A user-owned connection works only while that account may authenticate.
fn owner_active(state: &State, owner_id: &str) -> bool {
    match owner_id.strip_prefix("user/") {
        Some(login) => state
            .accounts
            .get(login)
            .is_some_and(|account| account.status.permits_authentication()),
        None => true,
    }
}

pub(super) fn seal_binding(connection: &ProviderConnection) -> SealBinding<'_> {
    SealBinding {
        connection_id: &connection.id,
        owner_id: &connection.owner_id,
        provider: connection.provider.as_str(),
        generation: connection.connection_generation,
        secret_version: connection.secret_version,
        credential_kind: connection.credential_kind.as_str(),
    }
}

/// `auth_required`: the stored secret is in doubt, so it is dropped and the
/// owner has to connect the provider again. The generation stays; leases are
/// refused by state, and a reconnect bumps it.
fn fence_auth_required(record: &mut ConnectionRecord) {
    record.connection.state = ConnectionState::AuthRequired;
    record.connection.updated_at = Utc::now();
    record.sealed = None;
    record.rotation = None;
}

/// Every connection a rotation was in flight for when the store was last
/// written is `auth_required` once it is opened again: no refresh is running
/// in a process that has just started, so its outcome is unknown. Returns how
/// many were fenced.
pub(super) fn fence_unfinished_rotations(state: &mut State) -> usize {
    let mut fenced = 0;
    for record in state.provider_connections.values_mut() {
        if record.rotation.is_some() {
            fence_auth_required(record);
            fenced += 1;
        }
    }
    fenced
}

fn unregistered_service(name: &str) -> ForgeError {
    ForgeError::Validation(format!(
        "connection_owner_invalid: service/{name} is not a registered service namespace"
    ))
}

fn auth_required(provider: AgentProvider) -> ForgeError {
    ForgeError::Conflict(format!(
        "provider_auth_required: sign in to {} again in Settings; the stored credential may no longer be valid",
        provider.as_str()
    ))
}

fn stale_generation() -> ForgeError {
    ForgeError::Conflict(
        "connection_generation_stale: the session is bound to an older connection generation"
            .into(),
    )
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

#[cfg(test)]
mod broker_tests {
    use super::*;

    #[test]
    fn a_vault_issues_its_broker_once_and_only_with_a_key() {
        assert!(
            ForgeCore::new().issue_provider_broker().is_none(),
            "no vault"
        );
        let core = ForgeCore::new().with_vault_key(VaultKey::from_bytes(&[9; 32]).expect("key"));
        let clone = core.clone();
        assert!(core.issue_provider_broker().is_some(), "the first ask");
        assert!(core.issue_provider_broker().is_none(), "once");
        assert!(clone.issue_provider_broker().is_none(), "for every clone");
    }
}
