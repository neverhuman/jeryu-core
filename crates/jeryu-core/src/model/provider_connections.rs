//! Connect-once provider connections (contracts connection-v1). A connection is
//! made once in the product and bound to managed sessions by id and
//! generation. Secrets never appear on these types except the redacted
//! [`ProviderSecret`] handed to the control-plane gateway.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// A managed agent provider. Any other name is `provider_unknown`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum AgentProvider {
    Claude,
    Codex,
    Grok,
}

impl AgentProvider {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Grok => "grok",
        }
    }

    /// Parse a wire name; anything else is `provider_unknown`.
    pub fn parse(value: &str) -> crate::Result<Self> {
        match value {
            "claude" => Ok(Self::Claude),
            "codex" => Ok(Self::Codex),
            "grok" => Ok(Self::Grok),
            _ => Err(crate::ForgeError::Validation(format!(
                "provider_unknown: {value} is not a managed provider"
            ))),
        }
    }
}

/// What the vault holds for a connection. Both kinds reach the provider only
/// through the gateway; an API key is never a reason to put it in a guest.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    OauthRefresh,
    ApiKey,
}

impl CredentialKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OauthRefresh => "oauth_refresh",
            Self::ApiKey => "api_key",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Pending,
    Connected,
    /// A refresh's outcome is unknown, or the provider revoked the stored
    /// secret (connection-v1 §3): the owner must connect the provider again.
    /// Nothing is minted and no lease binds it.
    AuthRequired,
    Disconnected,
}

impl ConnectionState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Connected => "connected",
            Self::AuthRequired => "auth_required",
            Self::Disconnected => "disconnected",
        }
    }
}

/// How a provider token exchange ended (connection-v1 §3 step 6). The
/// gateway classifies the provider's answer; the vault acts on it.
#[derive(Debug)]
pub enum TokenExchange<A> {
    /// The provider rotated the stored secret. `access` is what it minted
    /// with it, handed back only once the rotated secret is durable.
    Rotated { secret: ProviderSecret, access: A },
    /// The provider answered without consuming the stored secret (rate
    /// limited, briefly unavailable): it stays current.
    Unchanged(String),
    /// The provider answered that the stored secret is no longer valid
    /// (an OAuth `invalid_grant`, for example).
    Revoked(String),
    /// No definite answer, such as a timeout or a connection dropped after
    /// the request was sent: the provider may have rotated the secret.
    Unknown(String),
}

/// A connection as every caller sees it: no secret, no sealed bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderConnection {
    pub id: String,
    /// `user/<login>` or `service/<name>`; the prefix is the owner kind.
    pub owner_id: String,
    pub provider: AgentProvider,
    /// Public account identifier following connection-v1; email addresses are not identifiers.
    pub provider_account: String,
    pub credential_kind: CredentialKind,
    pub state: ConnectionState,
    /// Bumped on connect, reconnect, and disconnect. A session bound to an
    /// older generation is fenced.
    pub connection_generation: u64,
    /// Refresh rotations within the current generation.
    pub secret_version: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub refreshed_at: Option<DateTime<Utc>>,
}

/// What a signed session lease carries (K1): identity, never a credential.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionBinding {
    pub provider: AgentProvider,
    pub connection_id: String,
    pub connection_generation: u64,
}

/// Secret bytes (a refresh token or an API key). Zeroed on drop and never
/// printed by `Debug`.
pub struct ProviderSecret(Zeroizing<Vec<u8>>);

impl ProviderSecret {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for ProviderSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProviderSecret(<redacted>)")
    }
}

/// Every error code the vault returns, as a typed value with its repair
/// guidance. Vault errors are `ForgeError`s whose text starts with one of
/// these codes; `from_error` recovers the code so an edge can map it to a
/// status and show the hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionErrorCode {
    #[error("provider_unknown")]
    ProviderUnknown,
    #[error("connection_owner_invalid")]
    ConnectionOwnerInvalid,
    #[error("connection_owner_mismatch")]
    ConnectionOwnerMismatch,
    #[error("provider_not_connected")]
    ProviderNotConnected,
    #[error("connection_generation_stale")]
    ConnectionGenerationStale,
    #[error("provider_connection_ambiguous")]
    ProviderConnectionAmbiguous,
    #[error("provider_account_invalid")]
    ProviderAccountInvalid,
    #[error("provider_secret_invalid")]
    ProviderSecretInvalid,
    #[error("credential_not_refreshable")]
    CredentialNotRefreshable,
    #[error("connection_busy")]
    ConnectionBusy,
    #[error("refresh_persist_failed")]
    RefreshPersistFailed,
    #[error("provider_auth_required")]
    ProviderAuthRequired,
    #[error("provider_refresh_failed")]
    ProviderRefreshFailed,
    #[error("vault_unavailable")]
    VaultUnavailable,
    #[error("vault_secret_unreadable")]
    VaultSecretUnreadable,
}

const CONNECTION_DOCS: &str = "contracts/connection-v1/connection-v1.md";

impl ConnectionErrorCode {
    pub const ALL: [Self; 15] = [
        Self::ProviderUnknown,
        Self::ConnectionOwnerInvalid,
        Self::ConnectionOwnerMismatch,
        Self::ProviderNotConnected,
        Self::ConnectionGenerationStale,
        Self::ProviderConnectionAmbiguous,
        Self::ProviderAccountInvalid,
        Self::ProviderSecretInvalid,
        Self::CredentialNotRefreshable,
        Self::ConnectionBusy,
        Self::RefreshPersistFailed,
        Self::ProviderAuthRequired,
        Self::ProviderRefreshFailed,
        Self::VaultUnavailable,
        Self::VaultSecretUnreadable,
    ];

    /// The code a vault `ForgeError` carries, if it is a vault error.
    #[must_use]
    pub fn from_error(error: &crate::ForgeError) -> Option<Self> {
        let text = error.to_string();
        let code = text
            .split_once(": ")
            .map_or(text.as_str(), |(_, rest)| rest);
        let code = code.split(':').next().unwrap_or_default();
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.to_string() == code)
    }

    /// HTTP status an API edge should answer with.
    #[must_use]
    pub fn http_status(self) -> u16 {
        match self {
            Self::ConnectionOwnerMismatch => 403,
            Self::ProviderNotConnected => 404,
            Self::ConnectionGenerationStale
            | Self::ProviderConnectionAmbiguous
            | Self::ConnectionBusy
            | Self::ProviderAuthRequired => 409,
            Self::RefreshPersistFailed
            | Self::ProviderRefreshFailed
            | Self::VaultUnavailable
            | Self::VaultSecretUnreadable => 503,
            _ => 422,
        }
    }

    /// Structured repair guidance for the person or agent that hit the error.
    #[must_use]
    pub fn repair_hint(self) -> crate::AgentRepairHint {
        let (purpose, common_fixes, repair_hint): (
            &'static str,
            &'static [&'static str],
            &'static str,
        ) = match self {
            Self::ProviderUnknown => (
                "choose a managed agent provider",
                &["use claude, codex, or grok"],
                "retry with a supported provider name",
            ),
            Self::ConnectionOwnerInvalid => (
                "name the owner of a provider connection",
                &["use user/<login> for a person or service/<name> for automation"],
                "fix the owner id, then reconnect",
            ),
            Self::ConnectionOwnerMismatch => (
                "use a provider connection",
                &[
                    "use a connection that belongs to the session owner",
                    "ask an admin to bind a service account connection",
                ],
                "resolve the binding again for the right owner",
            ),
            Self::ProviderNotConnected => (
                "use a provider connection",
                &[
                    "connect the provider once in Settings, Agent providers",
                    "reconnect if it was disconnected",
                ],
                "connect the provider, then start a new session",
            ),
            Self::ConnectionGenerationStale => (
                "use a provider connection",
                &["the credential was replaced or disconnected; start a new session"],
                "sign a new lease at the current connection generation",
            ),
            Self::ProviderConnectionAmbiguous => (
                "pick a provider connection",
                &["pass the connection_id to use"],
                "retry with an explicit connection_id",
            ),
            Self::ProviderAccountInvalid => (
                "label a provider account",
                &["use letters, digits, and ._:/-, starting and ending with a letter or digit"],
                "fix the account label, then reconnect",
            ),
            Self::ProviderSecretInvalid => (
                "store a provider credential",
                &["send a credential between 1 byte and 16 KiB"],
                "reconnect with the full credential",
            ),
            Self::CredentialNotRefreshable => (
                "refresh a provider credential",
                &["API keys do not rotate; reconnect to replace one"],
                "reconnect with the new API key",
            ),
            Self::ConnectionBusy => (
                "refresh a provider credential",
                &["another refresh is running; wait and retry"],
                "retry the refresh after a few seconds",
            ),
            Self::RefreshPersistFailed => (
                "persist a rotated credential",
                &[
                    "check forge storage health",
                    "if the provider had already rotated the credential, the connection is auth_required: connect the provider again",
                ],
                "retry once storage is healthy, or reconnect if the connection is auth_required",
            ),
            Self::ProviderAuthRequired => (
                "use a provider connection",
                &[
                    "sign in to the provider again in Settings, Agent providers",
                    "a refresh's outcome was unknown or the provider revoked the credential",
                ],
                "connect the provider again, then start a new session",
            ),
            Self::ProviderRefreshFailed => (
                "refresh a provider credential",
                &[
                    "the provider did not rotate the credential this time; the stored one stays current",
                ],
                "retry the refresh later",
            ),
            Self::VaultUnavailable => (
                "open the credential vault",
                &["configure the vault key file for this server"],
                "restart with a private vault key file",
            ),
            Self::VaultSecretUnreadable => (
                "open a stored credential",
                &["the stored credential no longer matches its row or key; reconnect it"],
                "disconnect and reconnect the provider",
            ),
        };
        crate::AgentRepairHint {
            purpose,
            reason: self.reason(),
            common_fixes,
            docs_url: CONNECTION_DOCS,
            repair_hint,
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::ProviderUnknown => "provider_unknown",
            Self::ConnectionOwnerInvalid => "connection_owner_invalid",
            Self::ConnectionOwnerMismatch => "connection_owner_mismatch",
            Self::ProviderNotConnected => "provider_not_connected",
            Self::ConnectionGenerationStale => "connection_generation_stale",
            Self::ProviderConnectionAmbiguous => "provider_connection_ambiguous",
            Self::ProviderAccountInvalid => "provider_account_invalid",
            Self::ProviderSecretInvalid => "provider_secret_invalid",
            Self::CredentialNotRefreshable => "credential_not_refreshable",
            Self::ConnectionBusy => "connection_busy",
            Self::RefreshPersistFailed => "refresh_persist_failed",
            Self::ProviderAuthRequired => "provider_auth_required",
            Self::ProviderRefreshFailed => "provider_refresh_failed",
            Self::VaultUnavailable => "vault_unavailable",
            Self::VaultSecretUnreadable => "vault_secret_unreadable",
        }
    }
}
