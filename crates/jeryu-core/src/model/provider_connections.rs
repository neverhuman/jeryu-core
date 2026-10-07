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
#[serde(rename_all = "lowercase")]
pub enum ConnectionState {
    Pending,
    Connected,
    Disconnected,
}

impl ConnectionState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Connected => "connected",
            Self::Disconnected => "disconnected",
        }
    }
}

/// A connection as every caller sees it: no secret, no sealed bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderConnection {
    pub id: String,
    /// `user/<login>` or `service/<name>`; the prefix is the owner kind.
    pub owner_id: String,
    pub provider: AgentProvider,
    /// Public account label such as an email or organization name.
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
