//! Account-owned bots (agents). Secrets never appear on these types.

use std::borrow::Cow;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Free-form label naming what drives a bot, such as `grok`, `muse`, or
/// `agent`. It grants nothing: reach and the owner's grants decide access.
///
/// A kind matches `^[a-z][a-z0-9-]{0,31}$`. Deserializing an invalid kind
/// fails, so a stored or posted kind is always valid.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(try_from = "String", into = "String")]
pub struct BotKind(Cow<'static, str>);

impl BotKind {
    /// Kind used when an enrollment names none.
    pub const AGENT: Self = Self(Cow::Borrowed("agent"));
    pub const GROK: Self = Self(Cow::Borrowed("grok"));
    pub const MUSE: Self = Self(Cow::Borrowed("muse"));
    pub const MAX_LEN: usize = 32;
    /// Machine code of the validation error an invalid kind returns.
    pub const INVALID_CODE: &'static str = "invalid_bot_kind";

    /// Validate a kind: a lowercase ASCII letter, then up to 31 lowercase
    /// letters, digits, or hyphens. Surrounding whitespace is not trimmed.
    pub fn parse(value: &str) -> Result<Self, crate::errors::ForgeError> {
        if Self::is_valid(value) {
            Ok(Self(Cow::Owned(value.to_string())))
        } else {
            Err(crate::errors::ForgeError::Validation(format!(
                "{}: bot kind must match ^[a-z][a-z0-9-]{{0,31}}$",
                Self::INVALID_CODE
            )))
        }
    }

    #[must_use]
    pub fn is_valid(value: &str) -> bool {
        let mut bytes = value.bytes();
        bytes.next().is_some_and(|first| first.is_ascii_lowercase())
            && value.len() <= Self::MAX_LEN
            && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Display name: `Grokbot` and `Musebot` for the two vendor kinds, and
    /// the kind as given for any other.
    #[must_use]
    pub fn label(&self) -> &str {
        match self.as_str() {
            "grok" => "Grokbot",
            "muse" => "Musebot",
            other => other,
        }
    }
}

impl Default for BotKind {
    fn default() -> Self {
        Self::AGENT
    }
}

impl std::fmt::Display for BotKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<String> for BotKind {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if Self::is_valid(&value) {
            Ok(Self(Cow::Owned(value)))
        } else {
            Err(format!(
                "{}: bot kind must match ^[a-z][a-z0-9-]{{0,31}}$",
                Self::INVALID_CODE
            ))
        }
    }
}

impl From<BotKind> for String {
    fn from(kind: BotKind) -> Self {
        kind.0.into_owned()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BotStatus {
    Active,
    Suspended,
    Revoked,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BotTaskKind {
    Issue,
    Pull,
    Branch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BotEffect {
    Read,
    Write,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BotRepoRef {
    pub owner: String,
    pub name: String,
}

/// What a bot may touch. Every arm is narrower than, or equal to, the owner's grants.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum BotReach {
    General,
    /// Every repository under one of these owners (accounts or
    /// organizations) on which the bot's owner holds an explicit grant,
    /// including repositories created after enrollment. A public read without
    /// a grant is not enough. Wire shape: `{"mode":"owners","owners":["acme"]}`.
    Owners {
        owners: Vec<String>,
    },
    Repositories {
        repos: Vec<BotRepoRef>,
    },
    Task {
        repo: BotRepoRef,
        task_kind: BotTaskKind,
        task_id: String,
    },
}

impl BotReach {
    /// Most owners one `owners` reach may name.
    pub const MAX_OWNERS: usize = 20;
    /// Machine code of the validation error a rejected `owners` reach returns.
    pub const INVALID_OWNERS_CODE: &'static str = "invalid_reach_owners";
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BotSummary {
    pub id: Uuid,
    pub owner: String,
    pub slug: String,
    pub display_name: String,
    pub kind: BotKind,
    pub status: BotStatus,
    pub reach: BotReach,
    pub credential_generation: u64,
    pub last_successful_access: Option<DateTime<Utc>>,
    pub last_auth: Option<DateTime<Utc>>,
    pub last_mutation: Option<DateTime<Utc>>,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub last_action: Option<String>,
    pub last_outcome: Option<String>,
    pub last_repo: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// One-time enrollment receipt. The key is not stored and is not returned again.
#[derive(Clone, PartialEq, Eq)]
pub struct BotEnrollment {
    pub bot: BotSummary,
    pub key_id: String,
    pub enrollment_key: String,
}

impl std::fmt::Debug for BotEnrollment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BotEnrollment")
            .field("bot", &self.bot)
            .field("key_id", &self.key_id)
            .field("enrollment_key", &"[REDACTED]")
            .finish()
    }
}

/// A scoped agent token, returned once when it is issued. It is presented
/// directly as `Authorization: Bearer` and carries its bot's grant: the
/// owner's non-admin rights cut down by the bot's reach.
#[derive(Clone, PartialEq, Eq)]
pub struct BotAccessTokenIssued {
    pub bot: BotSummary,
    pub token_id: String,
    pub token: String,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for BotAccessTokenIssued {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BotAccessTokenIssued")
            .field("bot", &self.bot)
            .field("token_id", &self.token_id)
            .field("token", &"[REDACTED]")
            .field("label", &self.label)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// What the owner sees about an agent token after it is issued: never the
/// token itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BotAccessTokenSummary {
    pub token_id: String,
    pub bot_id: Uuid,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// A verified agent token: the bot it acts as, and the key id and credential
/// generation its calls are authorized under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotAccessTokenAuth {
    pub bot: BotSummary,
    pub token_id: String,
    pub key_id: String,
    pub generation: u64,
    pub expires_at: DateTime<Utc>,
}

/// Access token material the edge turns into a short-lived JWT. The refresh
/// token is returned once per exchange or rotation.
/// Not serializable: a refresh token in this value must never be written to
/// sqlite, a snapshot, or an audit row. A lost-response replay seals its own
/// payload instead of storing this struct.
#[derive(Clone, PartialEq, Eq)]
pub struct BotSession {
    pub bot: BotSummary,
    pub key_id: String,
    pub generation: u64,
    pub refresh_token: String,
    pub refresh_expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for BotSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BotSession")
            .field("bot", &self.bot)
            .field("key_id", &self.key_id)
            .field("generation", &self.generation)
            .field("refresh_token", &"[REDACTED]")
            .field("refresh_expires_at", &self.refresh_expires_at)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotCall {
    pub bot_id: Uuid,
    pub generation: u64,
    pub key_id: String,
    pub owner: String,
    pub repo: String,
    pub effect: BotEffect,
    pub task_kind: Option<BotTaskKind>,
    pub task_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotObservation {
    pub key_id: String,
    pub action: String,
    pub outcome: String,
    pub scope: String,
    pub repo: Option<String>,
    pub session_id: Option<String>,
    pub success: bool,
    pub mutation: bool,
    pub heartbeat: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BotOperationGate {
    Start,
    Replay { result_json: String },
    InProgress,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BotActivityEvent {
    pub id: Uuid,
    pub bot_id: Uuid,
    pub key_id: String,
    pub repo: Option<String>,
    pub session_id: Option<String>,
    pub action: String,
    pub outcome: String,
    pub scope: String,
    pub created_at: DateTime<Utc>,
}
