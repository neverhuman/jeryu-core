//! Account-owned Grok and Muse bots. Secrets never appear on these types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Vendor kind shown in the product. The client does not get to rename it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BotKind {
    Grok,
    Muse,
}

impl BotKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Grok => "Grokbot",
            Self::Muse => "Musebot",
        }
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
    Repositories {
        repos: Vec<BotRepoRef>,
    },
    Task {
        repo: BotRepoRef,
        task_kind: BotTaskKind,
        task_id: String,
    },
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

/// Access token material the edge turns into a short-lived JWT. The refresh
/// token is returned once per exchange or rotation.
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
