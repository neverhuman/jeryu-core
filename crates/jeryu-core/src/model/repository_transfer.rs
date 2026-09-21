//! Durable repository-transfer journal and read-only alias models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// One old repository slug retained as a read-only Git/LFS alias.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepositoryAlias {
    pub repository_id: Uuid,
    pub owner: String,
    pub name: String,
    pub canonical_owner: String,
    pub canonical_name: String,
    pub created_at: DateTime<Utc>,
    pub transaction_id: Uuid,
    /// Which operation recorded the alias; stored rows before 0015 are
    /// transfers.
    #[serde(default)]
    pub origin: RepositoryAliasOrigin,
}

/// Operation that recorded a [`RepositoryAlias`].
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryAliasOrigin {
    /// Two-phase transfer journal (`commit_repository_transfer`).
    #[default]
    Transfer,
    /// `ForgeCore::rename_repository` (rename, owner move, or both).
    Rename,
}

/// State of a two-phase repository transfer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryTransferStatus {
    Prepared,
    Committed,
    Failed,
}

/// Closed request used to prepare a durable transfer journal entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrepareRepositoryTransfer {
    pub repository_id: Uuid,
    pub expected_source_owner: String,
    pub expected_source_name: String,
    pub destination_owner: String,
    pub request_fingerprint: String,
    pub idempotency_key: String,
}

/// Durable recovery record for a repository transfer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepositoryTransferJournal {
    pub transaction_id: Uuid,
    pub idempotency_key: String,
    pub request_fingerprint: String,
    pub repository_id: Uuid,
    pub source_owner: String,
    pub source_name: String,
    pub destination_owner: String,
    pub destination_name: String,
    pub status: RepositoryTransferStatus,
    pub prepared_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub failure: Option<String>,
    pub receipt: Option<Value>,
}
