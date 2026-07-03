//! Durable account, session, token, and repository-grant models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    User,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserAccount {
    pub login: String,
    pub password_hash: String,
    pub role: UserRole,
    #[serde(default)]
    pub must_change_password: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountSummary {
    pub login: String,
    pub role: UserRole,
    pub must_change_password: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<UserAccount> for AccountSummary {
    fn from(account: UserAccount) -> Self {
        Self {
            login: account.login,
            role: account.role,
            must_change_password: account.must_change_password,
            created_at: account.created_at,
            updated_at: account.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebSession {
    pub id: Uuid,
    pub login: String,
    pub token_hash: String,
    pub csrf_token: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionReceipt {
    pub session: WebSession,
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersonalAccessToken {
    pub id: Uuid,
    pub login: String,
    pub name: String,
    pub token_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersonalAccessTokenSummary {
    pub id: Uuid,
    pub login: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl From<PersonalAccessToken> for PersonalAccessTokenSummary {
    fn from(token: PersonalAccessToken) -> Self {
        Self {
            id: token.id,
            login: token.login,
            name: token.name,
            created_at: token.created_at,
            expires_at: token.expires_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonalAccessTokenReceipt {
    pub token: PersonalAccessToken,
    pub secret: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum RepoAccessLevel {
    Read,
    Write,
    Admin,
}

impl RepoAccessLevel {
    #[must_use]
    pub fn allows_read(self) -> bool {
        matches!(self, Self::Read | Self::Write | Self::Admin)
    }

    #[must_use]
    pub fn allows_write(self) -> bool {
        matches!(self, Self::Write | Self::Admin)
    }

    #[must_use]
    pub fn allows_admin(self) -> bool {
        self == Self::Admin
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoAccessGrant {
    pub login: String,
    pub owner: String,
    pub repo: String,
    pub access: RepoAccessLevel,
    pub granted_by: String,
    pub granted_at: DateTime<Utc>,
}
