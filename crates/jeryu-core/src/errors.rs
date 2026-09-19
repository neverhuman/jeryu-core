use thiserror::Error;

pub type Result<T> = std::result::Result<T, ForgeError>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ForgeError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    Conflict(String),
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("branch protection blocked the operation: {0}")]
    BranchProtection(String),
    /// The repository is archived (read-only). The display text starts with the
    /// stable code `repository_archived` so edges can surface it verbatim.
    #[error("repository_archived: repository {0} is archived and read-only")]
    RepositoryArchived(String),
    #[error("storage failed: {0}")]
    Storage(String),
}
