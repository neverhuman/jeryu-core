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
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("branch protection blocked the operation: {0}")]
    BranchProtection(String),
    /// The repository is archived (read-only). The display text starts with the
    /// stable code `repository_archived` so edges can surface it verbatim.
    #[error("repository_archived: repository {0} is archived and read-only")]
    RepositoryArchived(String),
    #[error("storage failed: {0}")]
    Storage(String),
    /// The public waitlist cannot store another new address.
    ///
    /// The display text starts with `waitlist_full` so the edge can map this
    /// exception to HTTP 503. A repeat of an address already stored is not
    /// this error.
    ///
    /// purpose: record a landing email without opening an account.
    /// reason: the waitlist is at its row cap.
    /// common fixes: keep the existing address; do not retry a new one in a loop; an operator reviews the list.
    /// docs_url: docs/errors.md#waitlist
    /// repair_hint: rerun cargo test -p jeryu-core waitlist
    #[error("waitlist_full: the waitlist is not accepting new addresses")]
    WaitlistFull,
    /// The store's one-writer custody refused an open or a write.
    ///
    /// The display text starts with a stable code: `store_locked` (another
    /// process, or another open in this process, has the database),
    /// `store_aliased` (the database file has a second hard link, or the path
    /// is a link to nothing), `store_replaced` (the path no longer names
    /// the file this store opened), or `store_journal` (the database is in WAL
    /// mode; the store keeps a rollback journal and converts it only offline).
    ///
    /// purpose: keep one writer per forge database, so its in-memory state is the truth.
    /// reason: a second writer, or another name or file for the database, would let two states overwrite each other.
    /// common fixes: run one forge per data directory; share a store by cloning its ForgeCore; open the database by its one path and remove extra hard links; do not move or replace forge.sqlite while the forge runs.
    /// docs_url: docs/errors.md#store-custody
    /// repair_hint: rerun cargo test -p jeryu-core storage::tests
    #[error("{0}")]
    StoreCustody(String),
}
