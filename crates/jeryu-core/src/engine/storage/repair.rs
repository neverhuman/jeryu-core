//! Agent repair hints for the failures the SQLite store raises.

use crate::error::AgentRepairHint;
use crate::errors::ForgeError;

/// The class of failure the SQLite store raised, as a typed error.
///
/// purpose: give each store failure one stable class that routes to one repair.
/// reason: custody codes and plain storage failures need different fixes.
/// common fixes: see `hint().common_fixes`.
/// docs_url: docs/errors.md#store-custody
/// repair_hint: rerun cargo test -p jeryu-core storage::tests
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreFailureError {
    /// Another process or open holds the database (`store_locked`).
    Locked,
    /// The file has a second hard link or the path is a dangling link (`store_aliased`).
    Aliased,
    /// The path no longer names the file this store opened (`store_replaced`).
    Replaced,
    /// The database is in WAL mode (`store_journal`).
    Journal,
    /// Any other custody refusal.
    Custody,
    /// A plain read or write failure.
    Storage,
}

impl StoreFailureError {
    /// Classify a forge error; `None` for errors the store does not raise.
    pub fn classify(error: &ForgeError) -> Option<Self> {
        match error {
            ForgeError::StoreCustody(text) => Some(
                [
                    ("store_locked", Self::Locked),
                    ("store_aliased", Self::Aliased),
                    ("store_replaced", Self::Replaced),
                    ("store_journal", Self::Journal),
                ]
                .into_iter()
                .find(|(code, _)| text.starts_with(code))
                .map_or(Self::Custody, |(_, class)| class),
            ),
            ForgeError::Storage(_) => Some(Self::Storage),
            _ => None,
        }
    }

    /// Return the repair contract for this class.
    pub fn hint(self) -> AgentRepairHint {
        let (reason, common_fixes): (&'static str, &'static [&'static str]) = match self {
            Self::Journal => (
                "store_journal",
                &[
                    "stop the forge, then run PRAGMA journal_mode = DELETE; on the database once",
                    "start the forge again; it never converts the journal on open",
                ],
            ),
            Self::Storage => (
                "storage_failed",
                &[
                    "check the database file is readable, writable and on a local disk",
                    "check the schema was migrated by the same or a newer forge build",
                ],
            ),
            Self::Locked | Self::Aliased | Self::Replaced | Self::Custody => (
                match self {
                    Self::Locked => "store_locked",
                    Self::Aliased => "store_aliased",
                    Self::Replaced => "store_replaced",
                    _ => "store_custody",
                },
                &[
                    "run one forge per data directory and share a store by cloning its ForgeCore",
                    "open the database by its one path and remove extra hard links",
                    "do not move or replace forge.sqlite while the forge runs",
                ],
            ),
        };
        AgentRepairHint {
            purpose: if self == Self::Storage {
                "read or write the durable forge state"
            } else {
                "keep one writer per forge database"
            },
            reason,
            common_fixes,
            docs_url: "docs/errors.md#store-custody",
            repair_hint: "rerun cargo test -p jeryu-core storage::tests",
        }
    }
}

impl ForgeError {
    /// Return the repair contract for a store failure, or `None` for errors
    /// the store does not raise.
    pub fn storage_repair_hint(&self) -> Option<AgentRepairHint> {
        StoreFailureError::classify(self).map(StoreFailureError::hint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_store_failure_has_a_repair_hint() {
        for (error, reason) in [
            (
                ForgeError::StoreCustody("store_locked: x".into()),
                "store_locked",
            ),
            (
                ForgeError::StoreCustody("store_aliased: x".into()),
                "store_aliased",
            ),
            (
                ForgeError::StoreCustody("store_replaced: x".into()),
                "store_replaced",
            ),
            (
                ForgeError::StoreCustody("store_journal: x".into()),
                "store_journal",
            ),
            (ForgeError::StoreCustody("other".into()), "store_custody"),
            (ForgeError::Storage("disk".into()), "storage_failed"),
        ] {
            let hint = error.storage_repair_hint().expect("hint");
            assert_eq!(hint.reason, reason);
            assert!(!hint.common_fixes.is_empty());
            assert!(hint.docs_url.starts_with("docs/errors.md#"));
            assert!(hint.repair_hint.contains("rerun"));
        }
    }

    #[test]
    fn errors_the_store_does_not_raise_have_no_hint() {
        assert!(
            ForgeError::NotFound("x".into())
                .storage_repair_hint()
                .is_none()
        );
    }
}
