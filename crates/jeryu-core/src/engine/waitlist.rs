//! Public waitlist. An address here is not an account and cannot log in.
//!
//! A join failure is a repairable exception.
//!
//! purpose: record a landing email without opening an account.
//! reason: the address is invalid, or the list cannot take a new row.
//! common fixes: send one normal email address; a repeat does not write again; a full list waits for an operator.
//! docs_url: docs/errors.md#waitlist
//! repair_hint: rerun cargo test -p jeryu-core waitlist

use chrono::Utc;

use super::ForgeCore;
use crate::errors::{ForgeError, Result};
use crate::model::{WaitlistJoin, WaitlistSignup, WaitlistStatus};

const EMAIL_MAX: usize = 254;
const LOCAL_MAX: usize = 64;
const NAME_MAX: usize = 80;
const NOTE_MAX: usize = 280;
const WAITLIST_SOURCE: &str = "landing";
/// Hard cap on stored addresses. Past this, a new address is
/// [`ForgeError::WaitlistFull`] and nothing is written.
pub const MAX_WAITLIST: usize = 50_000;

impl ForgeCore {
    /// Record an email, or report that the address is already listed.
    ///
    /// The address is trimmed and compared in ASCII lowercase. A repeat keeps
    /// the original row and does not persist. A new address at [`MAX_WAITLIST`]
    /// returns [`ForgeError::WaitlistFull`] and does not persist. Joining does
    /// not create a user.
    pub fn join_waitlist(
        &self,
        email: &str,
        name: Option<&str>,
        note: Option<&str>,
    ) -> Result<WaitlistJoin> {
        let email = normalize_waitlist_email(email)?;
        let name = normalize_waitlist_text(name, NAME_MAX, "name")?;
        let note = normalize_waitlist_text(note, NOTE_MAX, "note")?;
        let mut state = self.state.write();
        if let Some(existing) = state.waitlist.get(&email) {
            return Ok(WaitlistJoin::AlreadyListed(existing.clone()));
        }
        if state.waitlist.len() >= MAX_WAITLIST {
            return Err(ForgeError::WaitlistFull);
        }
        let now = Utc::now();
        let signup = WaitlistSignup {
            email: email.clone(),
            name,
            note,
            status: WaitlistStatus::Listed,
            source: WAITLIST_SOURCE.to_string(),
            request_count: 1,
            created_at: now,
            last_requested_at: now,
        };
        let previous = state.clone();
        state.waitlist.insert(email, signup.clone());
        self.persist_after_mutation(&mut state, previous)?;
        Ok(WaitlistJoin::Created(signup))
    }

    /// How many addresses are stored. This reads the map length and does not
    /// clone the forge state.
    #[must_use]
    pub fn waitlist_len(&self) -> usize {
        self.state.read().waitlist.len()
    }

    /// Every signup, oldest first.
    #[must_use]
    pub fn list_waitlist(&self) -> Vec<WaitlistSignup> {
        let state = self.state.read();
        let mut rows: Vec<_> = state.waitlist.values().cloned().collect();
        rows.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left.email.cmp(&right.email))
        });
        rows
    }
}

fn normalize_waitlist_email(raw: &str) -> Result<String> {
    let email = raw.trim().to_ascii_lowercase();
    let Some((local, domain)) = email.split_once('@') else {
        return invalid_email();
    };
    if email.len() < 3
        || email.len() > EMAIL_MAX
        || local.is_empty()
        || local.len() > LOCAL_MAX
        || email.matches('@').count() != 1
        || !local_part_ok(local)
        || !domain_ok(domain)
    {
        return invalid_email();
    }
    Ok(email)
}

fn invalid_email() -> Result<String> {
    Err(ForgeError::Validation(
        "enter a valid email address".to_string(),
    ))
}

fn local_part_ok(local: &str) -> bool {
    let bytes = local.as_bytes();
    !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'%' | b'+' | b'-')
        })
}

fn domain_ok(domain: &str) -> bool {
    let labels: Vec<&str> = domain.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            let bytes = label.as_bytes();
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
}

fn normalize_waitlist_text(
    raw: Option<&str>,
    max_chars: usize,
    field: &str,
) -> Result<Option<String>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let text = raw.trim();
    if text.is_empty() {
        return Ok(None);
    }
    if text.chars().count() > max_chars || text.chars().any(char::is_control) {
        return Err(ForgeError::Validation(format!(
            "{field} must be {max_chars} characters or fewer, without control characters"
        )));
    }
    Ok(Some(text.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CreateUserRequest;

    #[test]
    fn waitlist_join_normalizes_and_keeps_the_first_signup() {
        let core = ForgeCore::new();
        let created = core
            .join_waitlist("  Ada@Example.COM ", Some("  Ada  "), Some("  a forge  "))
            .unwrap();
        let WaitlistJoin::Created(signup) = created else {
            panic!("first join creates a row");
        };
        assert_eq!(signup.email, "ada@example.com");
        assert_eq!(signup.name.as_deref(), Some("Ada"));
        assert_eq!(signup.note.as_deref(), Some("a forge"));
        assert_eq!(signup.status, WaitlistStatus::Listed);
        assert_eq!(signup.source, "landing");
        assert_eq!(signup.request_count, 1);
        assert_eq!(signup.last_requested_at, signup.created_at);

        let again = core
            .join_waitlist(
                "ADA@example.com",
                Some("someone else"),
                Some("a different note"),
            )
            .unwrap();
        let WaitlistJoin::AlreadyListed(listed) = again else {
            panic!("a repeated address is already listed");
        };
        assert_eq!(listed.name, signup.name);
        assert_eq!(listed.note, signup.note);
        assert_eq!(listed.status, signup.status);
        assert_eq!(listed.created_at, signup.created_at);
        assert_eq!(listed.request_count, 1);
        assert_eq!(listed.last_requested_at, signup.created_at);
        assert_eq!(core.waitlist_len(), 1);
        assert_eq!(core.list_waitlist(), vec![listed]);

        let blank = core
            .join_waitlist("ada@example.com", Some("   "), Some("  "))
            .unwrap();
        assert!(matches!(blank, WaitlistJoin::AlreadyListed(_)));

        assert!(core.join_waitlist("not-an-email", None, None).is_err());
        assert!(core.join_waitlist("a@b", None, None).is_err());
        assert!(
            core.join_waitlist(" ada @example.com ", None, None)
                .is_err()
        );
        assert!(
            core.join_waitlist("ada@example.com", Some("a\nb"), None)
                .is_err()
        );
        assert!(
            core.join_waitlist("ada@example.com", None, Some("a\nb"))
                .is_err()
        );
        assert!(core.list_accounts().is_empty());
    }

    #[test]
    fn waitlist_survives_sqlite_reopen_and_unrelated_write() {
        let tempdir = tempfile::tempdir().unwrap();
        let db_path = tempdir.path().join("forge.sqlite");
        let core = ForgeCore::open_sqlite(&db_path).unwrap();
        let WaitlistJoin::Created(signup) = core
            .join_waitlist("ada@example.com", None, Some("agents"))
            .unwrap()
        else {
            panic!("created");
        };
        core.create_user(CreateUserRequest {
            login: "alice".to_string(),
            name: None,
            email: None,
        })
        .unwrap();
        assert_eq!(core.list_waitlist(), vec![signup.clone()]);

        drop(core);
        let reopened = ForgeCore::open_sqlite(&db_path).unwrap();
        assert_eq!(reopened.list_waitlist(), vec![signup]);
        assert_eq!(reopened.get_user("alice").unwrap().login, "alice");
    }

    #[test]
    fn waitlist_repeat_does_not_rewrite_sqlite() {
        let tempdir = tempfile::tempdir().unwrap();
        let db_path = tempdir.path().join("forge.sqlite");
        let core = ForgeCore::open_sqlite(&db_path).unwrap();
        core.join_waitlist("ada@example.com", Some("Ada"), Some("agents"))
            .unwrap();
        let before = std::fs::read(&db_path).unwrap();
        let again = core
            .join_waitlist("ADA@example.com", Some("other"), Some("nope"))
            .unwrap();
        let WaitlistJoin::AlreadyListed(row) = again else {
            panic!("repeat");
        };
        assert_eq!(row.request_count, 1);
        assert_eq!(row.name.as_deref(), Some("Ada"));
        assert_eq!(std::fs::read(&db_path).unwrap(), before);
        assert_eq!(core.waitlist_len(), 1);
    }

    #[test]
    fn waitlist_cap_refuses_a_new_address_and_keeps_a_repeat() {
        let core = ForgeCore::new();
        let now = Utc::now();
        {
            let mut state = core.state.write();
            for index in 0..MAX_WAITLIST {
                let email = format!("u{index}@x.co");
                state.waitlist.insert(
                    email.clone(),
                    WaitlistSignup {
                        email,
                        name: None,
                        note: None,
                        status: WaitlistStatus::Listed,
                        source: WAITLIST_SOURCE.to_string(),
                        request_count: 1,
                        created_at: now,
                        last_requested_at: now,
                    },
                );
            }
        }
        assert_eq!(core.waitlist_len(), MAX_WAITLIST);
        let refused = core
            .join_waitlist("new@example.com", None, None)
            .expect_err("the cap refuses a new address");
        assert!(matches!(refused, ForgeError::WaitlistFull), "{refused:?}");
        assert_eq!(core.waitlist_len(), MAX_WAITLIST);
        let repeat = core.join_waitlist("u0@x.co", Some("nope"), None).unwrap();
        assert!(matches!(repeat, WaitlistJoin::AlreadyListed(_)));
        assert_eq!(core.waitlist_len(), MAX_WAITLIST);
    }

    /// `db/constraints.md` says a second join keeps the stored request count.
    /// Restoring the older increment sentence fails this test.
    #[test]
    fn waitlist_constraints_keep_the_stored_request_count() {
        let policy = include_str!("../../../../db/constraints.md");
        assert!(
            policy.contains("stored row and does not write"),
            "constraints.md must say a repeat returns the stored row and does not write"
        );
        assert!(
            policy.contains("`request_count` stay as stored"),
            "constraints.md must say request_count stays as stored"
        );
        assert!(
            !policy.contains("increments the count"),
            "constraints.md must not say a repeat increments the count"
        );

        let core = ForgeCore::new();
        let WaitlistJoin::Created(signup) = core
            .join_waitlist("ada@example.com", Some("Ada"), None)
            .unwrap()
        else {
            panic!("first join creates a row");
        };
        assert_eq!(signup.request_count, 1);
        let WaitlistJoin::AlreadyListed(listed) = core
            .join_waitlist("ADA@example.com", Some("other"), Some("nope"))
            .unwrap()
        else {
            panic!("a repeated address is already listed");
        };
        assert_eq!(listed.request_count, signup.request_count);
        assert_eq!(listed.created_at, signup.created_at);
        assert_eq!(listed.last_requested_at, signup.last_requested_at);
        assert_eq!(core.waitlist_len(), 1);
    }
}
