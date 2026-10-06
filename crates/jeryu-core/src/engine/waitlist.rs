//! Public waitlist. An address here is not an account and cannot log in.

use chrono::Utc;

use super::ForgeCore;
use crate::errors::{ForgeError, Result};
use crate::model::{WaitlistJoin, WaitlistSignup};

const EMAIL_MAX: usize = 254;
const LOCAL_MAX: usize = 64;
const NAME_MAX: usize = 80;

impl ForgeCore {
    /// Record an email, or return the existing row when that email is already listed.
    ///
    /// The address is trimmed and compared in ASCII lowercase. A repeat does not
    /// change the stored name or the original time, and it does not create a user.
    pub fn join_waitlist(&self, email: &str, name: Option<&str>) -> Result<WaitlistJoin> {
        let email = normalize_waitlist_email(email)?;
        let name = normalize_waitlist_name(name)?;
        let mut state = self.state.write();
        if let Some(existing) = state.waitlist.get(&email) {
            return Ok(WaitlistJoin::AlreadyListed(existing.clone()));
        }
        let signup = WaitlistSignup {
            email: email.clone(),
            name,
            created_at: Utc::now(),
        };
        let previous = state.clone();
        state.waitlist.insert(email, signup.clone());
        self.persist_after_mutation(&mut state, previous)?;
        Ok(WaitlistJoin::Created(signup))
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

fn normalize_waitlist_name(raw: Option<&str>) -> Result<Option<String>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let name = raw.trim();
    if name.is_empty() {
        return Ok(None);
    }
    if name.chars().count() > NAME_MAX || name.chars().any(char::is_control) {
        return Err(ForgeError::Validation(
            "name must be 80 characters or fewer, without control characters".to_string(),
        ));
    }
    Ok(Some(name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CreateUserRequest;

    #[test]
    fn waitlist_join_normalizes_and_keeps_the_first_signup() {
        let core = ForgeCore::new();
        let created = core
            .join_waitlist("  Ada@Example.COM ", Some("  Ada  "))
            .unwrap();
        let WaitlistJoin::Created(signup) = created else {
            panic!("first join creates a row");
        };
        assert_eq!(signup.email, "ada@example.com");
        assert_eq!(signup.name.as_deref(), Some("Ada"));

        let again = core
            .join_waitlist("ADA@example.com", Some("someone else"))
            .unwrap();
        let WaitlistJoin::AlreadyListed(listed) = again else {
            panic!("a repeated address is already listed");
        };
        assert_eq!(listed, signup);
        assert_eq!(core.list_waitlist(), vec![signup]);

        let blank = core.join_waitlist("ada@example.com", Some("   ")).unwrap();
        assert!(matches!(blank, WaitlistJoin::AlreadyListed(_)));

        assert!(core.join_waitlist("not-an-email", None).is_err());
        assert!(core.join_waitlist("a@b", None).is_err());
        assert!(core.join_waitlist(" ada @example.com ", None).is_err());
        assert!(core.join_waitlist("ada@example.com", Some("a\nb")).is_err());
        assert!(core.list_accounts().is_empty());
    }

    #[test]
    fn waitlist_survives_sqlite_reopen_and_unrelated_write() {
        let tempdir = tempfile::tempdir().unwrap();
        let db_path = tempdir.path().join("forge.sqlite");
        let core = ForgeCore::open_sqlite(&db_path).unwrap();
        let WaitlistJoin::Created(signup) = core.join_waitlist("ada@example.com", None).unwrap()
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
}
