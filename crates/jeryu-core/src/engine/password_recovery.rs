//! Self-service password recovery with a core-issued, single-use secret.
//!
//! `issue_password_recovery` mints a secret for an active account. The edge
//! mails it to the account's verified address. `recover_password` takes that
//! secret back with the new password and spends it under the forge write lock. Core stores only the SHA-256 of the secret. A secret expires
//! after an hour, is spent once, is bound to the account's `auth_epoch` at
//! issue, and dies after five wrong secrets for its id.
//!
//! A recovery revokes every session and API credential of the account, like
//! `change_account_password` (docs/adr/0001): it bumps `auth_epoch`, ends
//! browser sessions, deletes personal access tokens, and revokes the keys,
//! refresh tokens and agent tokens of the account's own bots. A recovery is
//! what someone reaches for when they think the account is compromised, so it
//! must cut off a credential that has already leaked. Repository grants are
//! the account's permissions, not credentials, and stay. Team bots belong to
//! their organization; as with a steward's password change, their tokens stay.
//!
//! What core guarantees, and what the edge must add:
//! - Every refusal is one `Validation` error, and issuing for an unknown or
//!   inactive login does the same durable work as issuing for an active one:
//!   a full snapshot write and one audit row in the same transaction.
//! - Core does not rate limit and cannot hide the network timing of its
//!   caller. The edge must answer the forgot-password request without waiting
//!   for `issue_password_recovery` (run it after responding), and rate limit
//!   both endpoints per client and per address.
//! - Dead rows (spent, expired, exhausted) are pruned on every issue, every
//!   spend and every open, and a login holds at most one live secret, so the
//!   table never holds more live rows than there are active accounts.

use chrono::{DateTime, Duration, Utc};
use parking_lot::RwLockWriteGuard;
use uuid::Uuid;

use super::audit::AuditEntry;
use super::auth::{
    constant_time_eq, hash_password, next_auth_epoch, require_login, require_password,
};
use super::bots::{new_key_id, new_secret, token_hash};
use super::{ForgeCore, State};
use crate::errors::{ForgeError, Result};
use crate::model::*;

/// Prefix of every recovery secret, so secret scanners can recognise one.
pub const PASSWORD_RECOVERY_PREFIX: &str = "jrr_";
const RECOVERY_TTL_MINUTES: i64 = 60;
const RECOVERY_MAX_ATTEMPTS: u32 = 5;
/// One answer for every refusal, so neither call reveals whether a login
/// exists, is active, or holds a live secret.
const RECOVERY_ERROR: &str = "password recovery could not be completed";
const ISSUE_ACTION: &str = "account.password_recovery.issue";
/// Audit action of a spend, or of a wrong secret presented for a live id.
pub(super) const RECOVERY_AUDIT_ACTION: &str = "account.password_recovery.reset";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PasswordRecoveryRecord {
    pub token_id: String,
    pub login: String,
    pub secret_hash: String,
    pub auth_epoch: u64,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub attempt_count: u32,
}

impl PasswordRecoveryRecord {
    fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.consumed_at.is_none()
            && self.expires_at > now
            && self.attempt_count < RECOVERY_MAX_ATTEMPTS
    }
}

/// What a verified secret allows, checked again before anything changes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedSpend {
    login: String,
    auth_epoch: u64,
}

impl ForgeCore {
    /// Issue a recovery secret for an active account, retire any secret issued
    /// to it before, and prune dead secrets. The secret is in the result once
    /// and is never stored or returned again.
    ///
    /// An unknown login and an account that is not active get the same
    /// `Validation` error. They cause the same durable work as a success (a
    /// snapshot write with one `failed` audit row) and change no account.
    pub fn issue_password_recovery(&self, login: &str) -> Result<PasswordRecoveryIssued> {
        if require_login(login).is_err() {
            // No account can have this shape, so answering at once reveals nothing.
            return Err(recovery_error());
        }
        let token_id = new_key_id()?;
        let token = format!("{PASSWORD_RECOVERY_PREFIX}{token_id}.{}", new_secret()?);
        let now = Utc::now();
        let expires_at = now + Duration::minutes(RECOVERY_TTL_MINUTES);
        let mut state = self.state.write();
        let previous = state.clone();
        prune_dead_recoveries(&mut state, now);
        let auth_epoch = match state.accounts.get(login) {
            Some(account) if account.status.permits_authentication() => account.auth_epoch,
            _ => {
                let entry = audit_entry(
                    "local",
                    ISSUE_ACTION,
                    login,
                    "failed",
                    serde_json::json!({}),
                );
                self.commit_with_audit(&mut state, previous, &entry)?;
                return Err(recovery_error());
            }
        };
        retire_live_secrets(&mut state, login, now);
        prune_dead_recoveries(&mut state, now);
        state.password_recoveries.insert(
            token_id.clone(),
            PasswordRecoveryRecord {
                token_id: token_id.clone(),
                login: login.to_string(),
                secret_hash: token_hash(&token),
                auth_epoch,
                created_at: now,
                expires_at,
                consumed_at: None,
                attempt_count: 0,
            },
        );
        let entry = audit_entry(
            login,
            ISSUE_ACTION,
            login,
            "completed",
            serde_json::json!({ "token_id": token_id, "expires_at": expires_at }),
        );
        self.commit_with_audit(&mut state, previous, &entry)?;
        Ok(PasswordRecoveryIssued {
            login: login.to_string(),
            token_id,
            token,
            expires_at,
        })
    }

    /// Spend a recovery secret from `issue_password_recovery` and set the new
    /// password.
    ///
    /// The secret is checked (one SHA-256) under the write lock before the
    /// Argon2id hash of the new password is computed, so only a live, correct
    /// secret pays for the hash. The hash runs outside the lock; the check is
    /// then repeated under the lock before anything changes, so a concurrent
    /// spend, issue or account change in between makes this one fail.
    ///
    /// Revokes every session and API credential of the account, exactly like
    /// `change_account_password` (docs/adr/0001): `auth_epoch` moves, browser
    /// sessions end, personal access tokens are deleted, and the account's own
    /// bots lose their keys, refresh tokens and agent tokens. A forced password
    /// change is cleared. Repository grants and team bots are untouched.
    ///
    /// A short password is refused first and spends nothing. Every other
    /// refusal is the same `Validation` error: an unknown, spent, expired or
    /// exhausted secret, an account that is no longer active, or an account
    /// whose `auth_epoch` moved since issue. A wrong secret for a live id
    /// counts one attempt and writes a `failed` audit row, and nothing else.
    ///
    /// The change and its `completed` audit row commit in one transaction:
    /// both or neither.
    pub fn recover_password(
        &self,
        recovery_secret: &str,
        new_password: &str,
    ) -> Result<PasswordRecoveryReceipt> {
        require_password(new_password)?;
        let token_id = parse_recovery_secret(recovery_secret).ok_or_else(recovery_error)?;
        let checked = {
            let mut state = self.state.write();
            match verify_spend(&state, token_id, recovery_secret, Utc::now()) {
                Ok(checked) => checked,
                Err(Refusal::WrongSecret) => {
                    self.count_wrong_secret(&mut state, token_id);
                    return Err(recovery_error());
                }
                Err(Refusal::Refused) => return Err(recovery_error()),
            }
        };
        let password_hash = hash_password(new_password)?;
        let now = Utc::now();
        let mut state = self.state.write();
        let verified = verify_spend(&state, token_id, recovery_secret, now)
            .ok()
            .filter(|again| *again == checked)
            .ok_or_else(recovery_error)?;
        let login = verified.login.as_str();
        let previous = state.clone();
        retire_live_secrets(&mut state, login, now);
        prune_dead_recoveries(&mut state, now);
        let account = state
            .accounts
            .get_mut(login)
            .expect("verify_spend found the account");
        account.password_hash = password_hash;
        account.must_change_password = false;
        account.auth_epoch = next_auth_epoch(account.auth_epoch)?;
        account.updated_at = now;
        let updated = account.clone();
        let sessions_before = state.sessions.len();
        state.sessions.retain(|_, session| session.login != login);
        let sessions_ended = sessions_before - state.sessions.len();
        let tokens_before = state.personal_tokens.len();
        state
            .personal_tokens
            .retain(|_, token| token.login != login);
        let personal_access_tokens_revoked = tokens_before - state.personal_tokens.len();
        super::bots::invalidate_account_bots(&mut state, login, now);
        let detail = serde_json::json!({
            "token_id": token_id,
            "auth_epoch_before": verified.auth_epoch,
            "auth_epoch": updated.auth_epoch,
            "sessions_ended": sessions_ended,
            "personal_access_tokens_revoked": personal_access_tokens_revoked,
            "bot_credentials_revoked": true,
        });
        let entry = audit_entry(login, RECOVERY_AUDIT_ACTION, login, "completed", detail);
        self.commit_with_audit(&mut state, previous, &entry)?;
        Ok(PasswordRecoveryReceipt {
            account: updated.into(),
            sessions_ended,
            personal_access_tokens_revoked,
        })
    }

    /// Count one wrong secret against a live id and audit it. A storage
    /// failure here is swallowed into the uniform refusal: it must not tell
    /// the caller that the id was live.
    fn count_wrong_secret(&self, state: &mut RwLockWriteGuard<'_, State>, token_id: &str) {
        let previous = state.clone();
        let Some(record) = state.password_recoveries.get_mut(token_id) else {
            return;
        };
        record.attempt_count = record.attempt_count.saturating_add(1);
        let entry = audit_entry(
            "local",
            RECOVERY_AUDIT_ACTION,
            &record.login,
            "failed",
            serde_json::json!({
                "token_id": token_id,
                "reason": "wrong secret",
                "attempt_count": record.attempt_count,
            }),
        );
        let _ = self.commit_with_audit(state, previous, &entry);
    }

    /// Persist the state and one audit row in a single transaction, or roll
    /// the in-memory state back. The in-memory core has no store and no trail.
    fn commit_with_audit(
        &self,
        state: &mut RwLockWriteGuard<'_, State>,
        previous: State,
        entry: &AuditEntry,
    ) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        if let Err(error) = storage.persist_with_audit(state, entry) {
            **state = previous;
            return Err(error);
        }
        Ok(())
    }
}

enum Refusal {
    /// The id names a live secret, but the secret is wrong.
    WrongSecret,
    Refused,
}

/// Check a presented secret against the state without changing anything.
fn verify_spend(
    state: &State,
    token_id: &str,
    secret: &str,
    now: DateTime<Utc>,
) -> std::result::Result<VerifiedSpend, Refusal> {
    let record = state
        .password_recoveries
        .get(token_id)
        .filter(|record| record.is_live(now))
        .ok_or(Refusal::Refused)?;
    if !constant_time_eq(token_hash(secret).as_bytes(), record.secret_hash.as_bytes()) {
        return Err(Refusal::WrongSecret);
    }
    match state.accounts.get(&record.login) {
        Some(account)
            if account.status.permits_authentication()
                && account.auth_epoch == record.auth_epoch =>
        {
            Ok(VerifiedSpend {
                login: record.login.clone(),
                auth_epoch: record.auth_epoch,
            })
        }
        _ => Err(Refusal::Refused),
    }
}

fn audit_entry(
    actor: &str,
    action: &str,
    login: &str,
    phase: &str,
    detail: serde_json::Value,
) -> AuditEntry {
    AuditEntry {
        id: Uuid::new_v4().to_string(),
        occurred_at: Utc::now().to_rfc3339(),
        actor: actor.to_string(),
        action: action.to_string(),
        subject: format!("account:{login}"),
        phase: phase.to_string(),
        detail,
    }
}

fn recovery_error() -> ForgeError {
    ForgeError::Validation(RECOVERY_ERROR.to_string())
}

/// The token id of a well-formed `jrr_<id>.<secret>` value.
fn parse_recovery_secret(value: &str) -> Option<&str> {
    if value.len() > 128 {
        return None;
    }
    let rest = value.strip_prefix(PASSWORD_RECOVERY_PREFIX)?;
    let (token_id, secret) = rest.split_once('.')?;
    (token_id.len() == 12 && secret.len() >= 32).then_some(token_id)
}

/// Spend every live secret of `login`, so at most one is ever live and none
/// outlives a recovery.
fn retire_live_secrets(state: &mut State, login: &str, now: DateTime<Utc>) {
    for record in state.password_recoveries.values_mut() {
        if record.login == login && record.consumed_at.is_none() {
            record.consumed_at = Some(now);
        }
    }
}

/// Drop every spent, expired or exhausted secret. Returns how many went.
pub(super) fn prune_dead_recoveries(state: &mut State, now: DateTime<Utc>) -> usize {
    let before = state.password_recoveries.len();
    state
        .password_recoveries
        .retain(|_, record| record.is_live(now));
    before - state.password_recoveries.len()
}
