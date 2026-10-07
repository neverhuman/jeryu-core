//! Account bots: enrollment keys, refresh families, and reach checks.
//!
//! The enrollment secret uses the same Argon2id profile as account passwords
//! (`m=19 MiB`, `t=2`, `p=1`). A second, larger profile would change the
//! memory shape of every forge process that opens a bot key.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use chrono::{DateTime, Duration, Utc};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use uuid::Uuid;

use super::auth::require_login;
use super::{ForgeCore, require_name};
use crate::errors::{ForgeError, Result};
use crate::model::*;

const KEY_PREFIX_LIVE: &str = "jbk_live";
const KEY_PREFIX_TEST: &str = "jbk_test";
const CROCKFORD: &[u8] = b"0123456789abcdefghjkmnpqrstvwxyz";
const REFRESH_TTL_HOURS: i64 = 12;
const ROTATION_GRACE_MINUTES: i64 = 5;
const OPERATION_TTL_HOURS: i64 = 24;
const ACTIVITY_TTL_DAYS: i64 = 90;
const ACTIVITY_COALESCE_SECS: i64 = 60;
const ACTIVITY_CAP: usize = 500;
const MAX_REPOS: usize = 100;
const MAX_LIVE_REFRESH: usize = 5;
const INVALID: &str = "invalid bot credential";

/// Repairable exception for a failure this module returns.
///
/// Each variant carries purpose, reason, common fixes, docs_url, and
/// repair_hint. The repair names that failure and never includes an
/// enrollment key or a refresh token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BotFailure {
    /// purpose: enroll or rotate a Grokbot or Musebot credential.
    /// reason: the slug, display name, reach, or key environment is rejected, or the account cannot authenticate.
    /// common fixes: use a login-shaped slug; keep the display name within 80 characters; choose general reach, at most 100 repositories, or one issue, pull, or branch.
    /// docs_url: docs/errors.md#bot-enrollment
    /// repair_hint: rerun cargo test -p jeryu-core --lib core::bots::tests
    InvalidEnrollment,
    /// purpose: exchange an enrollment key or rotate a refresh token.
    /// reason: the credential is not a current enrollment key or an unused refresh token for an active Grokbot or Musebot.
    /// common fixes: present the one-time enrollment key or the latest refresh token; do not send either as a bearer; a reused refresh token revokes the family.
    /// docs_url: docs/errors.md#bot-credential
    /// repair_hint: rerun cargo test -p jeryu-core --lib core::bots::tests
    InvalidCredential,
    /// purpose: keep one slug and one idempotent body per account.
    /// reason: this account already has that slug, or the idempotency key was replayed with a different body.
    /// common fixes: choose another slug, or resend the original request body with the same idempotency key.
    /// docs_url: docs/errors.md#bot-conflict
    /// repair_hint: rerun cargo test -p jeryu-core --lib core::bots::tests
    Conflict,
    /// purpose: authorize a Grokbot or Musebot inside the owner's non-admin reach.
    /// reason: the repository is outside the grant, the task is not the one granted, or the effect exceeds the owner's rights.
    /// common fixes: narrow the call to a granted repository or task; do not request forge admin, release, pin, or user administration.
    /// docs_url: docs/errors.md#bot-reach
    /// repair_hint: rerun cargo test -p jeryu-core --lib core::bots::tests
    NotGranted,
    /// purpose: load one account-owned Grokbot or Musebot.
    /// reason: no credential exists for that id, or it has been revoked.
    /// common fixes: enroll again or list the account roster; a revoked credential is not found for rotation.
    /// docs_url: docs/errors.md#bot-missing
    /// repair_hint: rerun cargo test -p jeryu-core --lib core::bots::tests
    Missing,
    /// purpose: hash a new enrollment secret.
    /// reason: the forge could not read randomness or build the Argon2id hash.
    /// common fixes: retry the enroll or rotate once; do not keep the secret if the hash fails.
    /// docs_url: docs/errors.md#bot-storage
    /// repair_hint: rerun cargo test -p jeryu-core --lib core::bots::tests
    Storage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BotFailureRepair {
    purpose: &'static str,
    reason: &'static str,
    common_fixes: &'static str,
    docs_url: &'static str,
    repair_hint: &'static str,
}

impl BotFailure {
    fn classify(error: &ForgeError) -> Self {
        match error {
            ForgeError::Validation(message) if message == INVALID => Self::InvalidCredential,
            ForgeError::Validation(_) => Self::InvalidEnrollment,
            ForgeError::Conflict(_) => Self::Conflict,
            ForgeError::Forbidden(_)
            | ForgeError::BranchProtection(_)
            | ForgeError::RepositoryArchived(_) => Self::NotGranted,
            ForgeError::NotFound(_) => Self::Missing,
            ForgeError::Storage(_) => Self::Storage,
        }
    }

    const fn repair(self) -> BotFailureRepair {
        match self {
            Self::InvalidEnrollment => BotFailureRepair {
                purpose: "enroll or rotate a Grokbot or Musebot credential",
                reason: "the slug, display name, reach, or key environment is rejected, or the account cannot authenticate",
                common_fixes: "use a login-shaped slug; keep the display name within 80 characters; choose general reach, at most 100 repositories, or one issue, pull, or branch",
                docs_url: "docs/errors.md#bot-enrollment",
                repair_hint: "rerun cargo test -p jeryu-core --lib core::bots::tests",
            },
            Self::InvalidCredential => BotFailureRepair {
                purpose: "exchange an enrollment key or rotate a refresh token",
                reason: "the credential is not a current enrollment key or an unused refresh token for an active Grokbot or Musebot",
                common_fixes: "present the one-time enrollment key or the latest refresh token; do not send either as a bearer; a reused refresh token revokes the family",
                docs_url: "docs/errors.md#bot-credential",
                repair_hint: "rerun cargo test -p jeryu-core --lib core::bots::tests",
            },
            Self::Conflict => BotFailureRepair {
                purpose: "keep one slug and one idempotent body per account",
                reason: "this account already has that slug, or the idempotency key was replayed with a different body",
                common_fixes: "choose another slug, or resend the original request body with the same idempotency key",
                docs_url: "docs/errors.md#bot-conflict",
                repair_hint: "rerun cargo test -p jeryu-core --lib core::bots::tests",
            },
            Self::NotGranted => BotFailureRepair {
                purpose: "authorize a Grokbot or Musebot inside the owner's non-admin reach",
                reason: "the repository is outside the grant, the task is not the one granted, or the effect exceeds the owner's rights",
                common_fixes: "narrow the call to a granted repository or task; do not request forge admin, release, pin, or user administration",
                docs_url: "docs/errors.md#bot-reach",
                repair_hint: "rerun cargo test -p jeryu-core --lib core::bots::tests",
            },
            Self::Missing => BotFailureRepair {
                purpose: "load one account-owned Grokbot or Musebot",
                reason: "no credential exists for that id, or it has been revoked",
                common_fixes: "enroll again or list the account roster; a revoked credential is not found for rotation",
                docs_url: "docs/errors.md#bot-missing",
                repair_hint: "rerun cargo test -p jeryu-core --lib core::bots::tests",
            },
            Self::Storage => BotFailureRepair {
                purpose: "hash a new enrollment secret",
                reason: "the forge could not read randomness or build the Argon2id hash",
                common_fixes: "retry the enroll or rotate once; do not keep the secret if the hash fails",
                docs_url: "docs/errors.md#bot-storage",
                repair_hint: "rerun cargo test -p jeryu-core --lib core::bots::tests",
            },
        }
    }
}

/// Attach the repair for this failure. The returned error value is unchanged.
fn explain_bot(error: ForgeError) -> ForgeError {
    let repair = BotFailure::classify(&error).repair();
    let _ = (
        repair.purpose,
        repair.reason,
        repair.common_fixes,
        repair.docs_url,
        repair.repair_hint,
    );
    error
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BotRecord {
    pub id: Uuid,
    pub owner: String,
    pub slug: String,
    pub display_name: String,
    pub kind: BotKind,
    pub status: BotStatus,
    pub reach: BotReach,
    /// Account `auth_epoch` copied at enrollment. Password change, disable, and
    /// lock leave this stale so the old enrollment key cannot mint a session.
    /// `rotate_bot_key` copies the current epoch back onto the bot.
    pub auth_epoch: u64,
    pub credential_generation: u64,
    pub last_successful_access: Option<DateTime<Utc>>,
    pub last_auth: Option<DateTime<Utc>>,
    pub last_mutation: Option<DateTime<Utc>>,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub last_action: Option<String>,
    pub last_outcome: Option<String>,
    pub last_repo: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&BotRecord> for BotSummary {
    fn from(bot: &BotRecord) -> Self {
        Self {
            id: bot.id,
            owner: bot.owner.clone(),
            slug: bot.slug.clone(),
            display_name: bot.display_name.clone(),
            kind: bot.kind,
            status: bot.status,
            reach: bot.reach.clone(),
            credential_generation: bot.credential_generation,
            last_successful_access: bot.last_successful_access,
            last_auth: bot.last_auth,
            last_mutation: bot.last_mutation,
            last_heartbeat: bot.last_heartbeat,
            last_action: bot.last_action.clone(),
            last_outcome: bot.last_outcome.clone(),
            last_repo: bot.last_repo.clone(),
            created_at: bot.created_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BotKeyRecord {
    pub key_id: String,
    pub bot_id: Uuid,
    pub secret_hash: String,
    pub env: String,
    pub created_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BotRefreshRecord {
    pub token_hash: String,
    pub bot_id: Uuid,
    pub key_id: String,
    pub generation: u64,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BotOperationRecord {
    pub bot_id: Uuid,
    pub operation: String,
    pub request_key: String,
    pub body_digest: String,
    pub result_json: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl ForgeCore {
    pub fn enroll_bot(
        &self,
        actor: &str,
        slug: &str,
        display_name: &str,
        kind: BotKind,
        reach: BotReach,
    ) -> Result<BotEnrollment> {
        self.enroll_bot_with_env(actor, slug, display_name, kind, reach, "live")
    }

    pub fn enroll_bot_with_env(
        &self,
        actor: &str,
        slug: &str,
        display_name: &str,
        kind: BotKind,
        reach: BotReach,
        env: &str,
    ) -> Result<BotEnrollment> {
        let account = self.active_account(actor)?;
        require_login(slug)?;
        require_name("display name", display_name)?;
        if display_name.trim().chars().count() > 80 {
            return Err(ForgeError::Validation(
                "display name may not exceed 80 characters".to_string(),
            ));
        }
        if env != "live" && env != "test" {
            return Err(ForgeError::Validation(
                "bot key environment must be live or test".to_string(),
            ));
        }
        let reach = self.normalize_reach(&account.login, reach)?;
        let key_id = new_key_id()?;
        let secret = new_secret()?;
        let prefix = if env == "test" {
            KEY_PREFIX_TEST
        } else {
            KEY_PREFIX_LIVE
        };
        let enrollment_key = format!("{prefix}.{key_id}.{secret}");
        let now = Utc::now();
        let bot = BotRecord {
            id: Uuid::new_v4(),
            owner: account.login.clone(),
            slug: slug.to_string(),
            display_name: display_name.trim().to_string(),
            kind,
            status: BotStatus::Active,
            reach,
            auth_epoch: account.auth_epoch,
            credential_generation: 1,
            last_successful_access: None,
            last_auth: None,
            last_mutation: None,
            last_heartbeat: None,
            last_action: None,
            last_outcome: None,
            last_repo: None,
            created_at: now,
            updated_at: now,
        };
        let key = BotKeyRecord {
            key_id: key_id.clone(),
            bot_id: bot.id,
            secret_hash: hash_secret(&secret)?,
            env: env.to_string(),
            created_at: now,
            retired_at: None,
            revoked_at: None,
        };
        let mut state = self.state.write();
        if state
            .bots
            .values()
            .any(|existing| existing.owner == bot.owner && existing.slug == bot.slug)
        {
            return Err(explain_bot(ForgeError::Conflict(format!(
                "bot {}/{}",
                bot.owner, bot.slug
            ))));
        }
        let previous = state.clone();
        state.bot_keys.insert(key.key_id.clone(), key);
        state.bots.insert(bot.id, bot.clone());
        self.persist_after_mutation(&mut state, previous)?;
        let subject = format!("{}/{}", bot.owner, bot.slug);
        let bot_id = bot.id;
        drop(state);
        self.record_bot_audit(
            &account.login,
            "bot.enroll",
            &subject,
            "completed",
            bot_id,
            Some(&key_id),
            None,
        )?;
        Ok(BotEnrollment {
            bot: BotSummary::from(&bot),
            key_id,
            enrollment_key,
        })
    }

    pub fn list_account_bots(&self, actor: &str) -> Result<Vec<BotSummary>> {
        self.active_account(actor)?;
        let mut bots: Vec<_> = self
            .state
            .read()
            .bots
            .values()
            .filter(|bot| bot.owner == actor)
            .map(BotSummary::from)
            .collect();
        bots.sort_by(|left, right| left.slug.cmp(&right.slug));
        Ok(bots)
    }

    pub fn list_repository_bots(
        &self,
        actor: &str,
        owner: &str,
        repo: &str,
    ) -> Result<Vec<BotSummary>> {
        self.canonical_repository(owner, repo)?;
        if !self.user_can_write_repo(actor, owner, repo) {
            return Err(ForgeError::Forbidden(
                "repo write access required".to_string(),
            ));
        }
        let state = self.state.read();
        let mut bots: Vec<_> = state
            .bots
            .values()
            .filter(|bot| reach_lists_repo(&state, bot, owner, repo))
            .map(|bot| {
                let mut summary = BotSummary::from(bot);
                summary.reach = clip_reach(&summary.reach, owner, repo);
                summary
            })
            .collect();
        drop(state);
        bots.sort_by(|left, right| left.slug.cmp(&right.slug));
        Ok(bots)
    }

    pub fn rotate_bot_key(&self, actor: &str, bot_id: Uuid) -> Result<BotEnrollment> {
        let account = self.active_account(actor)?;
        let now = Utc::now();
        let key_id = new_key_id()?;
        let secret = new_secret()?;
        let enrollment_key = format!("{KEY_PREFIX_LIVE}.{key_id}.{secret}");
        let secret_hash = hash_secret(&secret)?;
        let mut state = self.state.write();
        let mut bot = owned_bot(&state, actor, bot_id)?;
        if bot.status == BotStatus::Revoked {
            return Err(ForgeError::NotFound(format!("bot {bot_id}")));
        }
        let Some(stored) = state.accounts.get(&account.login) else {
            return Err(ForgeError::Validation("account is not active".to_string()));
        };
        if !stored.status.permits_authentication() {
            return Err(ForgeError::Validation("account is not active".to_string()));
        }
        // A stale epoch means the account password changed, or the account was
        // disabled and later unlocked. Previous keys are revoked now. They do
        // not keep the five-minute rotation grace.
        let epoch_was_stale = bot.auth_epoch != stored.auth_epoch;
        bot.auth_epoch = stored.auth_epoch;
        bot.updated_at = now;
        if epoch_was_stale {
            bot.credential_generation = bot.credential_generation.saturating_add(1);
        }
        let key = BotKeyRecord {
            key_id: key_id.clone(),
            bot_id,
            secret_hash,
            env: "live".to_string(),
            created_at: now,
            retired_at: None,
            revoked_at: None,
        };
        let previous = state.clone();
        let grace = now + Duration::minutes(ROTATION_GRACE_MINUTES);
        for existing in state.bot_keys.values_mut() {
            if existing.bot_id == bot_id
                && existing.revoked_at.is_none()
                && existing.key_id != key_id
            {
                if epoch_was_stale {
                    existing.revoked_at = Some(now);
                } else if existing.retired_at.is_none() {
                    existing.retired_at = Some(grace);
                }
            }
        }
        if epoch_was_stale {
            state.bot_refresh.retain(|_, token| token.bot_id != bot_id);
        }
        state.bot_keys.insert(key_id.clone(), key);
        let summary = BotSummary::from(&bot);
        state.bots.insert(bot_id, bot);
        self.persist_after_mutation(&mut state, previous)?;
        let subject = format!("{}/{}", summary.owner, summary.slug);
        drop(state);
        self.record_bot_audit(
            actor,
            "bot.rotate",
            &subject,
            "completed",
            bot_id,
            Some(&key_id),
            None,
        )?;
        Ok(BotEnrollment {
            bot: summary,
            key_id,
            enrollment_key,
        })
    }

    pub fn suspend_bot(&self, actor: &str, bot_id: Uuid) -> Result<BotSummary> {
        self.set_bot_status(actor, bot_id, BotStatus::Suspended)
    }

    pub fn revoke_bot(&self, actor: &str, bot_id: Uuid) -> Result<BotSummary> {
        let now = Utc::now();
        let mut state = self.state.write();
        let mut bot = owned_bot(&state, actor, bot_id)?;
        let key_id = live_key_id(&state, bot_id);
        let previous = state.clone();
        bot.status = BotStatus::Revoked;
        bot.credential_generation = bot.credential_generation.saturating_add(1);
        bot.updated_at = now;
        let summary = BotSummary::from(&bot);
        state.bots.insert(bot_id, bot);
        for key in state.bot_keys.values_mut() {
            if key.bot_id == bot_id {
                key.revoked_at = Some(now);
            }
        }
        state.bot_refresh.retain(|_, token| token.bot_id != bot_id);
        self.persist_after_mutation(&mut state, previous)?;
        let subject = format!("{}/{}", summary.owner, summary.slug);
        drop(state);
        self.record_bot_audit(
            actor,
            "bot.revoke",
            &subject,
            "completed",
            bot_id,
            key_id.as_deref(),
            None,
        )?;
        Ok(summary)
    }

    /// Exchange an enrollment key for a refresh token. Unknown keys and wrong
    /// secrets return the same error. A failed attempt does not move
    /// `last_successful_access`. Argon2 runs before the write lock is taken.
    pub fn exchange_bot_enrollment_key(&self, enrollment_key: &str) -> Result<BotSession> {
        let Some((env, key_id, secret)) = parse_enrollment_key(enrollment_key) else {
            let _ = verify_secret("invalid", dummy_secret_hash().as_str());
            return invalid();
        };
        let _ = env;
        let verified_hash = {
            let state = self.state.read();
            state
                .bot_keys
                .get(key_id)
                .map(|key| key.secret_hash.clone())
        };
        let Some(verified_hash) = verified_hash else {
            let _ = verify_secret(&secret, dummy_secret_hash().as_str());
            return invalid();
        };
        if verify_secret(&secret, &verified_hash).is_err() {
            return invalid();
        }
        let now = Utc::now();
        let mut state = self.state.write();
        let Some(key) = state.bot_keys.get(key_id).cloned() else {
            return invalid();
        };
        if !same_secret_hash(&key.secret_hash, &verified_hash) || !key_is_live(&key, now) {
            return invalid();
        }
        let Some(bot) = state.bots.get(&key.bot_id).cloned() else {
            return invalid();
        };
        if !bot_account_matches(&state, &bot) {
            return invalid();
        }
        let previous = state.clone();
        let session = issue_refresh(&mut state, &bot, &key, now)?;
        if let Some(stored) = state.bots.get_mut(&bot.id) {
            stored.last_auth = Some(now);
            stored.updated_at = now;
        }
        self.persist_after_mutation(&mut state, previous)?;
        let subject = format!("{}/{}", bot.owner, bot.slug);
        let bot_id = bot.id;
        let audit_key = key.key_id.clone();
        let actor = bot.owner.clone();
        drop(state);
        self.record_bot_audit(
            &actor,
            "bot.token.exchange",
            &subject,
            "completed",
            bot_id,
            Some(&audit_key),
            None,
        )?;
        Ok(session)
    }

    pub fn rotate_bot_refresh_token(&self, refresh_token: &str) -> Result<BotSession> {
        let hash = token_hash(refresh_token);
        let now = Utc::now();
        let mut state = self.state.write();
        let Some(existing) = state.bot_refresh.get(&hash).cloned() else {
            return invalid();
        };
        // Reuse of a token that was already rotated revokes the family. An
        // expired token is only an invalid credential.
        if existing.used_at.is_some() {
            let bot_id = existing.bot_id;
            let key_id = existing.key_id.clone();
            let (actor, subject) = match state.bots.get(&bot_id) {
                Some(bot) => (bot.owner.clone(), format!("{}/{}", bot.owner, bot.slug)),
                None => ("bot".into(), bot_id.to_string()),
            };
            let previous = state.clone();
            revoke_refresh_family(&mut state, bot_id, now);
            self.persist_after_mutation(&mut state, previous)?;
            drop(state);
            self.record_bot_audit(
                &actor,
                "bot.refresh.reuse",
                &subject,
                "failed",
                bot_id,
                Some(&key_id),
                None,
            )?;
            return invalid();
        }
        if existing.expires_at <= now {
            return invalid();
        }
        let Some(bot) = state.bots.get(&existing.bot_id).cloned() else {
            return invalid();
        };
        let Some(key) = state.bot_keys.get(&existing.key_id).cloned() else {
            return invalid();
        };
        if !bot_account_matches(&state, &bot)
            || bot.credential_generation != existing.generation
            || !key_is_live(&key, now)
        {
            return invalid();
        }
        let previous = state.clone();
        if let Some(row) = state.bot_refresh.get_mut(&hash) {
            row.used_at = Some(now);
        }
        let session = issue_refresh(&mut state, &bot, &key, now)?;
        if let Some(stored) = state.bots.get_mut(&bot.id) {
            stored.last_auth = Some(now);
            stored.updated_at = now;
        }
        self.persist_after_mutation(&mut state, previous)?;
        Ok(session)
    }

    /// Confirm the bot, key, generation, and account epoch without a repository.
    /// Repo and task checks stay on [`Self::authorize_bot`].
    pub fn authenticate_bot_access(
        &self,
        bot_id: Uuid,
        generation: u64,
        key_id: &str,
    ) -> Result<BotSummary> {
        let state = self.state.read();
        let bot = state
            .bots
            .get(&bot_id)
            .ok_or_else(|| ForgeError::Validation(INVALID.to_string()))?;
        if !bot_account_matches(&state, bot) || bot.credential_generation != generation {
            return Err(ForgeError::Validation(INVALID.to_string()));
        }
        let live = state
            .bot_keys
            .get(key_id)
            .is_some_and(|key| key.bot_id == bot.id && key_is_live(key, Utc::now()));
        if !live {
            return Err(ForgeError::Validation(INVALID.to_string()));
        }
        Ok(BotSummary::from(bot))
    }

    /// Authorize one bot call.
    ///
    /// `task_kind` and `task_id` are trusted only when the HTTP or MCP edge
    /// copied them from the issue, pull request, or branch being changed. A
    /// client field that repeats the bound task is not enough.
    ///
    /// Repository access is the owner's explicit grant. Forge admin does not
    /// widen it. A public repository still allows a read for any active account.
    pub fn authorize_bot(&self, call: &BotCall) -> Result<BotSummary> {
        let state = self.state.read();
        let bot = state
            .bots
            .get(&call.bot_id)
            .ok_or_else(|| ForgeError::Validation(INVALID.to_string()))?;
        if !bot_account_matches(&state, bot) || bot.credential_generation != call.generation {
            return Err(ForgeError::Validation(INVALID.to_string()));
        }
        let key = state
            .bot_keys
            .get(&call.key_id)
            .filter(|key| key.bot_id == bot.id && key_is_live(key, Utc::now()))
            .ok_or_else(|| ForgeError::Validation(INVALID.to_string()))?;
        let _ = key;
        let can_read = owner_grant_allows(&state, &bot.owner, &call.owner, &call.repo, false);
        let can_write = owner_grant_allows(&state, &bot.owner, &call.owner, &call.repo, true);
        let denied = if call.effect == BotEffect::Write && !can_write {
            Some(if can_read {
                "insufficient_scope"
            } else {
                "repo_not_granted"
            })
        } else if call.effect == BotEffect::Read && !can_read {
            Some("repo_not_granted")
        } else if !reach_allows(&bot.reach, call) {
            Some(reach_denial_code(&bot.reach, call))
        } else {
            None
        };
        if let Some(code) = denied {
            let owner = bot.owner.clone();
            let slug = bot.slug.clone();
            let bot_id = bot.id;
            let key_id = call.key_id.clone();
            drop(state);
            self.record_bot_audit(
                &owner,
                "bot.authorize",
                &format!("{owner}/{slug}"),
                "failed",
                bot_id,
                Some(&key_id),
                Some(code),
            )?;
            return Err(explain_bot(ForgeError::Forbidden(code.to_string())));
        }
        Ok(BotSummary::from(bot))
    }

    pub fn note_bot_observation(&self, bot_id: Uuid, observation: BotObservation) -> Result<()> {
        require_name("action", &observation.action)?;
        if observation_contains_secret(&observation) {
            return Err(ForgeError::Validation(
                "observation must not contain a bot credential".to_string(),
            ));
        }
        let now = Utc::now();
        let mut state = self.state.write();
        let Some(bot) = state.bots.get(&bot_id).cloned() else {
            return Err(ForgeError::NotFound(format!("bot {bot_id}")));
        };
        if observation.heartbeat {
            // The window is anchored on the last persisted heartbeat. Moving
            // that timestamp without a write would keep every later beat inside
            // the window.
            if bot
                .last_heartbeat
                .is_some_and(|previous| within_coalesce(now, previous))
            {
                return Ok(());
            }
            let previous = state.clone();
            if let Some(stored) = state.bots.get_mut(&bot_id) {
                stored.last_heartbeat = Some(now);
            }
            return self.persist_after_mutation(&mut state, previous);
        }
        let same_outcome = bot.last_outcome.as_deref() == Some(observation.outcome.as_str());
        if same_outcome && within_coalesce(now, bot.updated_at) {
            if let Some(stored) = state.bots.get_mut(&bot_id) {
                stored.last_action = Some(observation.action);
                stored.last_repo = observation.repo;
                if observation.success {
                    stored.last_successful_access = Some(now);
                    stored.last_auth = Some(now);
                }
                if observation.mutation {
                    stored.last_mutation = Some(now);
                }
            }
            return Ok(());
        }
        let previous = state.clone();
        if let Some(stored) = state.bots.get_mut(&bot_id) {
            stored.last_action = Some(observation.action.clone());
            stored.last_outcome = Some(observation.outcome.clone());
            stored.last_repo = observation.repo.clone();
            stored.updated_at = now;
            if observation.success {
                stored.last_successful_access = Some(now);
                stored.last_auth = Some(now);
            }
            if observation.mutation {
                stored.last_mutation = Some(now);
            }
        }
        state.bot_activity.push(BotActivityEvent {
            id: Uuid::new_v4(),
            bot_id,
            key_id: observation.key_id,
            repo: observation.repo,
            session_id: observation.session_id,
            action: observation.action,
            outcome: observation.outcome,
            scope: observation.scope,
            created_at: now,
        });
        let cutoff = now - Duration::days(ACTIVITY_TTL_DAYS);
        state
            .bot_activity
            .retain(|event| event.bot_id != bot.id || event.created_at >= cutoff);
        cap_bot_activity(&mut state.bot_activity, bot.id);
        self.persist_after_mutation(&mut state, previous)
    }

    pub fn list_bot_activity(&self, actor: &str, bot_id: Uuid) -> Result<Vec<BotActivityEvent>> {
        self.owned_summary(actor, bot_id)?;
        let mut events: Vec<_> = self
            .state
            .read()
            .bot_activity
            .iter()
            .filter(|event| event.bot_id == bot_id)
            .cloned()
            .collect();
        events.sort_by_key(|event| event.created_at);
        Ok(events)
    }

    pub fn list_repository_bot_activity(
        &self,
        actor: &str,
        owner: &str,
        repo: &str,
    ) -> Result<Vec<BotActivityEvent>> {
        self.canonical_repository(owner, repo)?;
        if !self.user_can_write_repo(actor, owner, repo) {
            return Err(ForgeError::Forbidden(
                "repo write access required".to_string(),
            ));
        }
        let full_name = format!("{owner}/{repo}");
        let mut events: Vec<_> = self
            .state
            .read()
            .bot_activity
            .iter()
            .filter(|event| event.repo.as_deref() == Some(full_name.as_str()))
            .cloned()
            .collect();
        events.sort_by_key(|event| event.created_at);
        Ok(events)
    }

    pub fn reserve_bot_operation(
        &self,
        bot_id: Uuid,
        operation: &str,
        request_key: &str,
        body_digest: &str,
    ) -> Result<BotOperationGate> {
        require_name("operation", operation)?;
        require_name("request key", request_key)?;
        if body_digest.len() != 64 || !body_digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ForgeError::Validation(
                "operation digest must be 64 hex characters".to_string(),
            ));
        }
        let now = Utc::now();
        let mut state = self.state.write();
        if !state.bots.contains_key(&bot_id) {
            return Err(ForgeError::NotFound(format!("bot {bot_id}")));
        }
        let previous = state.clone();
        let cutoff = now - Duration::hours(OPERATION_TTL_HOURS);
        state
            .bot_operations
            .retain(|_, record| record.created_at >= cutoff);
        let map_key = (bot_id, operation.to_string(), request_key.to_string());
        if let Some(existing) = state.bot_operations.get(&map_key) {
            if existing.body_digest != body_digest {
                *state = previous;
                return Err(ForgeError::Conflict("idempotency_conflict".to_string()));
            }
            let gate = match &existing.result_json {
                Some(result) => BotOperationGate::Replay {
                    result_json: result.clone(),
                },
                None => BotOperationGate::InProgress,
            };
            return Ok(gate);
        }
        state.bot_operations.insert(
            map_key,
            BotOperationRecord {
                bot_id,
                operation: operation.to_string(),
                request_key: request_key.to_string(),
                body_digest: body_digest.to_string(),
                result_json: None,
                created_at: now,
            },
        );
        self.persist_after_mutation(&mut state, previous)?;
        Ok(BotOperationGate::Start)
    }

    pub fn finish_bot_operation(
        &self,
        bot_id: Uuid,
        operation: &str,
        request_key: &str,
        result_json: &str,
    ) -> Result<()> {
        serde_json::from_str::<serde_json::Value>(result_json)
            .map_err(|_| ForgeError::Validation("operation result must be json".to_string()))?;
        let mut state = self.state.write();
        let map_key = (bot_id, operation.to_string(), request_key.to_string());
        let Some(existing) = state.bot_operations.get(&map_key) else {
            return Err(ForgeError::NotFound("bot operation".to_string()));
        };
        if existing.result_json.is_some() {
            return Err(ForgeError::Conflict(
                "bot operation already finished".to_string(),
            ));
        }
        let previous = state.clone();
        if let Some(record) = state.bot_operations.get_mut(&map_key) {
            record.result_json = Some(result_json.to_string());
        }
        self.persist_after_mutation(&mut state, previous)
    }

    #[cfg(test)]
    pub fn force_bot_key_retired(&self, key_id: &str) {
        let mut state = self.state.write();
        if let Some(key) = state.bot_keys.get_mut(key_id) {
            key.retired_at = Some(Utc::now() - Duration::seconds(1));
        }
    }

    #[cfg(test)]
    pub fn force_bot_activity_window_elapsed(&self, bot_id: Uuid) {
        let mut state = self.state.write();
        let Some(bot) = state.bots.get_mut(&bot_id) else {
            return;
        };
        let shift = Duration::seconds(ACTIVITY_COALESCE_SECS + 1);
        bot.updated_at -= shift;
        if let Some(beat) = bot.last_heartbeat.as_mut() {
            *beat -= shift;
        }
    }

    #[cfg(test)]
    pub fn force_bot_refresh_expired(&self, refresh_token: &str) {
        let hash = token_hash(refresh_token);
        let mut state = self.state.write();
        if let Some(token) = state.bot_refresh.get_mut(&hash) {
            token.expires_at = Utc::now() - Duration::seconds(1);
        }
    }

    fn set_bot_status(&self, actor: &str, bot_id: Uuid, status: BotStatus) -> Result<BotSummary> {
        let mut state = self.state.write();
        let mut bot = owned_bot(&state, actor, bot_id)?;
        if bot.status == BotStatus::Revoked {
            return Err(ForgeError::NotFound(format!("bot {bot_id}")));
        }
        let key_id = live_key_id(&state, bot_id);
        let previous = state.clone();
        bot.status = status;
        bot.updated_at = Utc::now();
        let summary = BotSummary::from(&bot);
        state.bots.insert(bot_id, bot);
        self.persist_after_mutation(&mut state, previous)?;
        let subject = format!("{}/{}", summary.owner, summary.slug);
        let action = match status {
            BotStatus::Suspended => "bot.suspend",
            BotStatus::Revoked => "bot.revoke",
            BotStatus::Active => "bot.activate",
        };
        drop(state);
        self.record_bot_audit(
            actor,
            action,
            &subject,
            "completed",
            bot_id,
            key_id.as_deref(),
            None,
        )?;
        Ok(summary)
    }

    fn record_bot_audit(
        &self,
        actor: &str,
        action: &str,
        subject: &str,
        phase: &str,
        bot_id: Uuid,
        key_id: Option<&str>,
        code: Option<&str>,
    ) -> Result<()> {
        let mut detail = serde_json::Map::new();
        detail.insert(
            "bot_id".to_string(),
            serde_json::Value::String(bot_id.to_string()),
        );
        if let Some(key_id) = key_id {
            detail.insert(
                "key_id".to_string(),
                serde_json::Value::String(key_id.to_string()),
            );
        }
        if let Some(code) = code {
            detail.insert(
                "code".to_string(),
                serde_json::Value::String(code.to_string()),
            );
        }
        let detail = serde_json::Value::Object(detail);
        let rendered = detail.to_string();
        if rendered.contains("jbk_") || rendered.contains("jbr_") || rendered.contains("eyJ") {
            return Err(ForgeError::Validation(
                "audit detail must not contain a bot credential".to_string(),
            ));
        }
        self.append_audit_as(actor, action, subject, phase, detail)?;
        Ok(())
    }

    fn active_account(&self, actor: &str) -> Result<AccountSummary> {
        let account = self.get_account(actor)?;
        if !account.status.permits_authentication() {
            return Err(ForgeError::Validation("account is not active".to_string()));
        }
        Ok(account)
    }

    fn owned_summary(&self, actor: &str, bot_id: Uuid) -> Result<BotSummary> {
        let state = self.state.read();
        let bot = owned_bot(&state, actor, bot_id)?;
        Ok(BotSummary::from(&bot))
    }

    fn normalize_reach(&self, actor: &str, reach: BotReach) -> Result<BotReach> {
        match reach {
            BotReach::General => Ok(BotReach::General),
            BotReach::Repositories { repos } => {
                if repos.is_empty() || repos.len() > MAX_REPOS {
                    return Err(ForgeError::Validation(
                        "repository reach needs between 1 and 100 repositories".to_string(),
                    ));
                }
                let mut seen = Vec::new();
                for repo in repos {
                    let normalized = self.require_readable_repo(actor, &repo.owner, &repo.name)?;
                    if !seen.contains(&normalized) {
                        seen.push(normalized);
                    }
                }
                Ok(BotReach::Repositories { repos: seen })
            }
            BotReach::Task {
                repo,
                task_kind,
                task_id,
            } => {
                let repo = self.require_readable_repo(actor, &repo.owner, &repo.name)?;
                validate_task(self, &repo, task_kind, &task_id)?;
                Ok(BotReach::Task {
                    repo,
                    task_kind,
                    task_id: task_id.trim().to_string(),
                })
            }
        }
    }

    fn require_readable_repo(&self, actor: &str, owner: &str, repo: &str) -> Result<BotRepoRef> {
        self.canonical_repository(owner, repo)?;
        let allowed = {
            let state = self.state.read();
            owner_grant_allows(&state, actor, owner, repo, false)
        };
        if !allowed {
            return Err(ForgeError::Validation(
                "reach cannot grant a repository the account cannot access".to_string(),
            ));
        }
        Ok(BotRepoRef {
            owner: owner.to_string(),
            name: repo.to_string(),
        })
    }
}

/// Drop refresh tokens and bump generation for every bot owned by `login`.
/// Enrollment keys are revoked. `auth_epoch` stays stale until the owner rotates.
pub(super) fn invalidate_account_bots(state: &mut super::State, login: &str, now: DateTime<Utc>) {
    let ids: Vec<Uuid> = state
        .bots
        .values()
        .filter(|bot| bot.owner == login)
        .map(|bot| bot.id)
        .collect();
    for id in &ids {
        if let Some(bot) = state.bots.get_mut(id) {
            bot.credential_generation = bot.credential_generation.saturating_add(1);
            bot.updated_at = now;
        }
    }
    for key in state.bot_keys.values_mut() {
        if ids.contains(&key.bot_id) && key.revoked_at.is_none() {
            key.revoked_at = Some(now);
        }
    }
    state
        .bot_refresh
        .retain(|_, token| !ids.contains(&token.bot_id));
}

fn owned_bot(state: &super::State, actor: &str, bot_id: Uuid) -> Result<BotRecord> {
    match state.bots.get(&bot_id) {
        Some(bot) if bot.owner == actor => Ok(bot.clone()),
        _ => Err(ForgeError::NotFound(format!("bot {bot_id}"))),
    }
}

fn reach_lists_repo(state: &super::State, bot: &BotRecord, owner: &str, repo: &str) -> bool {
    match &bot.reach {
        BotReach::General => owner_grant_allows(state, &bot.owner, owner, repo, false),
        BotReach::Repositories { repos } => repos
            .iter()
            .any(|item| item.owner == owner && item.name == repo),
        BotReach::Task { repo: bound, .. } => bound.owner == owner && bound.name == repo,
    }
}

/// Roster viewers learn only this repository. General reach names no other repo.
fn clip_reach(reach: &BotReach, owner: &str, repo: &str) -> BotReach {
    match reach {
        BotReach::Repositories { repos } => BotReach::Repositories {
            repos: repos
                .iter()
                .filter(|item| item.owner == owner && item.name == repo)
                .cloned()
                .collect(),
        },
        other => other.clone(),
    }
}

/// Explicit repository grant, plus a public read for any active account.
/// Forge admin is not a grant.
fn owner_grant_allows(
    state: &super::State,
    login: &str,
    owner: &str,
    repo: &str,
    write: bool,
) -> bool {
    let Some(account) = state.accounts.get(login) else {
        return false;
    };
    if !account.status.permits_authentication() {
        return false;
    }
    let Some(repo_row) = state.repos.get(&(owner.to_string(), repo.to_string())) else {
        return false;
    };
    if !write && !repo_row.private {
        return true;
    }
    let Some(grant) =
        state
            .repo_grants
            .get(&(login.to_string(), owner.to_string(), repo.to_string()))
    else {
        return false;
    };
    if write {
        grant.access.allows_write()
    } else {
        grant.access.allows_read()
    }
}

fn bot_account_matches(state: &super::State, bot: &BotRecord) -> bool {
    if bot.status != BotStatus::Active {
        return false;
    }
    state.accounts.get(&bot.owner).is_some_and(|account| {
        account.status.permits_authentication() && account.auth_epoch == bot.auth_epoch
    })
}

fn within_coalesce(now: DateTime<Utc>, then: DateTime<Utc>) -> bool {
    now.signed_duration_since(then) < Duration::seconds(ACTIVITY_COALESCE_SECS)
}

fn live_key_id(state: &super::State, bot_id: Uuid) -> Option<String> {
    state
        .bot_keys
        .values()
        .filter(|key| key.bot_id == bot_id && key.revoked_at.is_none())
        .max_by_key(|key| key.created_at)
        .map(|key| key.key_id.clone())
}

/// Events are appended in time order, so the prefix for one bot is the oldest.
fn cap_bot_activity(events: &mut Vec<BotActivityEvent>, bot_id: Uuid) {
    let count = events.iter().filter(|event| event.bot_id == bot_id).count();
    if count <= ACTIVITY_CAP {
        return;
    }
    let mut drop_remaining = count - ACTIVITY_CAP;
    events.retain(|event| {
        if event.bot_id != bot_id || drop_remaining == 0 {
            return true;
        }
        drop_remaining -= 1;
        false
    });
}

fn reach_denial_code(reach: &BotReach, call: &BotCall) -> &'static str {
    let wrong_task = match reach {
        BotReach::Task { repo, .. } => {
            call.effect == BotEffect::Write && repo.owner == call.owner && repo.name == call.repo
        }
        _ => false,
    };
    if wrong_task {
        "task_not_granted"
    } else {
        "repo_not_granted"
    }
}

fn observation_contains_secret(observation: &BotObservation) -> bool {
    let fields = [
        observation.action.as_str(),
        observation.outcome.as_str(),
        observation.scope.as_str(),
        observation.repo.as_deref().unwrap_or(""),
        observation.session_id.as_deref().unwrap_or(""),
    ];
    fields
        .iter()
        .any(|field| field.contains("jbk_") || field.contains("jbr_"))
}

fn same_secret_hash(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        diff |= left_byte ^ right_byte;
    }
    diff == 0
}

fn reach_allows(reach: &BotReach, call: &BotCall) -> bool {
    match reach {
        BotReach::General => true,
        BotReach::Repositories { repos } => repos
            .iter()
            .any(|repo| repo.owner == call.owner && repo.name == call.repo),
        BotReach::Task {
            repo,
            task_kind,
            task_id,
        } => {
            if repo.owner != call.owner || repo.name != call.repo {
                return false;
            }
            if call.effect == BotEffect::Read {
                return true;
            }
            call.task_kind == Some(*task_kind) && call.task_id.as_deref() == Some(task_id.as_str())
        }
    }
}

fn validate_task(
    core: &ForgeCore,
    repo: &BotRepoRef,
    kind: BotTaskKind,
    task_id: &str,
) -> Result<()> {
    let task_id = task_id.trim();
    if task_id.is_empty() {
        return Err(ForgeError::Validation(
            "task id cannot be empty".to_string(),
        ));
    }
    match kind {
        BotTaskKind::Issue | BotTaskKind::Pull => {
            let number: u64 = task_id.parse().map_err(|_| {
                ForgeError::Validation("issue or pull task id must be a number".to_string())
            })?;
            if kind == BotTaskKind::Issue {
                core.get_issue(&repo.owner, &repo.name, number)?;
            } else {
                core.get_pull_request(&repo.owner, &repo.name, number)?;
            }
        }
        BotTaskKind::Branch => {
            if task_id.contains(char::is_whitespace)
                || task_id.contains("..")
                || task_id.contains('/') && task_id.starts_with('/')
            {
                return Err(ForgeError::Validation(
                    "branch task id must be a single branch name".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn issue_refresh(
    state: &mut super::State,
    bot: &BotRecord,
    key: &BotKeyRecord,
    now: DateTime<Utc>,
) -> Result<BotSession> {
    let refresh_token = format!("jbr_{}", new_secret()?);
    let record = BotRefreshRecord {
        token_hash: token_hash(&refresh_token),
        bot_id: bot.id,
        key_id: key.key_id.clone(),
        generation: bot.credential_generation,
        expires_at: now + Duration::hours(REFRESH_TTL_HOURS),
        used_at: None,
    };
    state
        .bot_refresh
        .insert(record.token_hash.clone(), record.clone());
    cap_live_refresh(state, bot.id, now);
    Ok(BotSession {
        bot: BotSummary::from(bot),
        key_id: key.key_id.clone(),
        generation: bot.credential_generation,
        refresh_token,
        refresh_expires_at: record.expires_at,
    })
}

fn cap_live_refresh(state: &mut super::State, bot_id: Uuid, now: DateTime<Utc>) {
    state
        .bot_refresh
        .retain(|_, token| token.bot_id != bot_id || token.expires_at > now);
    let mut live: Vec<_> = state
        .bot_refresh
        .iter()
        .filter(|(_, token)| token.bot_id == bot_id && token.used_at.is_none())
        .map(|(hash, token)| (hash.clone(), token.expires_at))
        .collect();
    if live.len() <= MAX_LIVE_REFRESH {
        return;
    }
    live.sort_by_key(|(_, expires_at)| *expires_at);
    let excess = live.len() - MAX_LIVE_REFRESH;
    for (hash, _) in live.into_iter().take(excess) {
        state.bot_refresh.remove(&hash);
    }
}

fn revoke_refresh_family(state: &mut super::State, bot_id: Uuid, now: DateTime<Utc>) {
    state.bot_refresh.retain(|_, token| token.bot_id != bot_id);
    if let Some(bot) = state.bots.get_mut(&bot_id) {
        bot.credential_generation = bot.credential_generation.saturating_add(1);
        bot.updated_at = now;
    }
}

fn key_is_live(key: &BotKeyRecord, now: DateTime<Utc>) -> bool {
    key.revoked_at.is_none() && key.retired_at.is_none_or(|retired| retired > now)
}

fn parse_enrollment_key(value: &str) -> Option<(&str, &str, &str)> {
    if value.len() > 180 {
        return None;
    }
    let (env, rest) = value.split_once('.')?;
    if env != KEY_PREFIX_LIVE && env != KEY_PREFIX_TEST {
        return None;
    }
    let (key_id, secret) = rest.split_once('.')?;
    if key_id.len() != 12 || secret.len() < 32 {
        return None;
    }
    Some((env, key_id, secret))
}

fn invalid() -> Result<BotSession> {
    Err(explain_bot(ForgeError::Validation(INVALID.to_string())))
}

fn new_key_id() -> Result<String> {
    let mut id = String::with_capacity(12);
    while id.len() < 12 {
        let mut byte = [0u8; 1];
        OsRng
            .try_fill_bytes(&mut byte)
            .map_err(|err| explain_bot(ForgeError::Storage(format!("read randomness: {err}"))))?;
        id.push(CROCKFORD[(byte[0] % 32) as usize] as char);
    }
    Ok(id)
}

fn new_secret() -> Result<String> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|err| ForgeError::Storage(format!("read randomness: {err}")))?;
    Ok(base64url(&bytes))
}

fn base64url(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let chunk = ((bytes[index] as u32) << 16)
            | ((bytes[index + 1] as u32) << 8)
            | bytes[index + 2] as u32;
        out.push(TABLE[((chunk >> 18) & 63) as usize] as char);
        out.push(TABLE[((chunk >> 12) & 63) as usize] as char);
        out.push(TABLE[((chunk >> 6) & 63) as usize] as char);
        out.push(TABLE[(chunk & 63) as usize] as char);
        index += 3;
    }
    if index < bytes.len() {
        let mut chunk = (bytes[index] as u32) << 16;
        if index + 1 < bytes.len() {
            chunk |= (bytes[index + 1] as u32) << 8;
        }
        out.push(TABLE[((chunk >> 18) & 63) as usize] as char);
        out.push(TABLE[((chunk >> 12) & 63) as usize] as char);
        if index + 1 < bytes.len() {
            out.push(TABLE[((chunk >> 6) & 63) as usize] as char);
        }
    }
    out
}

fn argon() -> Result<Argon2<'static>> {
    let params = Params::new(19_456, 2, 1, None)
        .map_err(|err| ForgeError::Storage(format!("argon2 params: {err}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn hash_secret(secret: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    argon()?
        .hash_password(secret.as_bytes(), &salt)
        .map_err(|err| ForgeError::Storage(format!("hash bot secret: {err}")))
        .map(|hash| hash.to_string())
}

fn verify_secret(secret: &str, secret_hash: &str) -> Result<()> {
    let parsed =
        PasswordHash::new(secret_hash).map_err(|_| ForgeError::Validation(INVALID.to_string()))?;
    argon()?
        .verify_password(secret.as_bytes(), &parsed)
        .map_err(|_| ForgeError::Validation(INVALID.to_string()))
}

fn dummy_secret_hash() -> &'static String {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash_secret("dummy-bot-secret").expect("dummy bot hash"))
}

fn token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        CreateIssueRequest, CreatePullRequestRequest, CreateRepositoryRequest, RepoAccessLevel,
        UserRole,
    };

    #[test]
    fn bot_failures_name_a_repair_for_each_exception() {
        let cases = [
            (
                BotFailure::InvalidEnrollment,
                "slug",
                "login-shaped",
                "docs/errors.md#bot-enrollment",
            ),
            (
                BotFailure::InvalidCredential,
                "enrollment key",
                "refresh token",
                "docs/errors.md#bot-credential",
            ),
            (
                BotFailure::Conflict,
                "slug",
                "idempotency",
                "docs/errors.md#bot-conflict",
            ),
            (
                BotFailure::NotGranted,
                "repository",
                "forge admin",
                "docs/errors.md#bot-reach",
            ),
            (
                BotFailure::Missing,
                "revoked",
                "roster",
                "docs/errors.md#bot-missing",
            ),
            (
                BotFailure::Storage,
                "Argon2id",
                "hash fails",
                "docs/errors.md#bot-storage",
            ),
        ];
        let mut reasons = Vec::new();
        for (failure, reason_word, fix_word, docs_url) in cases {
            let repair = failure.repair();
            assert!(!repair.purpose.is_empty(), "{failure:?} purpose");
            assert!(
                repair.reason.contains(reason_word),
                "{failure:?} reason {:?}",
                repair.reason
            );
            assert!(
                repair.common_fixes.contains(fix_word),
                "{failure:?} common fixes {:?}",
                repair.common_fixes
            );
            assert_eq!(repair.docs_url, docs_url);
            assert!(
                repair.repair_hint.contains("core::bots::tests"),
                "{failure:?} repair_hint"
            );
            assert!(!repair.reason.contains("waitlist"));
            assert!(!repair.common_fixes.contains("jbk_"));
            assert!(!repair.repair_hint.contains("jbr_"));
            reasons.push(repair.reason);
        }
        reasons.sort_unstable();
        reasons.dedup();
        assert_eq!(reasons.len(), 6);

        assert_eq!(
            BotFailure::classify(&ForgeError::Validation(INVALID.to_string())),
            BotFailure::InvalidCredential
        );
        assert_eq!(
            BotFailure::classify(&ForgeError::Validation(
                "display name may not exceed 80 characters".to_string()
            )),
            BotFailure::InvalidEnrollment
        );
        assert_eq!(
            BotFailure::classify(&ForgeError::Validation("account is not active".to_string())),
            BotFailure::InvalidEnrollment
        );
        assert_eq!(
            BotFailure::classify(&ForgeError::Conflict("idempotency_conflict".to_string())),
            BotFailure::Conflict
        );
        assert_eq!(
            BotFailure::classify(&ForgeError::Forbidden("repo_not_granted".to_string())),
            BotFailure::NotGranted
        );
        assert_eq!(
            BotFailure::classify(&ForgeError::Forbidden("task_not_granted".to_string())),
            BotFailure::NotGranted
        );
        assert_eq!(
            BotFailure::classify(&ForgeError::Forbidden("insufficient_scope".to_string())),
            BotFailure::NotGranted
        );
        assert_eq!(
            BotFailure::classify(&ForgeError::NotFound("bot missing".to_string())),
            BotFailure::Missing
        );
        assert_eq!(
            BotFailure::classify(&ForgeError::Storage("read randomness: closed".to_string())),
            BotFailure::Storage
        );
        assert_eq!(
            explain_bot(ForgeError::Validation(INVALID.to_string())),
            ForgeError::Validation(INVALID.to_string())
        );
    }

    const PASSWORD: &str = "correct-horse-battery";

    fn fixture() -> (ForgeCore, String) {
        let core = ForgeCore::new();
        core.create_account("alice", PASSWORD, UserRole::User)
            .unwrap();
        core.create_repository(
            "alice",
            CreateRepositoryRequest {
                name: "widgets".to_string(),
                private: true,
                description: None,
                default_branch: Some("main".to_string()),
            },
        )
        .unwrap();
        core.create_repository(
            "alice",
            CreateRepositoryRequest {
                name: "other".to_string(),
                private: true,
                description: None,
                default_branch: Some("main".to_string()),
            },
        )
        .unwrap();
        core.grant_repo_access("alice", "alice", "alice", "widgets", RepoAccessLevel::Write)
            .unwrap();
        let issue = core
            .create_issue(
                "alice",
                "widgets",
                "alice",
                CreateIssueRequest {
                    title: "Fix the gate".to_string(),
                    body: None,
                    labels: Vec::new(),
                    assignees: Vec::new(),
                    milestone: None,
                },
            )
            .unwrap();
        (core, issue.number.to_string())
    }

    fn enroll(core: &ForgeCore, slug: &str, reach: BotReach) -> BotEnrollment {
        core.enroll_bot("alice", slug, slug, BotKind::Grok, reach)
            .unwrap()
    }

    #[test]
    fn many_bots_keep_separate_keys_and_kinds() {
        let (core, _) = fixture();
        let grok = enroll(&core, "atlas", BotReach::General);
        let muse = core
            .enroll_bot(
                "alice",
                "reviewer",
                "Reviewer",
                BotKind::Muse,
                BotReach::General,
            )
            .unwrap();
        assert_ne!(grok.key_id, muse.key_id);
        assert!(grok.enrollment_key.starts_with("jbk_live."));
        assert_eq!(grok.bot.kind.label(), "Grokbot");
        assert_eq!(muse.bot.kind.label(), "Musebot");
        let listed = core.list_account_bots("alice").unwrap();
        assert_eq!(listed.len(), 2);
        assert!(
            core.enroll_bot("alice", "atlas", "Atlas", BotKind::Grok, BotReach::General)
                .is_err()
        );
        let debug = format!("{:?}", grok);
        assert!(!debug.contains(&grok.enrollment_key));
    }

    #[test]
    fn unknown_and_wrong_enrollment_keys_are_the_same_error() {
        let (core, _) = fixture();
        let enrolled = enroll(&core, "atlas", BotReach::General);
        let unknown =
            core.exchange_bot_enrollment_key("jbk_live.abcdefghjkmn.not-a-real-secret-value");
        let mut parts = enrolled.enrollment_key.split('.');
        let env = parts.next().unwrap();
        let key_id = parts.next().unwrap();
        let wrong = core.exchange_bot_enrollment_key(&format!(
            "{env}.{key_id}.wrong-secret-value-with-enough-length"
        ));
        match (unknown, wrong) {
            (Err(ForgeError::Validation(left)), Err(ForgeError::Validation(right))) => {
                assert_eq!(left, right);
                assert_eq!(left, INVALID);
            }
            other => panic!("expected matching validation errors, got {other:?}"),
        }
        assert!(
            core.list_account_bots("alice").unwrap()[0]
                .last_successful_access
                .is_none()
        );
    }

    #[test]
    fn reach_cannot_grant_a_repository_the_account_cannot_access() {
        let (core, _) = fixture();
        let denied = core.enroll_bot(
            "alice",
            "sneak",
            "Sneak",
            BotKind::Muse,
            BotReach::Repositories {
                repos: vec![BotRepoRef {
                    owner: "alice".to_string(),
                    name: "other".to_string(),
                }],
            },
        );
        assert!(
            matches!(denied, Err(ForgeError::Validation(message)) if message.contains("cannot access"))
        );
    }

    #[test]
    fn general_repo_and_task_reach_follow_the_owner() {
        let (core, issue) = fixture();
        let general = enroll(&core, "general", BotReach::General);
        let listed = enroll(
            &core,
            "listed",
            BotReach::Repositories {
                repos: vec![BotRepoRef {
                    owner: "alice".to_string(),
                    name: "widgets".to_string(),
                }],
            },
        );
        let task = enroll(
            &core,
            "tasked",
            BotReach::Task {
                repo: BotRepoRef {
                    owner: "alice".to_string(),
                    name: "widgets".to_string(),
                },
                task_kind: BotTaskKind::Issue,
                task_id: issue.clone(),
            },
        );
        let session = core
            .exchange_bot_enrollment_key(&general.enrollment_key)
            .unwrap();
        let widgets = BotCall {
            bot_id: session.bot.id,
            generation: session.generation,
            key_id: session.key_id.clone(),
            owner: "alice".to_string(),
            repo: "widgets".to_string(),
            effect: BotEffect::Write,
            task_kind: None,
            task_id: None,
        };
        assert!(core.authorize_bot(&widgets).is_ok());
        let other = BotCall {
            repo: "other".to_string(),
            ..widgets.clone()
        };
        assert!(matches!(
            core.authorize_bot(&other),
            Err(ForgeError::Forbidden(code)) if code == "repo_not_granted"
        ));
        core.grant_repo_access("alice", "alice", "alice", "other", RepoAccessLevel::Read)
            .unwrap();
        assert!(core.authorize_bot(&other).is_ok() == false);
        let read_other = BotCall {
            effect: BotEffect::Read,
            ..other
        };
        assert!(core.authorize_bot(&read_other).is_ok());

        let listed_session = core
            .exchange_bot_enrollment_key(&listed.enrollment_key)
            .unwrap();
        let listed_other = BotCall {
            bot_id: listed_session.bot.id,
            generation: listed_session.generation,
            key_id: listed_session.key_id,
            effect: BotEffect::Read,
            ..read_other.clone()
        };
        assert!(matches!(
            core.authorize_bot(&listed_other),
            Err(ForgeError::Forbidden(code)) if code == "repo_not_granted"
        ));

        let task_session = core
            .exchange_bot_enrollment_key(&task.enrollment_key)
            .unwrap();
        let task_read = BotCall {
            bot_id: task_session.bot.id,
            generation: task_session.generation,
            key_id: task_session.key_id.clone(),
            owner: "alice".to_string(),
            repo: "widgets".to_string(),
            effect: BotEffect::Read,
            task_kind: None,
            task_id: None,
        };
        assert!(core.authorize_bot(&task_read).is_ok());
        let task_write = BotCall {
            effect: BotEffect::Write,
            task_kind: Some(BotTaskKind::Issue),
            task_id: Some(issue),
            ..task_read.clone()
        };
        assert!(core.authorize_bot(&task_write).is_ok());
        let wrong_task = BotCall {
            task_id: Some("999".to_string()),
            ..task_write
        };
        assert!(matches!(
            core.authorize_bot(&wrong_task),
            Err(ForgeError::Forbidden(code)) if code == "task_not_granted"
        ));

        let roster = core
            .list_repository_bots("alice", "alice", "widgets")
            .unwrap();
        assert_eq!(roster.len(), 3);
        assert!(roster.iter().any(|bot| bot.kind == BotKind::Grok));
    }

    #[test]
    fn reused_refresh_token_revokes_the_family() {
        let (core, _) = fixture();
        let enrolled = enroll(&core, "atlas", BotReach::General);
        let first = core
            .exchange_bot_enrollment_key(&enrolled.enrollment_key)
            .unwrap();
        let second = core.rotate_bot_refresh_token(&first.refresh_token).unwrap();
        assert_ne!(first.refresh_token, second.refresh_token);
        assert!(core.rotate_bot_refresh_token(&first.refresh_token).is_err());
        assert!(
            core.rotate_bot_refresh_token(&second.refresh_token)
                .is_err()
        );
        let renewed = core
            .exchange_bot_enrollment_key(&enrolled.enrollment_key)
            .unwrap();
        assert!(renewed.generation > first.generation);
        let stale = BotCall {
            bot_id: first.bot.id,
            generation: first.generation,
            key_id: first.key_id,
            owner: "alice".to_string(),
            repo: "widgets".to_string(),
            effect: BotEffect::Read,
            task_kind: None,
            task_id: None,
        };
        assert!(core.authorize_bot(&stale).is_err());
        let fresh = BotCall {
            generation: renewed.generation,
            key_id: renewed.key_id,
            ..stale
        };
        assert!(core.authorize_bot(&fresh).is_ok());
    }

    #[test]
    fn rotation_grace_then_retirement_and_revoke() {
        let (core, _) = fixture();
        let enrolled = enroll(&core, "atlas", BotReach::General);
        let rotated = core.rotate_bot_key("alice", enrolled.bot.id).unwrap();
        assert!(
            core.exchange_bot_enrollment_key(&enrolled.enrollment_key)
                .is_ok()
        );
        assert!(
            core.exchange_bot_enrollment_key(&rotated.enrollment_key)
                .is_ok()
        );
        core.force_bot_key_retired(&enrolled.key_id);
        assert!(
            core.exchange_bot_enrollment_key(&enrolled.enrollment_key)
                .is_err()
        );
        core.revoke_bot("alice", enrolled.bot.id).unwrap();
        assert!(
            core.exchange_bot_enrollment_key(&rotated.enrollment_key)
                .is_err()
        );
    }

    #[test]
    fn observation_keeps_secrets_out_of_activity_and_failed_auth_does_not_count() {
        let (core, _) = fixture();
        let enrolled = enroll(&core, "atlas", BotReach::General);
        core.note_bot_observation(
            enrolled.bot.id,
            BotObservation {
                key_id: enrolled.key_id.clone(),
                action: "whoami".to_string(),
                outcome: "ok".to_string(),
                scope: "general".to_string(),
                repo: Some("alice/widgets".to_string()),
                session_id: None,
                success: true,
                mutation: false,
                heartbeat: false,
            },
        )
        .unwrap();
        let events = core.list_bot_activity("alice", enrolled.bot.id).unwrap();
        let rendered = format!("{events:?}");
        assert!(!rendered.contains(&enrolled.enrollment_key));
        assert!(!rendered.contains("jbk_"));
        assert!(
            core.list_account_bots("alice").unwrap()[0]
                .last_successful_access
                .is_some()
        );
    }

    #[test]
    fn idempotent_operation_replays_and_rejects_a_different_body() {
        let (core, _) = fixture();
        let enrolled = enroll(&core, "atlas", BotReach::General);
        let digest = "ab".repeat(32);
        assert!(matches!(
            core.reserve_bot_operation(enrolled.bot.id, "session.start", "k1", &digest)
                .unwrap(),
            BotOperationGate::Start
        ));
        assert!(matches!(
            core.reserve_bot_operation(enrolled.bot.id, "session.start", "k1", &digest)
                .unwrap(),
            BotOperationGate::InProgress
        ));
        core.finish_bot_operation(
            enrolled.bot.id,
            "session.start",
            "k1",
            r#"{"session_id":"s1"}"#,
        )
        .unwrap();
        match core
            .reserve_bot_operation(enrolled.bot.id, "session.start", "k1", &digest)
            .unwrap()
        {
            BotOperationGate::Replay { result_json } => {
                assert!(result_json.contains("s1"));
            }
            other => panic!("expected replay, got {other:?}"),
        }
        let other = "cd".repeat(32);
        assert!(matches!(
            core.reserve_bot_operation(enrolled.bot.id, "session.start", "k1", &other),
            Err(ForgeError::Conflict(_))
        ));
    }

    #[test]
    fn bot_round_trip_survives_sqlite_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("forge.sqlite");
        let key = {
            let core = ForgeCore::open_sqlite(&path).unwrap();
            core.create_account("alice", PASSWORD, UserRole::User)
                .unwrap();
            core.create_repository(
                "alice",
                CreateRepositoryRequest {
                    name: "widgets".to_string(),
                    private: true,
                    description: None,
                    default_branch: Some("main".to_string()),
                },
            )
            .unwrap();
            core.grant_repo_access("alice", "alice", "alice", "widgets", RepoAccessLevel::Write)
                .unwrap();
            let enrolled = enroll(&core, "atlas", BotReach::General);
            enrolled.enrollment_key
        };
        let core = ForgeCore::open_sqlite(&path).unwrap();
        let session = core.exchange_bot_enrollment_key(&key).unwrap();
        assert_eq!(session.bot.kind, BotKind::Grok);
        assert_eq!(session.bot.slug, "atlas");
        let bots = core.list_account_bots("alice").unwrap();
        assert_eq!(bots.len(), 1);
        let rendered = format!("{bots:?}");
        assert!(!rendered.contains(&key));
    }

    #[test]
    fn admin_bot_uses_explicit_grants_and_public_reads() {
        let core = ForgeCore::new();
        core.create_account("root", PASSWORD, UserRole::Admin)
            .unwrap();
        core.create_account("alice", PASSWORD, UserRole::User)
            .unwrap();
        core.create_repository(
            "alice",
            CreateRepositoryRequest {
                name: "secret".to_string(),
                private: true,
                description: None,
                default_branch: Some("main".to_string()),
            },
        )
        .unwrap();
        core.grant_repo_access("alice", "alice", "alice", "secret", RepoAccessLevel::Admin)
            .unwrap();
        core.create_repository(
            "alice",
            CreateRepositoryRequest {
                name: "open".to_string(),
                private: false,
                description: None,
                default_branch: Some("main".to_string()),
            },
        )
        .unwrap();
        let enrolled = core
            .enroll_bot("root", "atlas", "Atlas", BotKind::Grok, BotReach::General)
            .unwrap();
        let session = core
            .exchange_bot_enrollment_key(&enrolled.enrollment_key)
            .unwrap();
        let call = |repo: &str, effect: BotEffect| BotCall {
            bot_id: session.bot.id,
            generation: session.generation,
            key_id: session.key_id.clone(),
            owner: "alice".to_string(),
            repo: repo.to_string(),
            effect,
            task_kind: None,
            task_id: None,
        };
        assert!(matches!(
            core.authorize_bot(&call("secret", BotEffect::Write)),
            Err(ForgeError::Forbidden(code)) if code == "repo_not_granted"
        ));
        assert!(matches!(
            core.authorize_bot(&call("secret", BotEffect::Read)),
            Err(ForgeError::Forbidden(code)) if code == "repo_not_granted"
        ));
        assert!(core.authorize_bot(&call("open", BotEffect::Read)).is_ok());
        assert!(matches!(
            core.authorize_bot(&call("open", BotEffect::Write)),
            Err(ForgeError::Forbidden(code)) if code == "insufficient_scope"
        ));
        let hash = core
            .state
            .read()
            .bot_keys
            .values()
            .next()
            .unwrap()
            .secret_hash
            .clone();
        assert!(hash.contains("m=19456,t=2,p=1"));
    }

    #[test]
    fn expired_refresh_does_not_revoke_the_family() {
        let (core, _) = fixture();
        let enrolled = enroll(&core, "atlas", BotReach::General);
        let first = core
            .exchange_bot_enrollment_key(&enrolled.enrollment_key)
            .unwrap();
        core.force_bot_refresh_expired(&first.refresh_token);
        assert!(matches!(
            core.rotate_bot_refresh_token(&first.refresh_token),
            Err(ForgeError::Validation(message)) if message == INVALID
        ));
        let renewed = core
            .exchange_bot_enrollment_key(&enrolled.enrollment_key)
            .unwrap();
        assert_eq!(renewed.generation, first.generation);
        let call = BotCall {
            bot_id: first.bot.id,
            generation: first.generation,
            key_id: first.key_id.clone(),
            owner: "alice".to_string(),
            repo: "widgets".to_string(),
            effect: BotEffect::Read,
            task_kind: None,
            task_id: None,
        };
        assert!(core.authorize_bot(&call).is_ok());
    }

    #[test]
    fn password_change_kills_bot_keys_until_the_owner_rotates() {
        let (core, _) = fixture();
        let enrolled = enroll(&core, "atlas", BotReach::General);
        let session = core
            .exchange_bot_enrollment_key(&enrolled.enrollment_key)
            .unwrap();
        core.change_account_password("alice", PASSWORD, "replacement-horse-battery")
            .unwrap();
        assert!(
            core.exchange_bot_enrollment_key(&enrolled.enrollment_key)
                .is_err()
        );
        let stale = BotCall {
            bot_id: session.bot.id,
            generation: session.generation,
            key_id: session.key_id.clone(),
            owner: "alice".to_string(),
            repo: "widgets".to_string(),
            effect: BotEffect::Read,
            task_kind: None,
            task_id: None,
        };
        assert!(core.authorize_bot(&stale).is_err());
        assert!(
            core.authenticate_bot_access(session.bot.id, session.generation, &session.key_id)
                .is_err()
        );
        let rotated = core.rotate_bot_key("alice", enrolled.bot.id).unwrap();
        assert!(
            core.exchange_bot_enrollment_key(&enrolled.enrollment_key)
                .is_err()
        );
        let recovered = core
            .exchange_bot_enrollment_key(&rotated.enrollment_key)
            .unwrap();
        let fresh = BotCall {
            bot_id: recovered.bot.id,
            generation: recovered.generation,
            key_id: recovered.key_id,
            owner: "alice".to_string(),
            repo: "widgets".to_string(),
            effect: BotEffect::Read,
            task_kind: None,
            task_id: None,
        };
        assert!(core.authorize_bot(&fresh).is_ok());
    }

    #[test]
    fn observation_rejects_credential_material() {
        let (core, _) = fixture();
        let enrolled = enroll(&core, "atlas", BotReach::General);
        let rejected = core.note_bot_observation(
            enrolled.bot.id,
            BotObservation {
                key_id: enrolled.key_id.clone(),
                action: "saw jbk_live.abcdefghjkmn.secret".to_string(),
                outcome: "ok".to_string(),
                scope: "general".to_string(),
                repo: Some("alice/widgets".to_string()),
                session_id: None,
                success: true,
                mutation: false,
                heartbeat: false,
            },
        );
        assert!(matches!(rejected, Err(ForgeError::Validation(_))));
        assert!(
            core.list_bot_activity("alice", enrolled.bot.id)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn repository_roster_clips_reach_to_the_viewed_repo() {
        let (core, _) = fixture();
        core.grant_repo_access("alice", "alice", "alice", "other", RepoAccessLevel::Write)
            .unwrap();
        core.create_account("bob", PASSWORD, UserRole::User)
            .unwrap();
        core.grant_repo_access("alice", "bob", "alice", "widgets", RepoAccessLevel::Write)
            .unwrap();
        let enrolled = enroll(
            &core,
            "listed",
            BotReach::Repositories {
                repos: vec![
                    BotRepoRef {
                        owner: "alice".to_string(),
                        name: "widgets".to_string(),
                    },
                    BotRepoRef {
                        owner: "alice".to_string(),
                        name: "other".to_string(),
                    },
                ],
            },
        );
        let roster = core
            .list_repository_bots("bob", "alice", "widgets")
            .unwrap();
        assert_eq!(roster.len(), 1);
        match &roster[0].reach {
            BotReach::Repositories { repos } => {
                assert_eq!(repos.len(), 1);
                assert_eq!(repos[0].name, "widgets");
            }
            other => panic!("expected a clipped repository reach, got {other:?}"),
        }
        let owned = core.list_account_bots("alice").unwrap();
        match &owned
            .iter()
            .find(|bot| bot.id == enrolled.bot.id)
            .unwrap()
            .reach
        {
            BotReach::Repositories { repos } => assert_eq!(repos.len(), 2),
            other => panic!("owner list keeps the full reach, got {other:?}"),
        }
    }

    #[test]
    fn live_refresh_tokens_stay_capped_at_five() {
        let (core, _) = fixture();
        let enrolled = enroll(&core, "atlas", BotReach::General);
        let mut sessions = Vec::new();
        for _ in 0..6 {
            sessions.push(
                core.exchange_bot_enrollment_key(&enrolled.enrollment_key)
                    .unwrap(),
            );
        }
        let generation = sessions[0].generation;
        assert!(
            core.rotate_bot_refresh_token(&sessions[0].refresh_token)
                .is_err()
        );
        assert_eq!(
            core.exchange_bot_enrollment_key(&enrolled.enrollment_key)
                .unwrap()
                .generation,
            generation
        );
        assert!(
            core.rotate_bot_refresh_token(&sessions[5].refresh_token)
                .is_ok()
        );
    }

    #[test]
    fn suspended_locked_and_rejected_inputs_stay_closed() {
        let (core, issue) = fixture();
        let enrolled = enroll(&core, "atlas", BotReach::General);
        let session = core
            .exchange_bot_enrollment_key(&enrolled.enrollment_key)
            .unwrap();
        let debug = format!("{session:?}");
        assert!(debug.contains("BotSession"));
        assert!(!debug.contains(&session.refresh_token));
        assert!(
            core.authenticate_bot_access(session.bot.id, session.generation, &session.key_id)
                .is_ok()
        );
        assert!(
            core.authenticate_bot_access(Uuid::new_v4(), session.generation, &session.key_id)
                .is_err()
        );
        assert!(
            core.authenticate_bot_access(session.bot.id, session.generation, "missing-key-id")
                .is_err()
        );

        let suspended = core.suspend_bot("alice", enrolled.bot.id).unwrap();
        assert_eq!(suspended.status, BotStatus::Suspended);
        assert!(
            core.exchange_bot_enrollment_key(&enrolled.enrollment_key)
                .is_err()
        );
        assert!(
            core.rotate_bot_refresh_token(&session.refresh_token)
                .is_err()
        );
        let call = BotCall {
            bot_id: session.bot.id,
            generation: session.generation,
            key_id: session.key_id.clone(),
            owner: "alice".to_string(),
            repo: "widgets".to_string(),
            effect: BotEffect::Read,
            task_kind: None,
            task_id: None,
        };
        assert!(core.authorize_bot(&call).is_err());
        core.note_bot_observation(
            enrolled.bot.id,
            BotObservation {
                key_id: enrolled.key_id.clone(),
                action: "heartbeat".to_string(),
                outcome: "alive".to_string(),
                scope: "general".to_string(),
                repo: None,
                session_id: None,
                success: false,
                mutation: false,
                heartbeat: true,
            },
        )
        .unwrap();
        core.note_bot_observation(
            enrolled.bot.id,
            BotObservation {
                key_id: enrolled.key_id.clone(),
                action: "edit".to_string(),
                outcome: "wrote".to_string(),
                scope: "repo".to_string(),
                repo: Some("alice/widgets".to_string()),
                session_id: Some("sess-1".to_string()),
                success: false,
                mutation: true,
                heartbeat: false,
            },
        )
        .unwrap();
        let listed = core.list_account_bots("alice").unwrap();
        assert!(listed[0].last_heartbeat.is_some());
        assert!(listed[0].last_mutation.is_some());
        assert!(listed[0].last_successful_access.is_none());
        let repo_events = core
            .list_repository_bot_activity("alice", "alice", "widgets")
            .unwrap();
        assert_eq!(repo_events.len(), 1);
        assert_eq!(repo_events[0].session_id.as_deref(), Some("sess-1"));
        core.create_account("carol", PASSWORD, UserRole::User)
            .unwrap();
        assert!(matches!(
            core.list_repository_bots("carol", "alice", "widgets"),
            Err(ForgeError::Forbidden(_))
        ));
        assert!(matches!(
            core.list_repository_bot_activity("carol", "alice", "widgets"),
            Err(ForgeError::Forbidden(_))
        ));
        assert!(matches!(
            core.list_bot_activity("carol", enrolled.bot.id),
            Err(ForgeError::NotFound(_))
        ));
        assert!(matches!(
            core.note_bot_observation(
                Uuid::new_v4(),
                BotObservation {
                    key_id: "none".to_string(),
                    action: "x".to_string(),
                    outcome: "y".to_string(),
                    scope: "z".to_string(),
                    repo: None,
                    session_id: None,
                    success: false,
                    mutation: false,
                    heartbeat: false,
                },
            ),
            Err(ForgeError::NotFound(_))
        ));
        assert!(matches!(
            core.note_bot_observation(
                enrolled.bot.id,
                BotObservation {
                    key_id: enrolled.key_id.clone(),
                    action: " ".to_string(),
                    outcome: "y".to_string(),
                    scope: "z".to_string(),
                    repo: Some("jbr_refresh".to_string()),
                    session_id: None,
                    success: false,
                    mutation: false,
                    heartbeat: false,
                },
            ),
            Err(ForgeError::Validation(_))
        ));

        core.revoke_bot("alice", enrolled.bot.id).unwrap();
        assert!(matches!(
            core.rotate_bot_key("alice", enrolled.bot.id),
            Err(ForgeError::NotFound(_))
        ));
        assert!(matches!(
            core.suspend_bot("alice", enrolled.bot.id),
            Err(ForgeError::NotFound(_))
        ));

        let test_key = core
            .enroll_bot_with_env(
                "alice",
                "lab",
                "Lab",
                BotKind::Muse,
                BotReach::Repositories {
                    repos: vec![
                        BotRepoRef {
                            owner: "alice".to_string(),
                            name: "widgets".to_string(),
                        },
                        BotRepoRef {
                            owner: "alice".to_string(),
                            name: "widgets".to_string(),
                        },
                    ],
                },
                "test",
            )
            .unwrap();
        assert!(test_key.enrollment_key.starts_with("jbk_test."));
        match &test_key.bot.reach {
            BotReach::Repositories { repos } => assert_eq!(repos.len(), 1),
            other => panic!("duplicate repos collapse, got {other:?}"),
        }
        assert!(
            core.enroll_bot_with_env(
                "alice",
                "long-name",
                &"n".repeat(81),
                BotKind::Grok,
                BotReach::General,
                "live",
            )
            .is_err()
        );
        assert!(
            core.enroll_bot_with_env(
                "alice",
                "bad-env",
                "Bad",
                BotKind::Grok,
                BotReach::General,
                "dev",
            )
            .is_err()
        );
        assert!(
            core.enroll_bot(
                "alice",
                "empty-reach",
                "Empty",
                BotKind::Grok,
                BotReach::Repositories { repos: Vec::new() },
            )
            .is_err()
        );
        for key in [
            "not-a-key",
            &"jbk_live.".repeat(40),
            "jbk_live.short.abcdefghijklmnopqrstuvwxyz012345",
            "jbk_other.abcdefghjkmn.abcdefghijklmnopqrstuvwxyz012345",
        ] {
            assert!(matches!(
                core.exchange_bot_enrollment_key(key),
                Err(ForgeError::Validation(message)) if message == INVALID
            ));
        }

        let pull = core
            .create_pull_request(
                "alice",
                "widgets",
                "alice",
                CreatePullRequestRequest {
                    title: "Add a gate".to_string(),
                    head: "feature".to_string(),
                    base: "main".to_string(),
                    ..CreatePullRequestRequest::default()
                },
            )
            .unwrap();
        let pull_bot = enroll(
            &core,
            "puller",
            BotReach::Task {
                repo: BotRepoRef {
                    owner: "alice".to_string(),
                    name: "widgets".to_string(),
                },
                task_kind: BotTaskKind::Pull,
                task_id: pull.number.to_string(),
            },
        );
        let branch_bot = enroll(
            &core,
            "brancher",
            BotReach::Task {
                repo: BotRepoRef {
                    owner: "alice".to_string(),
                    name: "widgets".to_string(),
                },
                task_kind: BotTaskKind::Branch,
                task_id: "feature/setup".to_string(),
            },
        );
        for (slug, task_id, kind) in [
            ("blank-task", " ", BotTaskKind::Issue),
            ("text-task", "nope", BotTaskKind::Issue),
            ("missing-issue", "999", BotTaskKind::Issue),
            ("missing-pull", "999", BotTaskKind::Pull),
            ("spaced-branch", "has space", BotTaskKind::Branch),
            ("dotdot-branch", "a..b", BotTaskKind::Branch),
            ("rooted-branch", "/abs", BotTaskKind::Branch),
        ] {
            assert!(
                core.enroll_bot(
                    "alice",
                    slug,
                    slug,
                    BotKind::Grok,
                    BotReach::Task {
                        repo: BotRepoRef {
                            owner: "alice".to_string(),
                            name: "widgets".to_string(),
                        },
                        task_kind: kind,
                        task_id: task_id.to_string(),
                    },
                )
                .is_err(),
                "{slug} should be rejected"
            );
        }
        core.grant_repo_access("alice", "alice", "alice", "other", RepoAccessLevel::Write)
            .unwrap();
        let pull_session = core
            .exchange_bot_enrollment_key(&pull_bot.enrollment_key)
            .unwrap();
        let branch_session = core
            .exchange_bot_enrollment_key(&branch_bot.enrollment_key)
            .unwrap();
        let mut pull_call = BotCall {
            bot_id: pull_session.bot.id,
            generation: pull_session.generation,
            key_id: pull_session.key_id,
            owner: "alice".to_string(),
            repo: "widgets".to_string(),
            effect: BotEffect::Write,
            task_kind: Some(BotTaskKind::Pull),
            task_id: Some(pull.number.to_string()),
        };
        assert!(core.authorize_bot(&pull_call).is_ok());
        pull_call.repo = "other".to_string();
        assert!(matches!(
            core.authorize_bot(&pull_call),
            Err(ForgeError::Forbidden(code)) if code == "repo_not_granted"
        ));
        pull_call.effect = BotEffect::Read;
        assert!(matches!(
            core.authorize_bot(&pull_call),
            Err(ForgeError::Forbidden(code)) if code == "repo_not_granted"
        ));
        let mut branch_call = BotCall {
            bot_id: branch_session.bot.id,
            generation: branch_session.generation,
            key_id: branch_session.key_id,
            owner: "alice".to_string(),
            repo: "widgets".to_string(),
            effect: BotEffect::Write,
            task_kind: Some(BotTaskKind::Branch),
            task_id: Some("feature/setup".to_string()),
        };
        assert!(core.authorize_bot(&branch_call).is_ok());
        branch_call.task_id = Some("main".to_string());
        assert!(matches!(
            core.authorize_bot(&branch_call),
            Err(ForgeError::Forbidden(code)) if code == "task_not_granted"
        ));
        branch_call.task_kind = None;
        branch_call.task_id = None;
        assert!(matches!(
            core.authorize_bot(&branch_call),
            Err(ForgeError::Forbidden(code)) if code == "task_not_granted"
        ));
        let _ = issue;

        let digest = "ab".repeat(32);
        assert!(matches!(
            core.reserve_bot_operation(pull_bot.bot.id, "session.start", "k", "zz"),
            Err(ForgeError::Validation(_))
        ));
        assert!(matches!(
            core.reserve_bot_operation(pull_bot.bot.id, " ", "k", &digest),
            Err(ForgeError::Validation(_))
        ));
        assert!(matches!(
            core.reserve_bot_operation(Uuid::new_v4(), "session.start", "k", &digest),
            Err(ForgeError::NotFound(_))
        ));
        assert!(matches!(
            core.finish_bot_operation(pull_bot.bot.id, "missing", "k", "{}"),
            Err(ForgeError::NotFound(_))
        ));
        core.reserve_bot_operation(pull_bot.bot.id, "session.start", "k", &digest)
            .unwrap();
        assert!(matches!(
            core.finish_bot_operation(pull_bot.bot.id, "session.start", "k", "not-json"),
            Err(ForgeError::Validation(_))
        ));
        core.finish_bot_operation(pull_bot.bot.id, "session.start", "k", "{}")
            .unwrap();
        assert!(matches!(
            core.finish_bot_operation(pull_bot.bot.id, "session.start", "k", "{}"),
            Err(ForgeError::Conflict(_))
        ));

        core.create_account("bob", PASSWORD, UserRole::User)
            .unwrap();
        core.grant_repo_access("alice", "bob", "alice", "widgets", RepoAccessLevel::Read)
            .unwrap();
        let bob_bot = core
            .enroll_bot("bob", "helper", "Helper", BotKind::Grok, BotReach::General)
            .unwrap();
        core.lock_account("bob").unwrap();
        assert!(
            core.exchange_bot_enrollment_key(&bob_bot.enrollment_key)
                .is_err()
        );
        assert!(
            core.enroll_bot(
                "bob",
                "after-lock",
                "After",
                BotKind::Muse,
                BotReach::General
            )
            .is_err()
        );
        core.disable_account("carol").unwrap();
        assert!(core.list_account_bots("carol").is_err());
    }

    #[test]
    fn persisted_refresh_activity_and_operations_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("forge.sqlite");
        let (key, refresh, bot_id) = {
            let core = ForgeCore::open_sqlite(&path).unwrap();
            core.create_account("alice", PASSWORD, UserRole::User)
                .unwrap();
            core.create_repository(
                "alice",
                CreateRepositoryRequest {
                    name: "widgets".to_string(),
                    private: true,
                    description: None,
                    default_branch: Some("main".to_string()),
                },
            )
            .unwrap();
            core.grant_repo_access("alice", "alice", "alice", "widgets", RepoAccessLevel::Write)
                .unwrap();
            let enrolled = enroll(&core, "atlas", BotReach::General);
            let first = core
                .exchange_bot_enrollment_key(&enrolled.enrollment_key)
                .unwrap();
            let _rotated_refresh = core.rotate_bot_refresh_token(&first.refresh_token).unwrap();
            let rotated = core.rotate_bot_key("alice", enrolled.bot.id).unwrap();
            let second = core
                .exchange_bot_enrollment_key(&rotated.enrollment_key)
                .unwrap();
            core.force_bot_key_retired(&enrolled.key_id);
            core.note_bot_observation(
                enrolled.bot.id,
                BotObservation {
                    key_id: enrolled.key_id.clone(),
                    action: "edit".to_string(),
                    outcome: "ok".to_string(),
                    scope: "repo".to_string(),
                    repo: Some("alice/widgets".to_string()),
                    session_id: Some("sess-9".to_string()),
                    success: true,
                    mutation: true,
                    heartbeat: false,
                },
            )
            .unwrap();
            core.note_bot_observation(
                enrolled.bot.id,
                BotObservation {
                    key_id: enrolled.key_id.clone(),
                    action: "ping".to_string(),
                    outcome: "ok".to_string(),
                    scope: "general".to_string(),
                    repo: None,
                    session_id: None,
                    success: false,
                    mutation: false,
                    heartbeat: true,
                },
            )
            .unwrap();
            let digest = "ef".repeat(32);
            core.reserve_bot_operation(enrolled.bot.id, "session.start", "once", &digest)
                .unwrap();
            core.finish_bot_operation(enrolled.bot.id, "session.start", "once", r#"{"ok":true}"#)
                .unwrap();
            let muse = core
                .enroll_bot_with_env(
                    "alice",
                    "paused",
                    "Paused",
                    BotKind::Muse,
                    BotReach::General,
                    "test",
                )
                .unwrap();
            core.suspend_bot("alice", muse.bot.id).unwrap();
            (
                enrolled.enrollment_key,
                second.refresh_token,
                enrolled.bot.id,
            )
        };
        let core = ForgeCore::open_sqlite(&path).unwrap();
        assert!(core.exchange_bot_enrollment_key(&key).is_err());
        let renewed = core.rotate_bot_refresh_token(&refresh).unwrap();
        assert_eq!(renewed.bot.id, bot_id);
        let events = core.list_bot_activity("alice", bot_id).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "edit");
        let bots = core.list_account_bots("alice").unwrap();
        assert_eq!(bots.len(), 2);
        assert!(bots.iter().any(|bot| bot.kind == BotKind::Muse));
        assert!(
            bots.iter()
                .any(|bot| bot.status == BotStatus::Suspended && bot.last_heartbeat.is_none())
        );
        assert!(
            bots.iter()
                .any(|bot| bot.slug == "atlas" && bot.last_heartbeat.is_some())
        );
        let digest = "ef".repeat(32);
        assert!(matches!(
            core.reserve_bot_operation(bot_id, "session.start", "once", &digest)
                .unwrap(),
            BotOperationGate::Replay { .. }
        ));
    }

    fn observation(key_id: &str, action: &str, outcome: &str) -> BotObservation {
        BotObservation {
            key_id: key_id.to_string(),
            action: action.to_string(),
            outcome: outcome.to_string(),
            scope: "general".to_string(),
            repo: None,
            session_id: None,
            success: true,
            mutation: false,
            heartbeat: false,
        }
    }

    #[test]
    fn activity_coalesces_until_the_outcome_changes_or_the_window_elapses() {
        let (core, _) = fixture();
        let enrolled = enroll(&core, "atlas", BotReach::General);
        let id = enrolled.bot.id;
        core.note_bot_observation(id, observation(&enrolled.key_id, "whoami", "ok"))
            .unwrap();
        core.note_bot_observation(id, observation(&enrolled.key_id, "whoami-again", "ok"))
            .unwrap();
        let events = core.list_bot_activity("alice", id).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "whoami");
        assert_eq!(
            core.list_account_bots("alice").unwrap()[0]
                .last_action
                .as_deref(),
            Some("whoami-again")
        );
        core.note_bot_observation(id, observation(&enrolled.key_id, "whoami", "denied"))
            .unwrap();
        assert_eq!(core.list_bot_activity("alice", id).unwrap().len(), 2);
        core.force_bot_activity_window_elapsed(id);
        core.note_bot_observation(id, observation(&enrolled.key_id, "whoami", "denied"))
            .unwrap();
        assert_eq!(core.list_bot_activity("alice", id).unwrap().len(), 3);

        let beat = BotObservation {
            action: "ping".to_string(),
            outcome: "alive".to_string(),
            success: false,
            heartbeat: true,
            ..observation(&enrolled.key_id, "ping", "alive")
        };
        core.note_bot_observation(id, beat.clone()).unwrap();
        let first = core.list_account_bots("alice").unwrap()[0].last_heartbeat;
        core.note_bot_observation(id, beat.clone()).unwrap();
        assert_eq!(
            core.list_account_bots("alice").unwrap()[0].last_heartbeat,
            first
        );
        core.force_bot_activity_window_elapsed(id);
        core.note_bot_observation(id, beat).unwrap();
        assert_ne!(
            core.list_account_bots("alice").unwrap()[0].last_heartbeat,
            first
        );
    }

    #[test]
    fn activity_keeps_the_newest_five_hundred_events_for_that_bot() {
        let (core, _) = fixture();
        let enrolled = enroll(&core, "atlas", BotReach::General);
        let other = enroll(&core, "nova", BotReach::General);
        core.note_bot_observation(other.bot.id, observation(&other.key_id, "stay", "ok"))
            .unwrap();
        for index in 0..=ACTIVITY_CAP {
            core.note_bot_observation(
                enrolled.bot.id,
                observation(&enrolled.key_id, "edit", &format!("n{index}")),
            )
            .unwrap();
        }
        let events = core.list_bot_activity("alice", enrolled.bot.id).unwrap();
        assert_eq!(events.len(), ACTIVITY_CAP);
        assert!(events.iter().all(|event| event.outcome != "n0"));
        let newest = format!("n{ACTIVITY_CAP}");
        assert!(events.iter().any(|event| event.outcome == newest));
        assert_eq!(
            core.list_bot_activity("alice", other.bot.id).unwrap().len(),
            1
        );
    }

    #[test]
    fn bot_lifecycle_audits_actor_and_ids_without_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("forge.sqlite");
        let core = ForgeCore::open_sqlite(&path).unwrap();
        core.create_account("alice", PASSWORD, UserRole::User)
            .unwrap();
        for name in ["widgets", "other"] {
            core.create_repository(
                "alice",
                CreateRepositoryRequest {
                    name: name.to_string(),
                    private: true,
                    description: None,
                    default_branch: Some("main".to_string()),
                },
            )
            .unwrap();
        }
        core.grant_repo_access("alice", "alice", "alice", "widgets", RepoAccessLevel::Write)
            .unwrap();
        let enrolled = enroll(&core, "atlas", BotReach::General);
        let session = core
            .exchange_bot_enrollment_key(&enrolled.enrollment_key)
            .unwrap();
        let rotated = core.rotate_bot_key("alice", enrolled.bot.id).unwrap();
        let denied = core.authorize_bot(&BotCall {
            bot_id: session.bot.id,
            generation: session.generation,
            key_id: session.key_id.clone(),
            owner: "alice".to_string(),
            repo: "other".to_string(),
            effect: BotEffect::Write,
            task_kind: None,
            task_id: None,
        });
        assert!(matches!(
            denied,
            Err(ForgeError::Forbidden(code)) if code == "repo_not_granted"
        ));
        let renewed = core
            .rotate_bot_refresh_token(&session.refresh_token)
            .unwrap();
        assert!(
            core.rotate_bot_refresh_token(&session.refresh_token)
                .is_err()
        );
        core.suspend_bot("alice", enrolled.bot.id).unwrap();
        core.revoke_bot("alice", enrolled.bot.id).unwrap();

        let trail = core.list_audit("alice/atlas").unwrap();
        let rendered = format!("{trail:?}");
        assert!(!rendered.contains(&enrolled.enrollment_key));
        assert!(!rendered.contains(&rotated.enrollment_key));
        assert!(!rendered.contains(&session.refresh_token));
        assert!(!rendered.contains(&renewed.refresh_token));
        assert!(!rendered.contains("jbk_"));
        assert!(!rendered.contains("jbr_"));
        let actions: Vec<&str> = trail.iter().map(|entry| entry.action.as_str()).collect();
        for action in [
            "bot.enroll",
            "bot.token.exchange",
            "bot.rotate",
            "bot.authorize",
            "bot.refresh.reuse",
            "bot.suspend",
            "bot.revoke",
        ] {
            assert!(actions.contains(&action), "missing {action} in {actions:?}");
        }
        let denial = trail
            .iter()
            .find(|entry| entry.action == "bot.authorize")
            .unwrap();
        assert_eq!(denial.actor, "alice");
        assert_eq!(denial.phase, "failed");
        assert_eq!(denial.detail["code"], "repo_not_granted");
        assert_eq!(denial.detail["bot_id"], enrolled.bot.id.to_string());
        assert_eq!(denial.detail["key_id"], session.key_id);
        assert!(trail.iter().all(|entry| entry.actor == "alice"));
    }
}
