//! Scoped agent tokens: a long-lived bearer for one account bot.
//!
//! A token adds no rights of its own. It names a bot, and every call it makes
//! is authorized exactly like that bot's short-lived access token: the owner's
//! non-admin rights, cut down by the bot's reach, checked again per request.
//! A token is valid while the bot's credential generation is the one it was
//! issued under, so suspending or revoking the bot, or any owner account event
//! that bumps the generation, ends it. A team bot's token also records who
//! issued it, and works only while that person may still issue one (record
//! 0008). Rotating the bot's enrollment key does
//! not: the enrollment key and a token are separate secrets, and a token is
//! ended by revoking it. Only its SHA-256 is
//! stored, and it is looked up by that hash.

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use super::ForgeCore;
use super::bots::{
    bot_account_matches, explain_bot, key_is_live, managed_bot, new_key_id, new_secret, token_hash,
};
use crate::errors::{ForgeError, Result};
use crate::model::*;

/// Prefix of every agent token, so secret scanners can recognise one.
pub const AGENT_TOKEN_PREFIX: &str = "jat_";
const DEFAULT_TTL_DAYS: u32 = 90;
const MAX_TTL_DAYS: u32 = 365;
const MAX_LIVE_TOKENS: usize = 10;
const LAST_USED_COALESCE_SECS: i64 = 60;
const INVALID: &str = "invalid agent token";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BotAccessTokenRecord {
    pub token_hash: String,
    pub token_id: String,
    pub bot_id: Uuid,
    pub key_id: String,
    pub generation: u64,
    pub label: Option<String>,
    /// The login that issued it; `None` for tokens issued before record 0008.
    pub issued_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl From<&BotAccessTokenRecord> for BotAccessTokenSummary {
    fn from(record: &BotAccessTokenRecord) -> Self {
        Self {
            token_id: record.token_id.clone(),
            bot_id: record.bot_id,
            label: record.label.clone(),
            issued_by: record.issued_by.clone(),
            created_at: record.created_at,
            expires_at: record.expires_at,
            last_used_at: record.last_used_at,
            revoked_at: record.revoked_at,
        }
    }
}

impl ForgeCore {
    /// Issue a new agent token for a bot `actor` manages: their own bot, or a
    /// team bot they steward. The token is in the result once and is never
    /// stored or returned again.
    pub fn issue_bot_access_token(
        &self,
        actor: &str,
        bot_id: Uuid,
        label: Option<&str>,
        ttl_days: Option<u32>,
    ) -> Result<BotAccessTokenIssued> {
        self.active_account(actor)?;
        let ttl_days = ttl_days.unwrap_or(DEFAULT_TTL_DAYS);
        if ttl_days == 0 || ttl_days > MAX_TTL_DAYS {
            return Err(ForgeError::Validation(format!(
                "ttl_days must be between 1 and {MAX_TTL_DAYS}"
            )));
        }
        let label = match label.map(str::trim) {
            Some("") | None => None,
            Some(text) if text.chars().count() > 80 => {
                return Err(ForgeError::Validation(
                    "label must be at most 80 characters".to_string(),
                ));
            }
            Some(text) => Some(text.to_string()),
        };
        let token_id = new_key_id()?;
        let token = format!("{AGENT_TOKEN_PREFIX}{token_id}.{}", new_secret()?);
        let now = Utc::now();
        let mut state = self.state.write();
        let bot = managed_bot(&state, actor, bot_id)?;
        if !bot_account_matches(&state, &bot) {
            return Err(ForgeError::Validation(
                "the bot is not active; agent tokens need an active bot".to_string(),
            ));
        }
        let Some(key_id) = state
            .bot_keys
            .values()
            .filter(|key| key.bot_id == bot.id && key_is_live(key, now))
            .max_by_key(|key| key.created_at)
            .map(|key| key.key_id.clone())
        else {
            return Err(ForgeError::Validation(
                "the bot has no live key; rotate its key first".to_string(),
            ));
        };
        let live = state
            .bot_access_tokens
            .values()
            .filter(|record| record.bot_id == bot.id && token_is_live(record, &bot, now))
            .count();
        if live >= MAX_LIVE_TOKENS {
            return Err(ForgeError::Conflict(format!(
                "the bot already has {MAX_LIVE_TOKENS} live agent tokens; revoke one first"
            )));
        }
        let previous = state.clone();
        let record = BotAccessTokenRecord {
            token_hash: token_hash(&token),
            token_id: token_id.clone(),
            bot_id: bot.id,
            key_id: key_id.clone(),
            generation: bot.credential_generation,
            label: label.clone(),
            issued_by: Some(actor.to_string()),
            created_at: now,
            expires_at: now + Duration::days(i64::from(ttl_days)),
            last_used_at: None,
            revoked_at: None,
        };
        state
            .bot_access_tokens
            .insert(record.token_hash.clone(), record.clone());
        self.persist_after_mutation(&mut state, previous)?;
        drop(state);
        self.record_bot_audit(
            actor,
            "bot.token.issue",
            &format!("{}/{}", bot.owner, bot.slug),
            "completed",
            bot.id,
            Some(&key_id),
            None,
        )?;
        Ok(BotAccessTokenIssued {
            bot: BotSummary::from(&bot),
            token_id,
            token,
            label,
            created_at: record.created_at,
            expires_at: record.expires_at,
        })
    }

    /// The agent tokens of one of `actor`'s bots, newest first. Never the
    /// tokens themselves.
    pub fn list_bot_access_tokens(
        &self,
        actor: &str,
        bot_id: Uuid,
    ) -> Result<Vec<BotAccessTokenSummary>> {
        let state = self.state.read();
        managed_bot(&state, actor, bot_id)?;
        let mut tokens: Vec<_> = state
            .bot_access_tokens
            .values()
            .filter(|record| record.bot_id == bot_id)
            .map(BotAccessTokenSummary::from)
            .collect();
        tokens.sort_by_key(|token| std::cmp::Reverse(token.created_at));
        Ok(tokens)
    }

    /// Revoke one agent token. Revoking an already revoked token succeeds.
    pub fn revoke_bot_access_token(
        &self,
        actor: &str,
        bot_id: Uuid,
        token_id: &str,
    ) -> Result<BotAccessTokenSummary> {
        let now = Utc::now();
        let mut state = self.state.write();
        let bot = managed_bot(&state, actor, bot_id)?;
        let Some(hash) = state
            .bot_access_tokens
            .iter()
            .find(|(_, record)| record.bot_id == bot_id && record.token_id == token_id)
            .map(|(hash, _)| hash.clone())
        else {
            return Err(ForgeError::NotFound(format!("agent token {token_id}")));
        };
        let previous = state.clone();
        let summary = {
            let record = state
                .bot_access_tokens
                .get_mut(&hash)
                .expect("token found above");
            if record.revoked_at.is_none() {
                record.revoked_at = Some(now);
            }
            BotAccessTokenSummary::from(&*record)
        };
        self.persist_after_mutation(&mut state, previous)?;
        drop(state);
        self.record_bot_audit(
            actor,
            "bot.token.revoke",
            &format!("{}/{}", bot.owner, bot.slug),
            "completed",
            bot.id,
            None,
            None,
        )?;
        Ok(summary)
    }

    /// Verify a presented agent token. Every failure is the same error, so a
    /// caller learns nothing about which check failed.
    pub fn authenticate_bot_access_token(&self, token: &str) -> Result<BotAccessTokenAuth> {
        if !token.starts_with(AGENT_TOKEN_PREFIX) || token.len() > 120 {
            return Err(invalid());
        }
        let hash = token_hash(token);
        let now = Utc::now();
        let auth = {
            let state = self.state.read();
            let record = state.bot_access_tokens.get(&hash).ok_or_else(invalid)?;
            let bot = state.bots.get(&record.bot_id).ok_or_else(invalid)?;
            if !bot_account_matches(&state, bot)
                || !token_is_live(record, bot, now)
                || !super::team_bots::issuer_still_stewards(&state, bot, record)
            {
                return Err(invalid());
            }
            // Calls are authorized under one of the bot's live keys, whichever
            // is newest now, so a key rotation does not end the token.
            let key_id = state
                .bot_keys
                .values()
                .filter(|key| key.bot_id == bot.id && key_is_live(key, now))
                .max_by_key(|key| key.created_at)
                .map(|key| key.key_id.clone())
                .ok_or_else(invalid)?;
            let stale = record.last_used_at.is_none_or(|used| {
                now.signed_duration_since(used) >= Duration::seconds(LAST_USED_COALESCE_SECS)
            });
            (
                BotAccessTokenAuth {
                    bot: BotSummary::from(bot),
                    token_id: record.token_id.clone(),
                    key_id,
                    generation: record.generation,
                    expires_at: record.expires_at,
                },
                stale,
            )
        };
        let (auth, stale) = auth;
        if stale {
            // Last use is advisory and kept in memory; it is written with the
            // next mutation, so a request never waits on storage for it.
            let mut state = self.state.write();
            if let Some(record) = state.bot_access_tokens.get_mut(&hash) {
                record.last_used_at = Some(now);
            }
        }
        Ok(auth)
    }
}

fn token_is_live(
    record: &BotAccessTokenRecord,
    bot: &super::bots::BotRecord,
    now: DateTime<Utc>,
) -> bool {
    record.revoked_at.is_none()
        && record.expires_at > now
        && record.generation == bot.credential_generation
}

fn invalid() -> ForgeError {
    explain_bot(ForgeError::Validation(INVALID.to_string()))
}
