//! Team bots: bots an organization owns (record 0008).
//!
//! A team bot is not anyone's: its rights are only the grants made to it on
//! single repositories (`read` or `write`, never `admin`, made by that
//! repository's administrators), narrowed by its reach. The members of one team
//! of its organization steward it, with forge administrators. It acts as
//! `<organization>.<slug>[bot]`, a name no account can have, and that name
//! resolves to the bot's own grants wherever a login's access is checked.
//!
//! It authenticates with agent tokens only. Each records who issued it and
//! works only while that person may still steward the bot, so a steward who
//! leaves the team, or whose account is disabled or locked, takes their tokens
//! with them; tokens other stewards issued keep working.

use chrono::{DateTime, Utc};
use serde_json::json;
use uuid::Uuid;

use super::ForgeCore;
use super::bot_tokens::BotAccessTokenRecord;
use super::bots::{BotRecord, bot_account_matches, explain_bot, managed_bot, validate_enrollment};
use super::organizations::{is_team_member, may_run_organization, state_is_admin};
use crate::errors::{ForgeError, Result};
use crate::model::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BotRepoGrantRecord {
    pub bot_id: Uuid,
    pub repo_id: Uuid,
    pub access: BotRepoAccess,
    pub granted_by: String,
    pub granted_at: DateTime<Utc>,
}

impl ForgeCore {
    /// Enroll a bot owned by organization `org`, stewarded by its team
    /// `steward_team`. An owner of the organization, or a forge administrator,
    /// may. The enrollment key in the result cannot be exchanged: a team bot
    /// authenticates only with agent tokens its stewards issue.
    #[allow(clippy::too_many_arguments)] // The enrollment fields plus the owner and steward team.
    pub fn enroll_team_bot(
        &self,
        actor: &str,
        org: &str,
        steward_team: &str,
        slug: &str,
        display_name: &str,
        kind: BotKind,
        reach: BotReach,
    ) -> Result<BotEnrollment> {
        let account = self.active_account(actor)?;
        validate_enrollment(slug, display_name, "live")?;
        {
            let state = self.state.read();
            if !state.organizations.contains_key(org) {
                return Err(ForgeError::NotFound(format!("organization {org}")));
            }
            if !may_run_organization(&state, &account.login, org) {
                return Err(ForgeError::Forbidden(
                    "organization owner or forge administrator required".to_string(),
                ));
            }
            if !state
                .teams
                .contains_key(&(org.to_string(), steward_team.to_string()))
            {
                return Err(ForgeError::Validation(format!(
                    "steward team {org}/{steward_team} does not exist"
                )));
            }
        }
        let reach = self.normalize_reach(&account.login, reach)?;
        let now = Utc::now();
        let bot = BotRecord {
            id: Uuid::new_v4(),
            owner: org.to_string(),
            owner_kind: BotOwnerKind::Organization,
            steward_team: Some(steward_team.to_string()),
            slug: slug.to_string(),
            display_name: display_name.trim().to_string(),
            kind,
            status: BotStatus::Active,
            reach,
            auth_epoch: 0,
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
        self.store_enrolled_bot(&account.login, bot, "live")
    }

    /// Team bots `actor` stewards, or every team bot for a forge administrator.
    pub fn list_team_bots(&self, actor: &str) -> Result<Vec<BotSummary>> {
        self.active_account(actor)?;
        let state = self.state.read();
        let mut bots: Vec<_> = state
            .bots
            .values()
            .filter(|bot| {
                bot.owner_kind == BotOwnerKind::Organization && is_steward(&state, bot, actor)
            })
            .map(BotSummary::from)
            .collect();
        bots.sort_by(|left, right| (&left.owner, &left.slug).cmp(&(&right.owner, &right.slug)));
        Ok(bots)
    }

    /// Give a team bot `read` or `write` on one repository, replacing any
    /// grant it held there. An administrator of that repository, or a forge
    /// administrator, may.
    pub fn grant_bot_repository(
        &self,
        actor: &str,
        bot_id: Uuid,
        owner: &str,
        repo: &str,
        access: BotRepoAccess,
    ) -> Result<BotRepoGrant> {
        let now = Utc::now();
        let mut state = self.state.write();
        let (bot, repo_id) = granting_context(&state, actor, bot_id, owner, repo)?;
        if bot.status == BotStatus::Revoked {
            return Err(ForgeError::NotFound(format!("bot {bot_id}")));
        }
        let previous = state.clone();
        let record = BotRepoGrantRecord {
            bot_id,
            repo_id,
            access,
            granted_by: actor.to_string(),
            granted_at: now,
        };
        state
            .bot_repo_grants
            .insert((bot_id, repo_id), record.clone());
        self.persist_after_mutation(&mut state, previous)?;
        drop(state);
        self.audit_grant(actor, "bot.grant", &bot, owner, repo, Some(access))?;
        Ok(BotRepoGrant {
            bot_id,
            owner: owner.to_string(),
            repo: repo.to_string(),
            access,
            granted_by: record.granted_by,
            granted_at: record.granted_at,
        })
    }

    /// Remove a team bot's grant on one repository. Removing a grant it does
    /// not hold succeeds.
    pub fn revoke_bot_repository_grant(
        &self,
        actor: &str,
        bot_id: Uuid,
        owner: &str,
        repo: &str,
    ) -> Result<()> {
        let mut state = self.state.write();
        let (bot, repo_id) = granting_context(&state, actor, bot_id, owner, repo)?;
        if !state.bot_repo_grants.contains_key(&(bot_id, repo_id)) {
            return Ok(());
        }
        let previous = state.clone();
        state.bot_repo_grants.remove(&(bot_id, repo_id));
        self.persist_after_mutation(&mut state, previous)?;
        drop(state);
        self.audit_grant(actor, "bot.ungrant", &bot, owner, repo, None)
    }

    /// Every grant a team bot holds, for its stewards and forge
    /// administrators. Sorted by repository.
    pub fn list_bot_repo_grants(&self, actor: &str, bot_id: Uuid) -> Result<Vec<BotRepoGrant>> {
        let state = self.state.read();
        managed_bot(&state, actor, bot_id)?;
        let mut grants: Vec<_> = state
            .bot_repo_grants
            .values()
            .filter(|grant| grant.bot_id == bot_id)
            .filter_map(|grant| {
                let repository = state.repos.values().find(|repo| repo.id == grant.repo_id)?;
                Some(BotRepoGrant {
                    bot_id,
                    owner: repository.owner.clone(),
                    repo: repository.name.clone(),
                    access: grant.access,
                    granted_by: grant.granted_by.clone(),
                    granted_at: grant.granted_at,
                })
            })
            .collect();
        grants.sort_by(|left, right| (&left.owner, &left.repo).cmp(&(&right.owner, &right.repo)));
        Ok(grants)
    }

    /// Revoke every live agent token `actor` issued for any team bot, in one
    /// action. Returns how many were revoked.
    pub fn revoke_issued_team_bot_tokens(&self, actor: &str) -> Result<usize> {
        let now = Utc::now();
        let mut state = self.state.write();
        let previous = state.clone();
        let revoked = revoke_tokens_issued_by(&mut state, actor, now);
        if revoked == 0 {
            return Ok(0);
        }
        self.persist_after_mutation(&mut state, previous)?;
        drop(state);
        self.append_audit_as(
            actor,
            "bot.token.revoke_issued",
            &format!("issuer:{actor}"),
            "completed",
            json!({ "revoked": revoked }),
        )?;
        Ok(revoked)
    }

    /// The account a bot's requests run as. A person's bot runs as its owner.
    /// A team bot runs as its own name, `<organization>.<slug>[bot]`, which is
    /// no account: the role is always `user` and it holds no password,
    /// session or personal token.
    pub fn bot_acting_account(&self, bot_id: Uuid) -> Result<AccountSummary> {
        let bot = {
            let state = self.state.read();
            state
                .bots
                .get(&bot_id)
                .cloned()
                .ok_or_else(|| ForgeError::NotFound(format!("bot {bot_id}")))?
        };
        match bot.owner_kind {
            BotOwnerKind::User => self.get_account(&bot.owner),
            BotOwnerKind::Organization => Ok(AccountSummary {
                login: team_bot_login(&bot.owner, &bot.slug),
                display_name: bot.display_name.clone(),
                role: UserRole::User,
                status: AccountStatus::Active,
                auth_epoch: 0,
                must_change_password: false,
                created_at: bot.created_at,
                updated_at: bot.updated_at,
            }),
        }
    }

    fn audit_grant(
        &self,
        actor: &str,
        action: &str,
        bot: &BotRecord,
        owner: &str,
        repo: &str,
        access: Option<BotRepoAccess>,
    ) -> Result<()> {
        self.append_audit_as(
            actor,
            action,
            &format!("{}/{}", bot.owner, bot.slug),
            "completed",
            json!({
                "bot_id": bot.id.to_string(),
                "repo": format!("{owner}/{repo}"),
                "access": access,
            }),
        )?;
        Ok(())
    }
}

/// `actor` stewards this team bot: an active member of its steward team, or an
/// active forge administrator. Never true for a person's bot.
pub(super) fn is_steward(state: &super::State, bot: &BotRecord, actor: &str) -> bool {
    if bot.owner_kind != BotOwnerKind::Organization {
        return false;
    }
    if state_is_admin(state, actor) {
        return true;
    }
    let active = state
        .accounts
        .get(actor)
        .is_some_and(|account| account.status.permits_authentication());
    active
        && bot
            .steward_team
            .as_deref()
            .is_some_and(|team| is_team_member(state, &bot.owner, team, actor))
}

/// A team bot's own grant on `owner/repo`, if it holds one.
pub(super) fn grant_access(
    state: &super::State,
    bot_id: Uuid,
    owner: &str,
    repo: &str,
) -> Option<BotRepoAccess> {
    let repository = state.repos.get(&(owner.to_string(), repo.to_string()))?;
    state
        .bot_repo_grants
        .get(&(bot_id, repository.id))
        .map(|grant| grant.access)
}

/// A team bot's own grant, plus a public read, as for any active principal.
pub(super) fn grant_allows(
    state: &super::State,
    bot_id: Uuid,
    owner: &str,
    repo: &str,
    write: bool,
) -> bool {
    let Some(repository) = state.repos.get(&(owner.to_string(), repo.to_string())) else {
        return false;
    };
    if !write && !repository.private {
        return true;
    }
    grant_access(state, bot_id, owner, repo).is_some_and(|access| !write || access.allows_write())
}

/// What a team bot's acting login may do on `owner/repo`, for
/// `repo_access_for`. `None` when the login names no live team bot or the bot
/// holds no grant there. Never `admin`.
pub(super) fn acting_repo_access(
    state: &super::State,
    login: &str,
    owner: &str,
    repo: &str,
) -> Option<RepoAccessLevel> {
    let (org, slug) = parse_team_bot_login(login)?;
    let bot = state.bots.values().find(|bot| {
        bot.owner_kind == BotOwnerKind::Organization && bot.owner == org && bot.slug == slug
    })?;
    if !bot_account_matches(state, bot) {
        return None;
    }
    grant_access(state, bot.id, owner, repo).map(|access| match access {
        BotRepoAccess::Read => RepoAccessLevel::Read,
        BotRepoAccess::Write => RepoAccessLevel::Write,
    })
}

/// A person's bot's tokens follow its owner's account. A team bot's token
/// works only while whoever issued it may still steward the bot.
pub(super) fn issuer_still_stewards(
    state: &super::State,
    bot: &BotRecord,
    record: &BotAccessTokenRecord,
) -> bool {
    match bot.owner_kind {
        BotOwnerKind::User => true,
        BotOwnerKind::Organization => record
            .issued_by
            .as_deref()
            .is_some_and(|issuer| is_steward(state, bot, issuer)),
    }
}

/// Revoke the live tokens `login` issued for the bots team `org/team`
/// stewards. Called when `login` leaves that team.
pub(super) fn revoke_steward_tokens(
    state: &mut super::State,
    org: &str,
    team: &str,
    login: &str,
    now: DateTime<Utc>,
) -> usize {
    let bots: Vec<Uuid> = state
        .bots
        .values()
        .filter(|bot| {
            bot.owner_kind == BotOwnerKind::Organization
                && bot.owner == org
                && bot.steward_team.as_deref() == Some(team)
        })
        .map(|bot| bot.id)
        .collect();
    revoke_matching(state, now, |record| {
        bots.contains(&record.bot_id) && record.issued_by.as_deref() == Some(login)
    })
}

/// Revoke the live tokens `login` issued for any team bot. Called when the
/// account can no longer authenticate.
pub(super) fn revoke_tokens_issued_by(
    state: &mut super::State,
    login: &str,
    now: DateTime<Utc>,
) -> usize {
    let bots: Vec<Uuid> = state
        .bots
        .values()
        .filter(|bot| bot.owner_kind == BotOwnerKind::Organization)
        .map(|bot| bot.id)
        .collect();
    revoke_matching(state, now, |record| {
        bots.contains(&record.bot_id) && record.issued_by.as_deref() == Some(login)
    })
}

fn revoke_matching(
    state: &mut super::State,
    now: DateTime<Utc>,
    matches: impl Fn(&BotAccessTokenRecord) -> bool,
) -> usize {
    let mut revoked = 0;
    for record in state.bot_access_tokens.values_mut() {
        if record.revoked_at.is_none() && matches(record) {
            record.revoked_at = Some(now);
            revoked += 1;
        }
    }
    revoked
}

/// The team bot and repository id for a grant change, when `actor`
/// administers that repository. A person's bot holds no grants of its own.
fn granting_context(
    state: &super::State,
    actor: &str,
    bot_id: Uuid,
    owner: &str,
    repo: &str,
) -> Result<(BotRecord, Uuid)> {
    let repository = state
        .repos
        .get(&(owner.to_string(), repo.to_string()))
        .ok_or_else(|| ForgeError::NotFound(format!("repository {owner}/{repo}")))?;
    if !administers_repository(state, actor, owner, repo) {
        return Err(ForgeError::Forbidden(
            "repository administrator required to change a bot's grant".to_string(),
        ));
    }
    let bot = state
        .bots
        .get(&bot_id)
        .filter(|bot| bot.owner_kind == BotOwnerKind::Organization)
        .cloned()
        .ok_or_else(|| explain_bot(ForgeError::NotFound(format!("team bot {bot_id}"))))?;
    Ok((bot, repository.id))
}

fn administers_repository(state: &super::State, actor: &str, owner: &str, repo: &str) -> bool {
    if state_is_admin(state, actor) {
        return true;
    }
    let active = state
        .accounts
        .get(actor)
        .is_some_and(|account| account.status.permits_authentication());
    active
        && state
            .repo_grants
            .get(&(actor.to_string(), owner.to_string(), repo.to_string()))
            .is_some_and(|grant| grant.access == RepoAccessLevel::Admin)
}
