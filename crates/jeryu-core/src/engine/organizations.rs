//! Organizations with owners, and the teams they run (record 0009).
//!
//! Forge administrators create an organization and name its first owners.
//! Owners, and administrators, add or remove owners (never the last), create
//! teams, and change team members. Every change is audited. Neither owning an
//! organization nor belonging to a team grants a repository right: record 0008
//! names the one thing a team does, stewarding a team bot.

use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use super::auth::require_login;
use super::{ForgeCore, require_name, slugify};
use crate::errors::{ForgeError, Result};
use crate::model::*;

const MAX_OWNERS: usize = 20;
const MAX_MEMBERS: usize = 200;

impl ForgeCore {
    /// Create an organization run by `owners`. Only a forge administrator may.
    /// The login is canonical and unique across accounts, user profiles and
    /// organizations; it may equal an existing repository owner name.
    pub fn create_organization_as(
        &self,
        actor: &str,
        login: &str,
        display_name: Option<&str>,
        owners: &[String],
    ) -> Result<Organization> {
        require_login(login)?;
        let display_name = match display_name.map(str::trim) {
            Some("") | None => None,
            Some(name) if name.chars().count() > 80 => {
                return Err(ForgeError::Validation(
                    "display name may not exceed 80 characters".to_string(),
                ));
            }
            Some(name) => Some(name.to_string()),
        };
        let mut state = self.state.write();
        if !state_is_admin(&state, actor) {
            return Err(ForgeError::Forbidden(
                "only a forge administrator may create an organization".to_string(),
            ));
        }
        if state.organizations.contains_key(login)
            || state.accounts.contains_key(login)
            || state.users.contains_key(login)
        {
            return Err(ForgeError::Conflict(format!("login {login} is taken")));
        }
        let owners = active_people(&state, owners, MAX_OWNERS, "owner")?;
        if owners.is_empty() {
            return Err(ForgeError::Validation(
                "an organization needs at least one owner".to_string(),
            ));
        }
        let previous = state.clone();
        let organization = Organization {
            id: Uuid::new_v4(),
            login: login.to_string(),
            display_name,
            created_at: Utc::now(),
            owners: owners.clone(),
            created_by: Some(actor.to_string()),
        };
        state
            .organizations
            .insert(login.to_string(), organization.clone());
        self.persist_after_mutation(&mut state, previous)?;
        drop(state);
        self.append_audit_as(
            actor,
            "org.create",
            &format!("org:{login}"),
            "completed",
            json!({ "owners": owners }),
        )?;
        Ok(organization)
    }

    /// Organizations `actor` owns or has a team in; every organization for a
    /// forge administrator. Sorted by login.
    pub fn list_organizations_for(&self, actor: &str) -> Result<Vec<Organization>> {
        let state = self.state.read();
        require_active(&state, actor)?;
        let mut organizations: Vec<_> = state
            .organizations
            .values()
            .filter(|organization| may_view_organization(&state, actor, &organization.login))
            .cloned()
            .collect();
        organizations.sort_by(|left, right| left.login.cmp(&right.login));
        Ok(organizations)
    }

    /// One organization and its teams. An organization `actor` may not see is
    /// not found, so its existence is not disclosed.
    pub fn organization_for(&self, actor: &str, org: &str) -> Result<OrganizationView> {
        let state = self.state.read();
        require_active(&state, actor)?;
        let organization = visible_organization(&state, actor, org)?;
        let mut teams: Vec<_> = state
            .teams
            .values()
            .filter(|team| team.organization == org)
            .cloned()
            .collect();
        teams.sort_by(|left, right| left.slug.cmp(&right.slug));
        Ok(OrganizationView {
            organization,
            teams,
            can_manage: may_run_organization(&state, actor, org),
        })
    }

    pub fn add_organization_owner(
        &self,
        actor: &str,
        org: &str,
        login: &str,
    ) -> Result<Organization> {
        let mut state = self.state.write();
        let mut organization = managed_organization(&state, actor, org)?;
        let login = active_person(&state, login)?;
        if organization.owners.contains(&login) {
            return Ok(organization);
        }
        if organization.owners.len() >= MAX_OWNERS {
            return Err(ForgeError::Validation(format!(
                "an organization may have at most {MAX_OWNERS} owners"
            )));
        }
        let previous = state.clone();
        organization.owners.push(login.clone());
        organization.owners.sort();
        state
            .organizations
            .insert(org.to_string(), organization.clone());
        self.persist_after_mutation(&mut state, previous)?;
        drop(state);
        self.audit_membership(actor, "org.owner.add", &format!("org:{org}"), &login)?;
        Ok(organization)
    }

    /// Remove an owner. The last owner stays: an organization always has
    /// someone to run it once it has had an owner.
    pub fn remove_organization_owner(
        &self,
        actor: &str,
        org: &str,
        login: &str,
    ) -> Result<Organization> {
        let mut state = self.state.write();
        let mut organization = managed_organization(&state, actor, org)?;
        if !organization.owners.iter().any(|owner| owner == login) {
            return Ok(organization);
        }
        if organization.owners.len() == 1 {
            return Err(ForgeError::Validation(
                "last_owner: add another owner before removing the last one".to_string(),
            ));
        }
        let previous = state.clone();
        organization.owners.retain(|owner| owner != login);
        state
            .organizations
            .insert(org.to_string(), organization.clone());
        self.persist_after_mutation(&mut state, previous)?;
        drop(state);
        self.audit_membership(actor, "org.owner.remove", &format!("org:{org}"), login)?;
        Ok(organization)
    }

    pub fn create_team_as(
        &self,
        actor: &str,
        org: &str,
        name: &str,
        slug: Option<&str>,
        members: &[String],
    ) -> Result<Team> {
        require_name("team name", name)?;
        if name.trim().chars().count() > 80 {
            return Err(ForgeError::Validation(
                "team name may not exceed 80 characters".to_string(),
            ));
        }
        let slug = match slug.map(str::trim) {
            Some(slug) if !slug.is_empty() => slug.to_string(),
            _ => slugify(name),
        };
        require_login(&slug).map_err(|_| {
            ForgeError::Validation(
                "team slug must be lowercase letters, numbers, hyphen, or underscore".to_string(),
            )
        })?;
        let mut state = self.state.write();
        managed_organization(&state, actor, org)?;
        let key = (org.to_string(), slug.clone());
        if state.teams.contains_key(&key) {
            return Err(ForgeError::Conflict(format!("team {org}/{slug}")));
        }
        let members = active_people(&state, members, MAX_MEMBERS, "member")?;
        let previous = state.clone();
        let team = Team {
            id: Uuid::new_v4(),
            organization: org.to_string(),
            slug: slug.clone(),
            name: name.trim().to_string(),
            members: members.clone(),
            created_at: Utc::now(),
        };
        state.teams.insert(key, team.clone());
        self.persist_after_mutation(&mut state, previous)?;
        drop(state);
        self.append_audit_as(
            actor,
            "team.create",
            &format!("team:{org}/{slug}"),
            "completed",
            json!({ "members": members }),
        )?;
        Ok(team)
    }

    pub fn add_team_member(&self, actor: &str, org: &str, team: &str, login: &str) -> Result<Team> {
        let mut state = self.state.write();
        managed_organization(&state, actor, org)?;
        let key = (org.to_string(), team.to_string());
        let Some(mut stored) = state.teams.get(&key).cloned() else {
            return Err(ForgeError::NotFound(format!("team {org}/{team}")));
        };
        let login = active_person(&state, login)?;
        if stored.members.contains(&login) {
            return Ok(stored);
        }
        if stored.members.len() >= MAX_MEMBERS {
            return Err(ForgeError::Validation(format!(
                "a team may have at most {MAX_MEMBERS} members"
            )));
        }
        let previous = state.clone();
        stored.members.push(login.clone());
        stored.members.sort();
        state.teams.insert(key, stored.clone());
        self.persist_after_mutation(&mut state, previous)?;
        drop(state);
        self.audit_membership(
            actor,
            "team.member.add",
            &format!("team:{org}/{team}"),
            &login,
        )?;
        Ok(stored)
    }

    /// Remove a member. A team may be emptied; it is never deleted, so
    /// nothing that names it dangles. Agent tokens the member issued for the
    /// bots this team stewards are revoked with the membership (record 0008).
    pub fn remove_team_member(
        &self,
        actor: &str,
        org: &str,
        team: &str,
        login: &str,
    ) -> Result<Team> {
        let now = Utc::now();
        let mut state = self.state.write();
        managed_organization(&state, actor, org)?;
        let key = (org.to_string(), team.to_string());
        let Some(mut stored) = state.teams.get(&key).cloned() else {
            return Err(ForgeError::NotFound(format!("team {org}/{team}")));
        };
        if !stored.members.iter().any(|member| member == login) {
            return Ok(stored);
        }
        let previous = state.clone();
        stored.members.retain(|member| member != login);
        state.teams.insert(key, stored.clone());
        let revoked = super::team_bots::revoke_steward_tokens(&mut state, org, team, login, now);
        self.persist_after_mutation(&mut state, previous)?;
        drop(state);
        self.append_audit_as(
            actor,
            "team.member.remove",
            &format!("team:{org}/{team}"),
            "completed",
            json!({ "login": login, "revoked_agent_tokens": revoked }),
        )?;
        Ok(stored)
    }

    fn audit_membership(
        &self,
        actor: &str,
        action: &str,
        subject: &str,
        login: &str,
    ) -> Result<()> {
        self.append_audit_as(
            actor,
            action,
            subject,
            "completed",
            json!({ "login": login }),
        )?;
        Ok(())
    }
}

/// `login` is an active account with the forge administrator role.
pub(super) fn state_is_admin(state: &super::State, login: &str) -> bool {
    state.accounts.get(login).is_some_and(|account| {
        account.status.permits_authentication() && account.role == UserRole::Admin
    })
}

/// `actor` may change this organization's owners, teams and members: an active
/// owner, or a forge administrator.
pub(super) fn may_run_organization(state: &super::State, actor: &str, org: &str) -> bool {
    if state_is_admin(state, actor) {
        return true;
    }
    let active = state
        .accounts
        .get(actor)
        .is_some_and(|account| account.status.permits_authentication());
    active
        && state
            .organizations
            .get(org)
            .is_some_and(|organization| organization.owners.iter().any(|owner| owner == actor))
}

/// `login` is listed on team `org/team`. Says nothing about the account's status.
pub(super) fn is_team_member(state: &super::State, org: &str, team: &str, login: &str) -> bool {
    state
        .teams
        .get(&(org.to_string(), team.to_string()))
        .is_some_and(|stored| stored.members.iter().any(|member| member == login))
}

fn may_view_organization(state: &super::State, actor: &str, org: &str) -> bool {
    may_run_organization(state, actor, org)
        || state.teams.values().any(|team| {
            team.organization == org && team.members.iter().any(|member| member == actor)
        })
}

fn visible_organization(state: &super::State, actor: &str, org: &str) -> Result<Organization> {
    match state.organizations.get(org) {
        Some(organization) if may_view_organization(state, actor, org) => Ok(organization.clone()),
        _ => Err(ForgeError::NotFound(format!("organization {org}"))),
    }
}

/// The organization, when `actor` may run it. One `actor` cannot see is not
/// found; one they can see but not run is forbidden.
fn managed_organization(state: &super::State, actor: &str, org: &str) -> Result<Organization> {
    require_active(state, actor)?;
    let organization = visible_organization(state, actor, org)?;
    if !may_run_organization(state, actor, org) {
        return Err(ForgeError::Forbidden(
            "organization owner or forge administrator required".to_string(),
        ));
    }
    Ok(organization)
}

fn require_active(state: &super::State, actor: &str) -> Result<()> {
    if state
        .accounts
        .get(actor)
        .is_some_and(|account| account.status.permits_authentication())
    {
        Ok(())
    } else {
        Err(ForgeError::Validation("account is not active".to_string()))
    }
}

/// The canonical login of an active account, from a trimmed, lowercased name.
fn active_person(state: &super::State, login: &str) -> Result<String> {
    let login = login.trim().to_ascii_lowercase();
    match state.accounts.get(&login) {
        Some(account) if account.status.permits_authentication() => {
            Ok(account.canonical_login.clone())
        }
        _ => Err(ForgeError::Validation(format!(
            "{login} is not an active account"
        ))),
    }
}

/// Distinct active accounts, sorted, at most `limit`.
fn active_people(
    state: &super::State,
    logins: &[String],
    limit: usize,
    role: &str,
) -> Result<Vec<String>> {
    let mut people = Vec::new();
    for login in logins {
        let login = active_person(state, login)?;
        if !people.contains(&login) {
            people.push(login);
        }
    }
    if people.len() > limit {
        return Err(ForgeError::Validation(format!(
            "at most {limit} {role}s may be named"
        )));
    }
    people.sort();
    Ok(people)
}
