//! Account credentials, sessions, PATs, and repository grants.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use chrono::{DateTime, Utc};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{ForgeCore, require_name};
use crate::errors::{ForgeError, Result};
use crate::model::*;

const SESSION_TTL_SECS: i64 = 60 * 60 * 24 * 14;
const PAT_DEFAULT_TTL_DAYS: i64 = 90;
const PAT_MAX_TTL_DAYS: i64 = 365;

impl ForgeCore {
    pub fn generate_one_time_password(&self) -> Result<String> {
        let secret = random_secret()?;
        Ok(format!("jeryu-{}", &secret[..32]))
    }

    pub fn create_account(
        &self,
        login: &str,
        password: &str,
        role: UserRole,
    ) -> Result<AccountSummary> {
        require_login(login)?;
        require_password(password)?;
        let mut state = self.state.write();
        if state.accounts.contains_key(login) {
            return Err(ForgeError::Conflict(format!("account {login}")));
        }
        let previous = state.clone();
        let now = Utc::now();
        let account = UserAccount {
            login: login.to_string(),
            password_hash: hash_password(password)?,
            role,
            must_change_password: false,
            created_at: now,
            updated_at: now,
        };
        state
            .users
            .entry(login.to_string())
            .or_insert_with(|| User {
                id: Uuid::new_v4(),
                login: login.to_string(),
                name: None,
                email: None,
                created_at: now,
            });
        state.accounts.insert(login.to_string(), account.clone());
        self.persist_after_mutation(&mut state, previous)?;
        Ok(account.into())
    }

    pub fn create_temporary_account(
        &self,
        login: &str,
        password: &str,
        role: UserRole,
    ) -> Result<AccountSummary> {
        let account = self.create_account(login, password, role)?;
        self.force_password_change(login, true)?;
        Ok(self.get_account(login).unwrap_or(account))
    }

    pub fn list_accounts(&self) -> Vec<AccountSummary> {
        let mut accounts: Vec<_> = self
            .state
            .read()
            .accounts
            .values()
            .cloned()
            .map(AccountSummary::from)
            .collect();
        accounts.sort_by(|a, b| a.login.cmp(&b.login));
        accounts
    }

    pub fn get_account(&self, login: &str) -> Result<AccountSummary> {
        self.state
            .read()
            .accounts
            .get(login)
            .cloned()
            .map(AccountSummary::from)
            .ok_or_else(|| ForgeError::NotFound(format!("account {login}")))
    }

    pub fn authenticate_password(&self, login: &str, password: &str) -> Result<AccountSummary> {
        let account = self
            .state
            .read()
            .accounts
            .get(login)
            .cloned()
            .ok_or_else(|| ForgeError::Validation("invalid login or password".to_string()))?;
        verify_password(password, &account.password_hash)?;
        Ok(account.into())
    }

    pub fn reset_account_password(
        &self,
        login: &str,
        new_password: &str,
    ) -> Result<AccountSummary> {
        require_password(new_password)?;
        let mut state = self.state.write();
        if !state.accounts.contains_key(login) {
            return Err(ForgeError::NotFound(format!("account {login}")));
        }
        let previous = state.clone();
        let account = state
            .accounts
            .get_mut(login)
            .expect("presence checked above");
        account.password_hash = hash_password(new_password)?;
        account.must_change_password = true;
        account.updated_at = Utc::now();
        let updated = account.clone();
        state.sessions.retain(|_, session| session.login != login);
        state
            .personal_tokens
            .retain(|_, token| token.login != login);
        self.persist_after_mutation(&mut state, previous)?;
        Ok(updated.into())
    }

    pub fn change_account_password(
        &self,
        login: &str,
        current_password: &str,
        new_password: &str,
    ) -> Result<AccountSummary> {
        require_password(new_password)?;
        let account = self
            .state
            .read()
            .accounts
            .get(login)
            .cloned()
            .ok_or_else(|| ForgeError::NotFound(format!("account {login}")))?;
        verify_password(current_password, &account.password_hash)?;
        let mut state = self.state.write();
        let previous = state.clone();
        let account = state
            .accounts
            .get_mut(login)
            .expect("account was read before write lock");
        account.password_hash = hash_password(new_password)?;
        account.must_change_password = false;
        account.updated_at = Utc::now();
        let updated = account.clone();
        self.persist_after_mutation(&mut state, previous)?;
        Ok(updated.into())
    }

    pub fn force_password_change(&self, login: &str, forced: bool) -> Result<AccountSummary> {
        let mut state = self.state.write();
        if !state.accounts.contains_key(login) {
            return Err(ForgeError::NotFound(format!("account {login}")));
        }
        let previous = state.clone();
        let account = state
            .accounts
            .get_mut(login)
            .expect("presence checked above");
        account.must_change_password = forced;
        account.updated_at = Utc::now();
        let updated = account.clone();
        self.persist_after_mutation(&mut state, previous)?;
        Ok(updated.into())
    }

    pub fn create_session(&self, login: &str) -> Result<SessionReceipt> {
        self.get_account(login)?;
        let token = random_secret()?;
        let csrf_token = random_secret()?;
        let session = WebSession {
            id: Uuid::new_v4(),
            login: login.to_string(),
            token_hash: token_hash(&token),
            csrf_token,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(SESSION_TTL_SECS),
        };
        let mut state = self.state.write();
        let previous = state.clone();
        state
            .sessions
            .insert(session.token_hash.clone(), session.clone());
        self.persist_after_mutation(&mut state, previous)?;
        Ok(SessionReceipt { session, token })
    }

    pub fn authenticate_session(&self, token: &str) -> Option<AccountSummary> {
        self.session_for_token(token).map(|(account, _)| account)
    }

    pub fn session_for_token(&self, token: &str) -> Option<(AccountSummary, WebSession)> {
        let hash = token_hash(token);
        let state = self.state.read();
        let session = state.sessions.get(&hash)?;
        if session.expires_at <= Utc::now() {
            return None;
        }
        let account = state
            .accounts
            .get(&session.login)
            .cloned()
            .map(AccountSummary::from)?;
        Some((account, session.clone()))
    }

    pub fn session_csrf_matches(&self, token: &str, csrf_token: &str) -> bool {
        self.session_for_token(token).is_some_and(|(_, session)| {
            constant_time_eq(session.csrf_token.as_bytes(), csrf_token.as_bytes())
        })
    }

    pub fn revoke_session(&self, token: &str) -> Result<()> {
        let hash = token_hash(token);
        let mut state = self.state.write();
        let previous = state.clone();
        state.sessions.remove(&hash);
        self.persist_after_mutation(&mut state, previous)
    }

    pub fn create_personal_access_token(
        &self,
        login: &str,
        name: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<PersonalAccessTokenReceipt> {
        self.get_account(login)?;
        require_name("token name", name)?;
        let expires_at = validate_pat_expiry(expires_at)?;
        let secret = format!("jpat_{}", random_secret()?);
        let token = PersonalAccessToken {
            id: Uuid::new_v4(),
            login: login.to_string(),
            name: name.trim().to_string(),
            token_hash: token_hash(&secret),
            created_at: Utc::now(),
            expires_at,
        };
        let mut state = self.state.write();
        let previous = state.clone();
        state.personal_tokens.insert(token.id, token.clone());
        self.persist_after_mutation(&mut state, previous)?;
        Ok(PersonalAccessTokenReceipt { token, secret })
    }

    pub fn list_personal_access_tokens(
        &self,
        login: &str,
    ) -> Result<Vec<PersonalAccessTokenSummary>> {
        self.get_account(login)?;
        let mut tokens: Vec<_> = self
            .state
            .read()
            .personal_tokens
            .values()
            .filter(|token| token.login == login)
            .cloned()
            .map(PersonalAccessTokenSummary::from)
            .collect();
        tokens.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(tokens)
    }

    pub fn revoke_personal_access_token(&self, login: &str, id: Uuid) -> Result<bool> {
        self.get_account(login)?;
        let mut state = self.state.write();
        let previous = state.clone();
        let removed = state
            .personal_tokens
            .get(&id)
            .is_some_and(|token| token.login == login);
        if removed {
            state.personal_tokens.remove(&id);
        }
        self.persist_after_mutation(&mut state, previous)?;
        Ok(removed)
    }

    pub fn authenticate_personal_access_token(&self, token: &str) -> Option<AccountSummary> {
        let hash = token_hash(token);
        let now = Utc::now();
        let state = self.state.read();
        let token = state.personal_tokens.values().find(|record| {
            record.token_hash == hash && record.expires_at.is_none_or(|expires| expires > now)
        })?;
        state
            .accounts
            .get(&token.login)
            .cloned()
            .map(AccountSummary::from)
    }

    pub fn grant_repo_access(
        &self,
        actor: &str,
        login: &str,
        owner: &str,
        repo: &str,
        access: RepoAccessLevel,
    ) -> Result<RepoAccessGrant> {
        self.get_account(login)?;
        self.get_repository(owner, repo)?;
        let mut state = self.state.write();
        let previous = state.clone();
        let grant = RepoAccessGrant {
            login: login.to_string(),
            owner: owner.to_string(),
            repo: repo.to_string(),
            access,
            granted_by: actor.to_string(),
            granted_at: Utc::now(),
        };
        state.repo_grants.insert(
            (login.to_string(), owner.to_string(), repo.to_string()),
            grant.clone(),
        );
        self.persist_after_mutation(&mut state, previous)?;
        Ok(grant)
    }

    pub fn grant_repo_access_checked(
        &self,
        actor: &str,
        login: &str,
        owner: &str,
        repo: &str,
        access: RepoAccessLevel,
    ) -> Result<RepoAccessGrant> {
        self.get_repository(owner, repo)?;
        if !self.user_can_admin_repo(actor, owner, repo) {
            return Err(ForgeError::BranchProtection(
                "repo admin access required".to_string(),
            ));
        }
        self.grant_repo_access(actor, login, owner, repo, access)
    }

    pub fn revoke_repo_access(&self, login: &str, owner: &str, repo: &str) -> Result<bool> {
        let mut state = self.state.write();
        let previous = state.clone();
        let removed = state
            .repo_grants
            .remove(&(login.to_string(), owner.to_string(), repo.to_string()))
            .is_some();
        self.persist_after_mutation(&mut state, previous)?;
        Ok(removed)
    }

    pub fn revoke_repo_access_checked(
        &self,
        actor: &str,
        login: &str,
        owner: &str,
        repo: &str,
    ) -> Result<bool> {
        self.get_repository(owner, repo)?;
        if !self.user_can_admin_repo(actor, owner, repo) {
            return Err(ForgeError::BranchProtection(
                "repo admin access required".to_string(),
            ));
        }
        self.revoke_repo_access(login, owner, repo)
    }

    pub fn list_repo_access(&self, owner: &str, repo: &str) -> Vec<RepoAccessGrant> {
        let mut grants: Vec<_> = self
            .state
            .read()
            .repo_grants
            .values()
            .filter(|grant| grant.owner == owner && grant.repo == repo)
            .cloned()
            .collect();
        grants.sort_by(|a, b| a.login.cmp(&b.login));
        grants
    }

    pub fn list_repo_access_checked(
        &self,
        actor: &str,
        owner: &str,
        repo: &str,
    ) -> Result<Vec<RepoAccessGrant>> {
        self.get_repository(owner, repo)?;
        if !self.user_can_admin_repo(actor, owner, repo) {
            return Err(ForgeError::BranchProtection(
                "repo admin access required".to_string(),
            ));
        }
        Ok(self.list_repo_access(owner, repo))
    }

    pub fn repo_access_for(&self, login: &str, owner: &str, repo: &str) -> Option<RepoAccessLevel> {
        let state = self.state.read();
        if state
            .accounts
            .get(login)
            .is_some_and(|account| account.role == UserRole::Admin)
        {
            return Some(RepoAccessLevel::Admin);
        }
        state
            .repo_grants
            .get(&(login.to_string(), owner.to_string(), repo.to_string()))
            .map(|grant| grant.access)
    }

    pub fn user_can_read_repo(&self, login: &str, owner: &str, repo: &str) -> bool {
        self.repo_access_for(login, owner, repo)
            .is_some_and(RepoAccessLevel::allows_read)
    }

    pub fn user_can_write_repo(&self, login: &str, owner: &str, repo: &str) -> bool {
        self.repo_access_for(login, owner, repo)
            .is_some_and(RepoAccessLevel::allows_write)
    }

    pub fn user_can_admin_repo(&self, login: &str, owner: &str, repo: &str) -> bool {
        self.repo_access_for(login, owner, repo)
            .is_some_and(RepoAccessLevel::allows_admin)
    }
}

fn require_login(login: &str) -> Result<()> {
    require_name("login", login)?;
    if !login
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
    {
        return Err(ForgeError::Validation(
            "login may contain only ASCII letters, numbers, hyphen, or underscore".to_string(),
        ));
    }
    Ok(())
}

fn require_password(password: &str) -> Result<()> {
    if password.len() < 12 {
        return Err(ForgeError::Validation(
            "password must be at least 12 bytes".to_string(),
        ));
    }
    Ok(())
}

fn argon2() -> Result<Argon2<'static>> {
    let params = Params::new(19_456, 2, 1, None)
        .map_err(|err| ForgeError::Storage(format!("argon2 params: {err}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2()?
        .hash_password(password.as_bytes(), &salt)
        .map_err(|err| ForgeError::Storage(format!("hash password: {err}")))?
        .to_string();
    if !hash.starts_with("$argon2id$") {
        return Err(ForgeError::Storage(
            "password hash was not encoded as argon2id PHC".to_string(),
        ));
    }
    Ok(hash)
}

fn verify_password(password: &str, password_hash: &str) -> Result<()> {
    let parsed = PasswordHash::new(password_hash)
        .map_err(|_| ForgeError::Validation("invalid login or password".to_string()))?;
    argon2()?
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| ForgeError::Validation("invalid login or password".to_string()))
}

fn validate_pat_expiry(expires_at: Option<DateTime<Utc>>) -> Result<Option<DateTime<Utc>>> {
    let now = Utc::now();
    let expires_at =
        expires_at.unwrap_or_else(|| now + chrono::Duration::days(PAT_DEFAULT_TTL_DAYS));
    if expires_at <= now {
        return Err(ForgeError::Validation(
            "token expiry must be in the future".to_string(),
        ));
    }
    if expires_at > now + chrono::Duration::days(PAT_MAX_TTL_DAYS) {
        return Err(ForgeError::Validation(format!(
            "token expiry may not exceed {PAT_MAX_TTL_DAYS} days"
        )));
    }
    Ok(Some(expires_at))
}

fn token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

pub(crate) fn random_secret() -> Result<String> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|err| ForgeError::Storage(format!("read randomness: {err}")))?;
    Ok(hex::encode(bytes))
}
