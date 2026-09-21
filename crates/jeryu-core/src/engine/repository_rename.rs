//! Repository rename and owner move with old-name redirects.

use chrono::Utc;
use uuid::Uuid;

use super::{ForgeCore, require_name};
use crate::{
    ForgeError, Repository, RepositoryAliasOrigin, RepositoryTransferJournal,
    RepositoryTransferStatus, Result,
};

/// Longest accepted repository name (GitHub's limit).
const MAX_REPOSITORY_NAME_LEN: usize = 100;

impl ForgeCore {
    /// Rename `owner/repo` to `new_owner/new_name` on behalf of `actor`.
    ///
    /// Covers a rename (same owner), a transfer (new owner) or both. Every
    /// repo-scoped `State` map is re-keyed in one persisted mutation and the
    /// bare git directory is moved through the [`super::RepoRelocator`] under
    /// the same lock; a failed move leaves state untouched. The old slug is
    /// kept as an alias, so [`Self::get_repository`] and the git edge resolve
    /// it to the moved repository until a repository is created at that name.
    ///
    /// `NotFound` for an unknown source. `Validation` when the new name is
    /// blank or not a repository slug, the new owner is not an existing user
    /// or organization, the target already exists, nothing changes, or the
    /// repository is archived (unarchive first). Audited as
    /// `repository.renamed` (requested/completed/failed) with `{from, to}`.
    pub fn rename_repository(
        &self,
        actor: &str,
        owner: &str,
        repo: &str,
        new_owner: &str,
        new_name: &str,
    ) -> Result<Repository> {
        self.canonical_repository(owner, repo)?;
        let subject = format!("{owner}/{repo}");
        let action = "repository.renamed";
        let detail = serde_json::json!({
            "from": subject,
            "to": format!("{new_owner}/{new_name}"),
        });
        self.append_audit_as(actor, action, &subject, "requested", detail.clone())?;
        let result = self.write_repository_rename(owner, repo, new_owner, new_name);
        let phase = if result.is_ok() {
            "completed"
        } else {
            "failed"
        };
        self.append_audit_as(actor, action, &subject, phase, detail)?;
        result
    }

    fn write_repository_rename(
        &self,
        owner: &str,
        repo: &str,
        new_owner: &str,
        new_name: &str,
    ) -> Result<Repository> {
        require_name("new owner", new_owner)?;
        validate_repository_name(new_name)?;
        let mut state = self.state.write();
        let key = (owner.to_string(), repo.to_string());
        let Some(current) = state.repos.get(&key).cloned() else {
            return Err(ForgeError::NotFound(format!("repository {owner}/{repo}")));
        };
        if current.archived {
            return Err(ForgeError::Validation(format!(
                "repository {owner}/{repo} is archived; unarchive it before renaming"
            )));
        }
        if owner == new_owner && repo == new_name {
            return Err(ForgeError::Validation(format!(
                "repository {owner}/{repo} already has that name"
            )));
        }
        if owner != new_owner
            && !state.users.contains_key(new_owner)
            && !state.organizations.contains_key(new_owner)
        {
            return Err(ForgeError::Validation(format!(
                "new owner {new_owner} is not an existing user or organization"
            )));
        }
        let target = (new_owner.to_string(), new_name.to_string());
        if state.repos.contains_key(&target) {
            return Err(ForgeError::Validation(format!(
                "repository {new_owner}/{new_name} already exists"
            )));
        }

        let previous = state.clone();
        let now = Utc::now();
        let transaction_id = Uuid::new_v4();
        let from = format!("{owner}/{repo}");
        let to = format!("{new_owner}/{new_name}");
        let journal = RepositoryTransferJournal {
            transaction_id,
            idempotency_key: format!("rename:{transaction_id}"),
            request_fingerprint: format!("rename {from} -> {to}"),
            repository_id: current.id,
            source_owner: owner.to_string(),
            source_name: repo.to_string(),
            destination_owner: new_owner.to_string(),
            destination_name: new_name.to_string(),
            status: RepositoryTransferStatus::Committed,
            prepared_at: now,
            completed_at: Some(now),
            failure: None,
            receipt: Some(serde_json::json!({ "from": from, "to": to })),
        };
        // A free slug that is still an alias (for example this repository's
        // own earlier name) is reclaimed by the rename.
        state.repository_aliases.remove(&target);
        if let Err(error) = super::repository_transfer_state::rekey_repository(&mut state, &journal)
        {
            *state = previous;
            return Err(error);
        }
        super::repository_transfer_state::record_alias(
            &mut state,
            &journal,
            RepositoryAliasOrigin::Rename,
        );
        state
            .repository_transfers
            .insert(journal.idempotency_key.clone(), journal);
        super::refresh_deployment_slugs(&mut state);
        let updated = state
            .repos
            .get(&target)
            .cloned()
            .expect("rekey inserted the target");

        if let Some(relocator) = &self.repo_relocator
            && let Err(error) = relocator.relocate(owner, repo, new_owner, new_name)
        {
            *state = previous;
            return Err(error);
        }
        if let Err(error) = self.persist_after_mutation(&mut state, previous) {
            // State is already rolled back; put the directory back as well.
            if let Some(relocator) = &self.repo_relocator {
                let _ = relocator.relocate(new_owner, new_name, owner, repo);
            }
            return Err(error);
        }
        Ok(updated)
    }
}

/// A repository slug: ASCII letters, digits, `-`, `_` and `.`, at most 100
/// characters, not `.`/`..`, not starting with `.` and not ending in `.git`.
fn validate_repository_name(name: &str) -> Result<()> {
    require_name("repository name", name)?;
    let valid_chars = name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'));
    if !valid_chars
        || name.len() > MAX_REPOSITORY_NAME_LEN
        || name.starts_with('.')
        || name.ends_with(".git")
    {
        return Err(ForgeError::Validation(format!(
            "repository name {name:?} is not a valid slug (letters, digits, '-', '_', '.'; \
             at most {MAX_REPOSITORY_NAME_LEN} characters; no leading '.' or trailing '.git')"
        )));
    }
    Ok(())
}
