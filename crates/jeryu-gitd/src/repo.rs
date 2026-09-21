//! Repository creation and lookup.

use crate::command::run_capture;
use crate::config::GitdConfig;
use crate::error::{GitdError, Result};
use crate::hooks::PRE_RECEIVE_HOOK;
use crate::path::{normalize_repo_name, safe_join, validate_segment};
use crate::push::{PushObserver, RefSnapshot, ref_snapshot, write_push_marker};
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

/// Logical repository identifier.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RepoId {
    /// Repository owner or organization.
    pub owner: String,
    /// Repository name without `.git`.
    pub name: String,
}

impl RepoId {
    /// Create and validate an identifier.
    pub fn new(owner: impl Into<String>, name: impl Into<String>) -> Result<Self> {
        let owner = owner.into();
        let name = name.into();
        validate_segment(&owner, "owner")?;
        validate_segment(name.strip_suffix(".git").unwrap_or(&name), "repo")?;
        Ok(Self {
            owner,
            name: name.strip_suffix(".git").unwrap_or(&name).to_string(),
        })
    }

    /// Bare repository directory name.
    #[must_use]
    pub fn bare_name(&self) -> String {
        format!("{}.git", self.name)
    }
}

impl Display for RepoId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.owner, self.name)
    }
}

/// Resolved repository on disk.
#[derive(Clone, Debug)]
pub struct Repository {
    /// Logical id.
    pub id: RepoId,
    /// Bare repository path.
    pub path: PathBuf,
}

/// Maps a renamed or transferred repository's old slug to its current one.
///
/// `jeryu-gitd` does not depend on the forge core: the unified `jeryu serve`
/// backs this with `ForgeCore::get_repository_alias`, so clone, fetch and push
/// by an old name keep reaching the moved bare repository.
pub trait RepoRedirects: std::fmt::Debug + Send + Sync {
    /// Current id for the old `owner/name`, or `None` when it is not an alias.
    fn redirect(&self, owner: &str, name: &str) -> Option<RepoId>;
}

/// Repository manager rooted at a storage directory.
#[derive(Clone, Debug)]
pub struct RepoManager {
    config: GitdConfig,
    push_observer: Option<Arc<dyn PushObserver>>,
    redirects: Option<Arc<dyn RepoRedirects>>,
}

impl RepoManager {
    /// Create a manager.
    #[must_use]
    pub fn new(config: GitdConfig) -> Self {
        Self {
            config,
            push_observer: None,
            redirects: None,
        }
    }

    /// Follow old-name aliases from `redirects` when a requested repository
    /// has no bare directory of its own.
    #[must_use]
    pub fn with_redirects(mut self, redirects: Arc<dyn RepoRedirects>) -> Self {
        self.redirects = Some(redirects);
        self
    }

    /// Report every successful push to `observer` (the unified `jeryu serve`
    /// forwards it to `ForgeCore::record_repository_push`).
    #[must_use]
    pub fn with_push_observer(mut self, observer: Arc<dyn PushObserver>) -> Self {
        self.push_observer = Some(observer);
        self
    }

    /// Snapshot refs before a push so [`Self::finish_push`] can tell whether
    /// it moved anything.
    pub fn begin_push(&self, repo: &Repository) -> Result<RefSnapshot> {
        ref_snapshot(&self.config.git_bin, repo)
    }

    /// Record a push when refs differ from `before`; a rejected or no-op push
    /// leaves refs unchanged and is not recorded. Returns whether it recorded.
    pub fn finish_push(&self, repo: &Repository, before: &RefSnapshot) -> Result<bool> {
        if ref_snapshot(&self.config.git_bin, repo)? == *before {
            return Ok(false);
        }
        self.record_push(repo)?;
        Ok(true)
    }

    /// Record a successful push now: marker file, receipt, observer.
    pub fn record_push(&self, repo: &Repository) -> Result<()> {
        let at = SystemTime::now();
        write_push_marker(repo, at)?;
        if let Some(observer) = &self.push_observer {
            observer.repository_pushed(&repo.id, at);
        }
        Ok(())
    }

    /// Newest committer date across refs of `owner/name`; `None` when the
    /// repository is absent on disk or has no commits. Backs the forge's
    /// one-time `pushed_at` backfill.
    pub fn newest_committer_time(&self, owner: &str, name: &str) -> Result<Option<SystemTime>> {
        let repo = match self.open_parts(owner, name) {
            Ok(repo) => repo,
            Err(GitdError::RepoNotFound(_)) => return Ok(None),
            Err(err) => return Err(err),
        };
        crate::push::newest_committer_time(&self.config.git_bin, &repo)
    }

    /// Access the active config.
    #[must_use]
    pub fn config(&self) -> &GitdConfig {
        &self.config
    }

    /// Resolve a repository id to a path.
    pub fn resolve(&self, id: &RepoId) -> Result<Repository> {
        let owner_root = safe_join(&self.config.storage_root, Path::new(&id.owner))?;
        let path = safe_join(&owner_root, Path::new(&id.bare_name()))?;
        Ok(Repository {
            id: id.clone(),
            path,
        })
    }

    /// Resolve owner and a repo name that may include `.git`.
    pub fn resolve_parts(&self, owner: &str, repo: &str) -> Result<Repository> {
        validate_segment(owner, "owner")?;
        let repo_git = normalize_repo_name(repo)?;
        let repo_name = repo_git.trim_end_matches(".git").to_string();
        self.resolve(&RepoId::new(owner, repo_name)?)
    }

    /// Create a bare repository and install Phase 1 metadata.
    pub fn create_bare(&self, id: &RepoId) -> Result<Repository> {
        let repo = self.resolve(id)?;
        if repo.path.exists() {
            return Err(GitdError::InvalidInput(format!(
                "repository already exists: {id}"
            )));
        }
        let parent = repo
            .path
            .parent()
            .ok_or_else(|| GitdError::InvalidPath("missing repository parent".to_string()))?;
        std::fs::create_dir_all(parent)?;
        let path_arg = repo.path.to_string_lossy().to_string();
        run_capture(&self.config.git_bin, &["init", "--bare", &path_arg], None)?;
        self.write_metadata(&repo)?;
        Ok(repo)
    }

    /// Open an existing repository.
    ///
    /// A repository present on disk under `id` always wins; only when it is
    /// absent is `id` followed through [`RepoRedirects`] to a moved one.
    pub fn open(&self, id: &RepoId) -> Result<Repository> {
        let repo = self.resolve(id)?;
        if repo.path.join("HEAD").is_file() {
            return Ok(repo);
        }
        if let Some(target) = self.redirect_target(id)? {
            return Ok(target);
        }
        Err(GitdError::RepoNotFound(repo.path))
    }

    /// Open a repository by URL path segments, following redirects.
    pub fn open_parts(&self, owner: &str, repo: &str) -> Result<Repository> {
        let repo = self.resolve_parts(owner, repo)?;
        self.open(&repo.id)
    }

    /// The id `owner/repo` is served as: itself when it exists on disk or
    /// has no redirect, otherwise the current id of the moved repository.
    /// Authorization must use the returned owner.
    pub fn canonical_parts(&self, owner: &str, repo: &str) -> Result<RepoId> {
        let requested = self.resolve_parts(owner, repo)?;
        if requested.path.join("HEAD").is_file() {
            return Ok(requested.id);
        }
        Ok(self
            .redirect_target(&requested.id)?
            .map_or(requested.id, |target| target.id))
    }

    fn redirect_target(&self, id: &RepoId) -> Result<Option<Repository>> {
        let Some(redirects) = &self.redirects else {
            return Ok(None);
        };
        let Some(target) = redirects.redirect(&id.owner, &id.name) else {
            return Ok(None);
        };
        if target == *id {
            return Ok(None);
        }
        let repo = self.resolve(&RepoId::new(target.owner, target.name)?)?;
        if !repo.path.join("HEAD").is_file() {
            return Err(GitdError::RepoNotFound(repo.path));
        }
        Ok(Some(repo))
    }

    /// Move the bare repository `from` to `to` (a rename or a transfer).
    ///
    /// Refuses when `from` is missing or `to` already exists; the owner
    /// directory of `to` is created on demand. The move is one `rename(2)`
    /// within the storage root, so it either happens completely or not at all.
    pub fn relocate_bare(&self, from: &RepoId, to: &RepoId) -> Result<Repository> {
        let source = self.resolve(from)?;
        if !source.path.join("HEAD").is_file() {
            return Err(GitdError::RepoNotFound(source.path));
        }
        let target = self.resolve(to)?;
        if target.path.exists() {
            return Err(GitdError::InvalidInput(format!(
                "repository already exists: {to}"
            )));
        }
        let parent = target
            .path
            .parent()
            .ok_or_else(|| GitdError::InvalidPath("missing repository parent".to_string()))?;
        std::fs::create_dir_all(parent)?;
        std::fs::rename(&source.path, &target.path)?;
        let metadata = target.path.join("jeryu");
        std::fs::create_dir_all(&metadata)?;
        std::fs::write(metadata.join("repo-id"), to.to_string())?;
        Ok(target)
    }

    /// Attach Jeryu metadata to an existing bare repository in this manager.
    pub fn record_existing_bare(&self, id: &RepoId) -> Result<Repository> {
        let repo = self.open(id)?;
        if !repo.path.join("objects").is_dir() || !repo.path.join("refs").is_dir() {
            return Err(GitdError::InvalidInput(format!(
                "repository is not a complete bare Git repo: {}",
                repo.path.display()
            )));
        }
        self.write_metadata(&repo)?;
        Ok(repo)
    }

    /// Mark `repo` archived (read-only) or clear the mark. Idempotent.
    ///
    /// The mark is the file `jeryu/archived` inside the bare repository, so
    /// every receive path (smart HTTP, SSH, the pre-receive hook and
    /// [`crate::refs::RefService`]) sees it without a forge round-trip. The
    /// forge (`ForgeCore::set_repository_archived`) stays the source of truth;
    /// the unified server mirrors its flag here.
    pub fn set_archived(&self, repo: &Repository, archived: bool) -> Result<()> {
        let marker = archived_marker(repo);
        if archived {
            if let Some(parent) = marker.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&marker, b"archived\n")?;
        } else {
            match std::fs::remove_file(&marker) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }

    /// Install Jeryu's server-side pre-receive hook into a bare repository.
    ///
    /// This is intentionally separate from [`Self::create_bare`] so tests and
    /// import tooling can seed fixtures with raw Git, while production
    /// materializers can opt into the durable receive guard after creation.
    pub fn install_pre_receive_hook(&self, repo: &Repository) -> Result<()> {
        let hooks = repo.path.join("hooks");
        std::fs::create_dir_all(&hooks)?;
        let hook = hooks.join("pre-receive");
        std::fs::write(&hook, PRE_RECEIVE_HOOK.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755))?;
        }
        Ok(())
    }

    fn write_metadata(&self, repo: &Repository) -> Result<()> {
        let jf = repo.path.join("jeryu");
        std::fs::create_dir_all(&jf)?;
        std::fs::write(jf.join("phase"), b"phase1-git-server-core\n")?;
        std::fs::write(jf.join("repo-id"), repo.id.to_string())?;
        Ok(())
    }
}

/// Path of the archive mark inside a bare repository.
fn archived_marker(repo: &Repository) -> PathBuf {
    repo.path.join("jeryu").join("archived")
}

impl Repository {
    /// Whether the repository carries the archive mark (read-only).
    #[must_use]
    pub fn is_archived(&self) -> bool {
        archived_marker(self).is_file()
    }

    /// Refuse a write with [`GitdError::RepositoryArchived`] when archived.
    pub fn ensure_writable(&self) -> Result<()> {
        if self.is_archived() {
            return Err(GitdError::RepositoryArchived(self.id.to_string()));
        }
        Ok(())
    }
}
