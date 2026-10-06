//! The in-memory ForgeCore store.
//!
//! `ForgeCore` is the typed Phase 2 forge store. Its methods are grouped by the
//! resource they operate on into the submodules below; every `impl ForgeCore`
//! block extends the same type, so `crate::core::ForgeCore` and every public
//! method signature resolve exactly as before this file was split out of a
//! single `core.rs`.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::{RwLock, RwLockWriteGuard};
use serde_json::Value;
use uuid::Uuid;

use crate::branch_protection::{BranchProtectionEvaluation, EvaluationContext};
use crate::errors::{ForgeError, Result};
use crate::model::*;
use crate::webhooks::{should_deliver, sign_webhook_payload};

mod accounts;
mod audit;
mod auth;
mod branch_protection;
mod check_runs;
mod commit_status;
mod deployments;
mod issues;
mod jankurai;
mod pull_requests;
mod readmes;
mod repositories;
mod repository_rename;
mod repository_transfer;
mod repository_transfer_state;
mod reviews;
mod storage;
mod waitlist;
mod webhooks;

#[cfg(test)]
mod tests;

pub use audit::AuditEntry;
pub use pull_requests::MergeReadiness;
pub use repositories::RepositoryDeletion;

#[derive(Debug, Clone, Default)]
struct Counters {
    issue: u64,
    pull: u64,
}

#[derive(Debug, Clone, Default)]
struct State {
    users: HashMap<String, User>,
    accounts: HashMap<String, UserAccount>,
    sessions: HashMap<String, WebSession>,
    personal_tokens: HashMap<Uuid, PersonalAccessToken>,
    invitations: HashMap<Uuid, AccountInvitation>,
    activation_challenges: HashMap<String, ActivationChallenge>,
    bootstrap_owner_consumed: bool,
    /// Keyed by the normalized email.
    waitlist: BTreeMap<String, WaitlistSignup>,
    repo_grants: HashMap<(String, String, String), RepoAccessGrant>,
    organizations: HashMap<String, Organization>,
    teams: HashMap<(String, String), Team>,
    repos: HashMap<(String, String), Repository>,
    labels: HashMap<(String, String, String), Label>,
    issues: HashMap<(String, String, u64), Issue>,
    issue_comments: HashMap<(String, String, u64), Vec<IssueComment>>,
    pulls: HashMap<(String, String, u64), PullRequest>,
    reviews: HashMap<(String, String, u64), Vec<Review>>,
    review_comments: HashMap<(String, String, u64), Vec<ReviewComment>>,
    branch_protections: HashMap<(String, String, String), BranchProtectionRule>,
    codeowners: HashMap<(String, String), String>,
    readmes: HashMap<(String, String), String>,
    statuses: HashMap<(String, String, String), Vec<CommitStatus>>,
    check_runs: HashMap<(String, String), Vec<CheckRun>>,
    webhooks: HashMap<(String, String), Vec<Webhook>>,
    webhook_deliveries: Vec<WebhookDelivery>,
    counters: HashMap<(String, String), Counters>,
    jankurai_scores: HashMap<(String, String), Vec<JankuraiScore>>,
    repository_aliases: HashMap<(String, String), RepositoryAlias>,
    repository_transfers: HashMap<String, RepositoryTransferJournal>,
    /// Keyed by id, so iteration is creation order. Durable only through the
    /// dedicated append path, never the State-owned snapshot.
    deployments: BTreeMap<u64, Deployment>,
    /// Append-only, oldest first per deployment.
    deployment_statuses: BTreeMap<u64, Vec<DeploymentStatus>>,
}

fn default_branch_protection_rule(owner: &str, repo: &str, branch: &str) -> BranchProtectionRule {
    BranchProtectionRule {
        owner: owner.to_string(),
        repo: repo.to_string(),
        branch: branch.to_string(),
        required_status_checks: Vec::new(),
        strict: false,
        required_approving_review_count: 0,
        enforce_admins: false,
        required_linear_history: true,
        allow_force_pushes: false,
        allow_deletions: false,
        require_signed_commits: false,
        require_jankurai_proof: false,
        updated_at: Utc::now(),
    }
}

/// Whether any branch protection rule of `owner/repo` requires a status
/// context. Such a repository can never opt out of default-branch protection.
fn repo_requires_status_context(state: &State, owner: &str, repo: &str) -> bool {
    state.branch_protections.values().any(|rule| {
        rule.owner == owner && rule.repo == repo && !rule.required_status_checks.is_empty()
    })
}

fn ensure_default_branch_protection(state: &mut State, repo: &Repository) -> bool {
    if repo.default_branch_protection_opt_out
        && !repo_requires_status_context(state, &repo.owner, &repo.name)
    {
        return false;
    }
    let key = (
        repo.owner.clone(),
        repo.name.clone(),
        repo.default_branch.clone(),
    );
    if state.branch_protections.contains_key(&key) {
        return false;
    }
    state.branch_protections.insert(
        key,
        default_branch_protection_rule(&repo.owner, &repo.name, &repo.default_branch),
    );
    true
}

/// The repository `owner/name` names: the canonical one, else the target of
/// an old-name alias. Aliases are retargeted on every move, so one hop is the
/// whole chain.
fn resolve_repository<'a>(state: &'a State, owner: &str, name: &str) -> Option<&'a Repository> {
    let key = (owner.to_string(), name.to_string());
    if let Some(repo) = state.repos.get(&key) {
        return Some(repo);
    }
    let alias = state.repository_aliases.get(&key)?;
    state
        .repos
        .get(&(alias.canonical_owner.clone(), alias.canonical_name.clone()))
        .filter(|repo| repo.id == alias.repository_id)
}

/// Point every deployment's denormalized `owner/repo` at the current slug of
/// its repository (matched by UUID).
fn refresh_deployment_slugs(state: &mut State) {
    let slugs: HashMap<Uuid, (String, String)> = state
        .repos
        .values()
        .map(|repo| (repo.id, (repo.owner.clone(), repo.name.clone())))
        .collect();
    for deployment in state.deployments.values_mut() {
        if let Some((owner, name)) = slugs.get(&deployment.repository_id) {
            deployment.owner.clone_from(owner);
            deployment.repo.clone_from(name);
        }
    }
}

fn backfill_default_branch_protections(state: &mut State) -> usize {
    let repos: Vec<_> = state.repos.values().cloned().collect();
    repos
        .into_iter()
        .filter(|repo| ensure_default_branch_protection(state, repo))
        .count()
}

/// Materializes a newly created repository's bare git directory on disk.
///
/// Defined in the pure forge core so `create_repository` can trigger on-disk
/// creation without `jeryu-core` depending on the git-daemon crate: the unified
/// `jeryu serve` injects a `jeryu-gitd`-backed implementation via
/// [`ForgeCore::with_repo_materializer`]. With no materializer set (the default,
/// e.g. in unit tests) repository creation stays metadata-only.
pub trait RepoMaterializer: std::fmt::Debug + Send + Sync {
    /// Create the bare repository for `owner/name` with `default_branch` as its
    /// initial `HEAD`. Implementations MUST be idempotent: an already-present
    /// repository is success, not an error.
    fn materialize(&self, owner: &str, name: &str, default_branch: &str) -> Result<()>;
}

/// Reads push history from a repository's git storage.
///
/// Like [`RepoMaterializer`], defined here so `jeryu-core` stays free of the
/// git-daemon crate: the unified `jeryu serve` backs it with
/// `jeryu_gitd::RepoManager::newest_committer_time` and hands it to
/// [`ForgeCore::backfill_repository_pushed_at`] once after opening the store.
pub trait RepoPushHistory: std::fmt::Debug + Send + Sync {
    /// Newest committer date across all refs of `owner/name`
    /// (`git for-each-ref --sort=-committerdate --count=1`); `None` when the
    /// repository has no commits or no bare directory on disk.
    fn newest_commit_time(&self, owner: &str, name: &str) -> Result<Option<DateTime<Utc>>>;
}

/// Answers whether a branch exists in a repository's git storage.
///
/// Like [`RepoPushHistory`], defined here so `jeryu-core` stays free of the
/// git-daemon crate; the caller of
/// [`ForgeCore::set_repository_default_branch`] backs it with the bare repo.
pub trait RepoBranches: std::fmt::Debug + Send + Sync {
    /// `true` when `refs/heads/<branch>` exists in `owner/name`.
    fn branch_exists(&self, owner: &str, name: &str, branch: &str) -> Result<bool>;
}

/// Moves a repository's bare git directory on disk for a rename or transfer.
///
/// Like [`RepoMaterializer`], defined here so `jeryu-core` stays free of the
/// git-daemon crate: the unified `jeryu serve` backs it with
/// `jeryu_gitd::RepoManager::relocate_bare` via
/// [`ForgeCore::with_repo_relocator`]. With none set, renames are
/// metadata-only.
pub trait RepoRelocator: std::fmt::Debug + Send + Sync {
    /// Move `from_owner/from_name` to `to_owner/to_name`. Must either move the
    /// directory completely or leave it where it was and return an error.
    fn relocate(
        &self,
        from_owner: &str,
        from_name: &str,
        to_owner: &str,
        to_name: &str,
    ) -> Result<()>;
}

#[derive(Debug, Clone, Default)]
pub struct ForgeCore {
    state: Arc<RwLock<State>>,
    storage: Option<Arc<storage::SqliteStore>>,
    repo_materializer: Option<Arc<dyn RepoMaterializer>>,
    repo_relocator: Option<Arc<dyn RepoRelocator>>,
}

impl ForgeCore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inject a [`RepoMaterializer`] so repository creation also writes a bare
    /// git repository to disk (used by the unified `jeryu serve`).
    #[must_use]
    pub fn with_repo_materializer(mut self, materializer: Arc<dyn RepoMaterializer>) -> Self {
        self.repo_materializer = Some(materializer);
        self
    }

    /// Inject a [`RepoRelocator`] so [`Self::rename_repository`] also moves
    /// the bare git repository on disk (used by the unified `jeryu serve`).
    #[must_use]
    pub fn with_repo_relocator(mut self, relocator: Arc<dyn RepoRelocator>) -> Self {
        self.repo_relocator = Some(relocator);
        self
    }

    pub fn open_sqlite(path: impl AsRef<Path>) -> Result<Self> {
        let (storage, state) = storage::SqliteStore::open(path)?;
        Ok(Self {
            state: Arc::new(RwLock::new(state)),
            storage: Some(Arc::new(storage)),
            repo_materializer: None,
            repo_relocator: None,
        })
    }

    /// Strict existence check on the canonical slug. Internal writers key
    /// state by the `(owner, repo)` they were given, so they must never follow
    /// an old-name alias.
    fn ensure_repo_exists(&self, owner: &str, repo: &str) -> Result<()> {
        self.canonical_repository(owner, repo).map(|_| ())
    }

    /// Refuse a write to `owner/repo` when it is archived.
    ///
    /// Unknown repositories are `NotFound`; archived ones are
    /// `RepositoryArchived`. Every mutating path of an archived repository
    /// (ref updates, pull requests, reviews, merges, statuses, check runs)
    /// goes through this check; the git edge calls it before accepting a push.
    pub fn ensure_repository_writable(&self, owner: &str, repo: &str) -> Result<()> {
        if self.get_repository(owner, repo)?.archived {
            return Err(ForgeError::RepositoryArchived(format!("{owner}/{repo}")));
        }
        Ok(())
    }

    fn persist_after_mutation(
        &self,
        state: &mut RwLockWriteGuard<'_, State>,
        previous: State,
    ) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        if let Err(error) = storage.persist(state) {
            **state = previous;
            return Err(error);
        }
        Ok(())
    }
}

fn require_name(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(ForgeError::Validation(format!("{field} cannot be empty")))
    } else {
        Ok(())
    }
}

fn slugify(value: &str) -> String {
    value
        .trim()
        .to_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Allocates the next number in a repository's single issue/pull number space.
///
/// Issues and pull requests share one sequence, the way GitHub numbers them: a
/// PR is an issue, so PR #N and issue #N are the same record and a comment
/// posted through the issues route reaches the PR it names. The two stored
/// counters are kept in step (both set to the number just handed out) so a
/// repository whose counters drifted apart before they were unified never
/// reuses a number that is already live.
fn next_record_number(state: &mut State, owner: &str, repo: &str) -> u64 {
    let counters = state
        .counters
        .entry((owner.to_string(), repo.to_string()))
        .or_default();
    let number = counters.issue.max(counters.pull) + 1;
    counters.issue = number;
    counters.pull = number;
    number
}

/// Whether jeryu enforces a passing `jankurai/proof` check on every merge,
/// family-wide. Driven by the `[audit].enforce_merge` setting, surfaced to this
/// domain layer via `JERYU_AUDIT_ENFORCE_MERGE`. Default `false` (the shadow
/// phase: scores are still recorded and the proof check published, but the merge
/// stays advisory). Flip to a truthy value once the fleet is green.
fn audit_merge_enforced() -> bool {
    matches!(
        std::env::var("JERYU_AUDIT_ENFORCE_MERGE")
            .ok()
            .as_deref()
            .map(str::trim),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

fn evaluate_locked(
    state: &State,
    pr: &PullRequest,
    requested_sha: Option<&str>,
) -> BranchProtectionEvaluation {
    use crate::branch_protection::evaluate_branch_protection_with;

    let protection = state.branch_protections.get(&(
        pr.owner.clone(),
        pr.repo.clone(),
        pr.base.ref_name.clone(),
    ));
    let reviews = match state
        .reviews
        .get(&(pr.owner.clone(), pr.repo.clone(), pr.number))
    {
        Some(reviews) => reviews.clone(),
        None => Vec::new(),
    };
    let statuses =
        match state
            .statuses
            .get(&(pr.owner.clone(), pr.repo.clone(), pr.head.sha.clone()))
        {
            Some(statuses) => statuses.clone(),
            None => Vec::new(),
        };
    let check_runs = match state.check_runs.get(&(pr.owner.clone(), pr.repo.clone())) {
        Some(check_runs) => check_runs
            .iter()
            .filter(|check| check.head_sha == pr.head.sha)
            .cloned()
            .collect::<Vec<_>>(),
        None => Vec::new(),
    };
    let codeowners = state.codeowners.get(&(pr.owner.clone(), pr.repo.clone()));
    let context = EvaluationContext {
        codeowners: codeowners.map(String::as_str),
        actor_is_admin: false,
        jankurai_proof_mandatory: audit_merge_enforced(),
    };
    evaluate_branch_protection_with(
        pr,
        protection,
        &reviews,
        &statuses,
        &check_runs,
        requested_sha,
        context,
    )
}

fn apply_evaluation(pr: &mut PullRequest, evaluation: BranchProtectionEvaluation) {
    // Terminal states are sticky. GitHub never resurrects a Merged or Closed PR
    // by recomputing mergeability on read: a merged PR stays merged, and a
    // closed PR stays closed until it is explicitly reopened. Previously only
    // `merged` was sticky, so a Closed PR with no blocking protection was
    // silently reverted to Mergeable on the next read (pinned by the former
    // `closing_a_mergeable_pr_does_not_stick`). This is the deliberate
    // correctness fix.
    if pr.merged || pr.state == PullRequestState::Merged {
        pr.mergeable = false;
        pr.mergeable_state = "merged".to_string();
        return;
    }
    if pr.state == PullRequestState::Closed {
        pr.mergeable = false;
        pr.mergeable_state = "closed".to_string();
        return;
    }
    pr.mergeable = evaluation.mergeable;
    pr.mergeable_state = evaluation.state;
    if pr.draft {
        pr.state = PullRequestState::Draft;
    } else if evaluation.mergeable {
        pr.state = PullRequestState::Mergeable;
    } else {
        pr.state = PullRequestState::BlockedByChecks;
    }
}

fn refresh_pull_mergeability_for_sha(state: &mut State, owner: &str, repo: &str, sha: &str) {
    let keys: Vec<_> = state
        .pulls
        .iter()
        .filter(|((pull_owner, pull_repo, _), pr)| {
            pull_owner == owner && pull_repo == repo && pr.head.sha == sha
        })
        .map(|(key, _)| key.clone())
        .collect();

    for key in keys {
        if let Some(snapshot) = state.pulls.get(&key).cloned() {
            let mut updated = snapshot;
            let evaluation = evaluate_locked(state, &updated, None);
            apply_evaluation(&mut updated, evaluation);
            state.pulls.insert(key, updated);
        }
    }
}

fn emit_event_locked(state: &mut State, owner: &str, repo: &str, event: &str, payload: Value) {
    let hooks = match state.webhooks.get(&(owner.to_string(), repo.to_string())) {
        Some(hooks) => hooks.clone(),
        None => Vec::new(),
    };
    for hook in hooks.iter().filter(|hook| should_deliver(hook, event)) {
        // A delivery's payload is always an internal `json!(domain_struct)`
        // value, which cannot fail to serialize; encode it explicitly so a
        // hypothetical failure surfaces as a panic at the bug site rather than
        // being silently signed as an empty body.
        let payload_bytes = match serde_json::to_vec(&payload) {
            Ok(bytes) => bytes,
            Err(error) => unreachable!("forge webhook payload is always serializable: {error}"),
        };
        let signature_256 = hook
            .config
            .secret
            .as_ref()
            .map(|secret| sign_webhook_payload(secret, &payload_bytes));
        state.webhook_deliveries.push(WebhookDelivery {
            id: Uuid::new_v4(),
            hook_id: hook.id,
            owner: owner.to_string(),
            repo: repo.to_string(),
            event: event.to_string(),
            target_url: hook.config.url.clone(),
            payload: payload.clone(),
            signature_256,
            delivered: false,
            created_at: Utc::now(),
        });
    }
}
