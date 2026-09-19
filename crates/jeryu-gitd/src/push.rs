//! Push bookkeeping: detect pushes that actually moved a ref and report them.
//!
//! `jeryu-gitd` does not depend on the forge core. A successful push is
//! recorded as a repository-local `jeryu/pushed_at` marker plus a receipt, and
//! handed to an optional [`PushObserver`] that the unified `jeryu serve` wires
//! to `ForgeCore::record_repository_push`. Rejected or no-op pushes leave every
//! ref unchanged and are never reported.

use crate::audit::append_receipt;
use crate::command::run_capture;
use crate::error::Result;
use crate::repo::{RepoId, Repository};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Receives successful-push notifications.
pub trait PushObserver: std::fmt::Debug + Send + Sync {
    /// `repo` accepted a push (or server-side ref update) at `at`.
    fn repository_pushed(&self, repo: &RepoId, at: SystemTime);
}

/// Opaque snapshot of every ref and its target, taken around a push.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefSnapshot(Vec<u8>);

/// Capture every ref and its target oid.
pub fn ref_snapshot(git_bin: &str, repo: &Repository) -> Result<RefSnapshot> {
    let output = run_capture(
        git_bin,
        &["for-each-ref", "--format=%(objectname) %(refname)"],
        Some(&repo.path),
    )?;
    Ok(RefSnapshot(output.stdout))
}

/// Newest committer date across all refs
/// (`git for-each-ref --sort=-committerdate --count=1`); `None` for a
/// repository without commits.
pub fn newest_committer_time(git_bin: &str, repo: &Repository) -> Result<Option<SystemTime>> {
    let output = run_capture(
        git_bin,
        &[
            "for-each-ref",
            "--sort=-committerdate",
            "--count=1",
            "--format=%(committerdate:unix)",
        ],
        Some(&repo.path),
    )?;
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|secs| *secs > 0)
        .map(|secs| UNIX_EPOCH + Duration::from_secs(secs)))
}

/// Write the `jeryu/pushed_at` marker (Unix seconds) and a `push` receipt.
pub(crate) fn write_push_marker(repo: &Repository, at: SystemTime) -> Result<()> {
    let secs = at
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let dir = repo.path.join("jeryu");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("pushed_at"), format!("{secs}\n"))?;
    append_receipt(&repo.path, "push", &repo.id.to_string())
}

/// Read the `jeryu/pushed_at` marker; `None` before the first recorded push.
pub fn read_push_marker(repo: &Repository) -> Result<Option<SystemTime>> {
    let path = repo.path.join("jeryu").join("pushed_at");
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    Ok(text
        .trim()
        .parse::<u64>()
        .ok()
        .map(|secs| UNIX_EPOCH + Duration::from_secs(secs)))
}
