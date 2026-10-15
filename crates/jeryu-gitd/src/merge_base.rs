//! The merge base a pull request's diff is taken from.
//!
//! The forge records it as the pull request's base after a push
//! (`ForgeCore::record_pull_request_base`), so a head rebased onto a newer
//! base stops showing that base's own commits as its changes. Computed here,
//! beside git, from the real objects.

use crate::command::run_capture;
use crate::error::{GitdError, Result};
use crate::repo::Repository;

/// The merge base of `base_oid` and `head_oid` in `repo`, or `None` when the
/// two commits share no history (git's exit status 1). Any other git failure
/// is an error, never `None`, so a caller cannot mistake a broken repository
/// for unrelated histories.
///
/// Both oids must be full object ids naming commits in `repo`; anything else
/// is refused before it reaches argv.
pub fn merge_base(
    git_bin: &str,
    repo: &Repository,
    base_oid: &str,
    head_oid: &str,
) -> Result<Option<String>> {
    verify_commit(git_bin, repo, base_oid)?;
    verify_commit(git_bin, repo, head_oid)?;
    let out = match run_capture(
        git_bin,
        &["merge-base", "--end-of-options", base_oid, head_oid],
        Some(&repo.path),
    ) {
        Ok(out) => out,
        Err(GitdError::GitCommandFailed { code: Some(1), .. }) => return Ok(None),
        Err(err) => return Err(err),
    };
    let text = String::from_utf8_lossy(&out.stdout);
    match text.split_whitespace().next() {
        Some(oid) if is_object_id(oid) => Ok(Some(oid.to_string())),
        other => Err(GitdError::GitCommandFailed {
            program: format!("{git_bin} merge-base"),
            code: None,
            stderr: format!("unexpected merge base: {}", other.unwrap_or("")),
        }),
    }
}

/// A full-length hexadecimal object id (SHA-1 or SHA-256).
fn is_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Verify that `oid` is a full object id naming a commit in the repository.
fn verify_commit(git_bin: &str, repo: &Repository, oid: &str) -> Result<()> {
    if !is_object_id(oid) {
        return Err(GitdError::InvalidInput(format!(
            "oid must be 40 or 64 hex digits: {oid}"
        )));
    }
    let spec = format!("{oid}^{{commit}}");
    run_capture(
        git_bin,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            &spec,
        ],
        Some(&repo.path),
    )
    .map_err(|_| {
        GitdError::InvalidInput(format!("oid is not a commit in this repository: {oid}"))
    })?;
    Ok(())
}
