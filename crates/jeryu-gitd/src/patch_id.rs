//! The diff identity of a pull-request head, commit by commit.
//!
//! A rebase that changes no content rewrites every commit id but leaves each
//! commit's diff alone. Core cannot see that: it holds no git objects, only
//! shas. So the diff identity is computed here, beside git, as git's own
//! per-commit patch ids (`git patch-id --stable`, the identity `git range-diff`
//! compares with), and recorded on the pull request
//! (`ForgeCore::refresh_pull_request_heads_for_ref_with_diff`). Two heads whose
//! patch-id lists are equal have the same diff, so an approval of one is an
//! approval of the other.

use crate::command::{run_capture, run_with_stdin};
use crate::error::{GitdError, Result};
use crate::merge_base::{is_object_id, verify_commit};
use crate::repo::Repository;

/// Ordered patch ids of the commits in `base_oid..head_oid`, oldest first.
///
/// Merge commits have no single diff and are skipped, as `git range-diff`
/// skips them. An empty range yields an empty list, which Core reads as "no
/// diff identity" and never treats as equal to another head.
///
/// Both oids must be full object ids naming commits in `repo`; anything else
/// is refused before it reaches argv.
pub fn patch_ids(
    git_bin: &str,
    repo: &Repository,
    base_oid: &str,
    head_oid: &str,
) -> Result<Vec<String>> {
    verify_commit(git_bin, repo, base_oid)?;
    verify_commit(git_bin, repo, head_oid)?;
    let range = format!("{base_oid}..{head_oid}");
    let log = run_capture(
        git_bin,
        &[
            "log",
            "--no-color",
            "--no-merges",
            "--reverse",
            "--patch",
            "--end-of-options",
            &range,
        ],
        Some(&repo.path),
    )?;
    if log.stdout.is_empty() {
        return Ok(Vec::new());
    }
    let ids = run_with_stdin(
        git_bin,
        &["patch-id", "--stable"],
        &log.stdout,
        Some(&repo.path),
    )?;
    let text = String::from_utf8_lossy(&ids.stdout);
    let mut patch_ids = Vec::new();
    for line in text.lines() {
        // Each line is "<patch id> <commit id>"; an empty commit produces none.
        match line.split_whitespace().next() {
            Some(id) if is_object_id(id) => patch_ids.push(id.to_string()),
            _ => {
                return Err(GitdError::GitCommandFailed {
                    program: format!("{git_bin} patch-id"),
                    code: None,
                    stderr: format!("unexpected patch id line: {line}"),
                });
            }
        }
    }
    Ok(patch_ids)
}
