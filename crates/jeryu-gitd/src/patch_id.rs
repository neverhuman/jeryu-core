//! The diff identity of a pull-request head, commit by commit.
//!
//! A rebase that changes no content rewrites every commit id but leaves each
//! commit's diff alone. Core cannot see that: it holds no git objects, only
//! shas. So the diff identity is computed here, beside git, and recorded on
//! the pull request (`ForgeCore::refresh_pull_request_heads_for_ref_with_diff`):
//! one digest per commit of that commit's own diff against its first parent.
//!
//! The identity is built to fail closed. It is a SHA-256 of the diff text with
//! only the parts a rebase moves taken out (the `index` lines naming blobs and
//! the line numbers in hunk headers), so every content byte, whitespace
//! included, is in it -- unlike `git patch-id`, which ignores whitespace and
//! would let an indentation change in Python or YAML keep an approval. A range
//! that holds a merge commit (whose conflict resolution is no single diff), a
//! commit with no diff, or more than [`MAX_COMMITS`] commits has no identity:
//! the list is empty, which Core reads as "unknown" and never as equal.

use sha2::{Digest, Sha256};

use crate::command::run_capture;
use crate::error::Result;
use crate::merge_base::verify_commit;
use crate::repo::Repository;

/// The most commits a range may hold and still get a diff identity.
pub const MAX_COMMITS: usize = 256;

/// Ordered diff digests of the commits in `base_oid..head_oid`, oldest first,
/// or an empty list when the range has no identity (see the module docs).
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
    let merges = run_capture(
        git_bin,
        &[
            "rev-list",
            "--merges",
            "--count",
            "--end-of-options",
            &range,
        ],
        Some(&repo.path),
    )?;
    if String::from_utf8_lossy(&merges.stdout).trim() != "0" {
        return Ok(Vec::new());
    }
    let listed = run_capture(
        git_bin,
        &["rev-list", "--reverse", "--end-of-options", &range],
        Some(&repo.path),
    )?;
    let commits: Vec<String> = String::from_utf8_lossy(&listed.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    if commits.is_empty() || commits.len() > MAX_COMMITS {
        return Ok(Vec::new());
    }
    let mut ids = Vec::with_capacity(commits.len());
    for commit in &commits {
        let diff = run_capture(
            git_bin,
            &[
                "diff-tree",
                "--no-color",
                "--no-commit-id",
                "--no-renames",
                "--full-index",
                "-r",
                "-p",
                "--end-of-options",
                commit,
            ],
            Some(&repo.path),
        )?;
        match content_digest(&diff.stdout) {
            Some(id) => ids.push(id),
            // A commit with no diff (empty, or mode-only) has no content to
            // compare, so the whole range has no identity.
            None => return Ok(Vec::new()),
        }
    }
    Ok(ids)
}

/// SHA-256 of a commit's diff with the rebase-moved parts removed: `index`
/// lines (blob ids) and the line numbers of hunk headers. `None` for a diff
/// with no content line.
fn content_digest(diff: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(diff);
    let mut hasher = Sha256::new();
    let mut content = false;
    for line in text.split_inclusive('\n') {
        if line.starts_with("index ") {
            continue;
        }
        if line.starts_with("@@") {
            // "@@ -a,b +c,d @@ context": keep only the marker, the numbers move
            // with every rebase.
            hasher.update(b"@@\n");
            continue;
        }
        if line.starts_with('+') && !line.starts_with("+++")
            || line.starts_with('-') && !line.starts_with("---")
        {
            content = true;
        }
        hasher.update(line.as_bytes());
    }
    content.then(|| {
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    })
}
