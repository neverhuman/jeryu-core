//! The diff identity of a pull-request head, commit by commit.
//!
//! Each digest binds the recorded base object, resulting tree id, commit
//! message, and complete diff bytes (including blob ids and hunk positions).
//! Equal lists therefore
//! cannot carry a verdict across a base change, reword, or relocated edit.
//! Digests carry a `v2:` tag so stored unbound identities cannot carry reviews.
//! Empty, merge-containing, and oversized ranges have no identity.

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
            "--no-replace-objects",
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
        &[
            "--no-replace-objects",
            "rev-list",
            "--reverse",
            "--max-count=257",
            "--end-of-options",
            &range,
        ],
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
                "--no-replace-objects",
                "diff-tree",
                "--no-color",
                "--no-ext-diff",
                "--no-textconv",
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
        let message = run_capture(
            git_bin,
            &[
                "--no-replace-objects",
                "show",
                "-s",
                "--format=%T%n%B",
                "--encoding=none",
                "--no-notes",
                "--end-of-options",
                commit,
            ],
            Some(&repo.path),
        )?;
        match content_digest(base_oid, &message.stdout, &diff.stdout) {
            Some(id) => ids.push(id),
            // A commit with no diff (empty, or mode-only) has no content to
            // compare, so the whole range has no identity.
            None => return Ok(Vec::new()),
        }
    }
    Ok(ids)
}

/// Versioned, length-delimited identity over raw bytes. No lossy text decoding
/// or diff normalization: even a moved hunk or non-UTF-8 content changes it.
fn content_digest(base: &str, message: &[u8], diff: &[u8]) -> Option<String> {
    let content = diff.split(|b| *b == b'\n').any(|line| {
        (line.starts_with(b"+") && !line.starts_with(b"+++"))
            || (line.starts_with(b"-") && !line.starts_with(b"---"))
    });
    if !content {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(b"jeryu-diff-v2\0");
    for bytes in [base.to_ascii_lowercase().as_bytes(), message, diff] {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Some(format!("v2:{digest}"))
}

/// Whether a stored digest uses the base-, tree-, and message-bound format.
/// Untagged digests from earlier producers are audit history only.
pub fn is_review_patch_id(value: &str) -> bool {
    value.strip_prefix("v2:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

/// Fresh commit metadata for protection evaluation. Refuse oversized ranges
/// rather than evaluating an incomplete commit list.
pub fn review_commits(
    git_bin: &str,
    repo: &Repository,
    base: &str,
    head: &str,
) -> Result<Vec<(String, u64, bool)>> {
    verify_commit(git_bin, repo, base)?;
    verify_commit(git_bin, repo, head)?;
    let range = format!("{base}..{head}");
    let output = run_capture(
        git_bin,
        &[
            "--no-replace-objects",
            "rev-list",
            "--parents",
            "--max-count=257",
            "--end-of-options",
            &range,
        ],
        Some(&repo.path),
    )?;
    let text = String::from_utf8_lossy(&output.stdout);
    let rows: Vec<_> = text.lines().collect();
    if rows.len() > MAX_COMMITS {
        return Err(crate::error::GitdError::InvalidInput(
            "review range exceeds 256 commits".into(),
        ));
    }
    let mut commits = Vec::with_capacity(rows.len());
    for row in rows {
        let fields: Vec<_> = row.split_whitespace().collect();
        let sha = fields[0].to_string();
        let verified = run_capture(
            git_bin,
            &["--no-replace-objects", "verify-commit", "--", &sha],
            Some(&repo.path),
        )
        .is_ok();
        commits.push((sha, (fields.len() - 1) as u64, verified));
    }
    Ok(commits)
}
