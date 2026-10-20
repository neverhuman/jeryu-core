mod common;

use jeryu_gitd::error::GitdError;
use jeryu_gitd::patch_ids;
use jeryu_gitd::repo::Repository;
use jeryu_gitd::{GitdConfig, RepoId, RepoManager};
use std::path::{Path, PathBuf};
use std::process::Command;

struct Fixture {
    root: PathBuf,
    work: PathBuf,
    repo: Repository,
    main_oid: String,
}

impl Fixture {
    fn publish(&self, refname: &str) {
        git(
            &self.work,
            &[
                "push",
                "--quiet",
                "--force",
                self.repo.path.to_str().unwrap(),
                &format!("HEAD:{refname}"),
            ],
        );
    }

    fn cleanup(self) {
        let _ = std::fs::remove_dir_all(&self.root);
        let _ = std::fs::remove_dir_all(&self.work);
    }
}

fn seed(prefix: &str) -> Fixture {
    let root = common::temp_dir(&format!("{prefix}-root"));
    let work = common::temp_dir(&format!("{prefix}-work"));
    let manager = RepoManager::new(GitdConfig::new(&root));
    let repo = manager
        .create_bare(&RepoId::new("acme", "demo").unwrap())
        .unwrap();
    git(&work, &["init", "--quiet", "-b", "main"]);
    git(&work, &["config", "user.email", "test@example.invalid"]);
    git(&work, &["config", "user.name", "Test"]);
    let main_oid = commit(&work, "README.md", "hello\n", "seed");
    let fixture = Fixture {
        root,
        work,
        repo,
        main_oid,
    };
    fixture.publish("refs/heads/main");
    fixture
}

fn git(cwd: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn commit(work: &Path, file: &str, body: &str, message: &str) -> String {
    std::fs::write(work.join(file), body).unwrap();
    git(work, &["add", file]);
    git(work, &["commit", "--quiet", "-m", message]);
    git(work, &["rev-parse", "HEAD"])
}

/// A changed base or message changes the identity even when the patch stays the same.
#[test]
fn base_changes_and_edits_change_the_diff_identity() {
    if !common::git_available() {
        return;
    }
    let fx = seed("jeryu-patch-ids-rebase");
    let base = fx.main_oid.clone();
    commit(&fx.work, "feature.txt", "feature\n", "feature");
    let head = commit(&fx.work, "more.txt", "more\n", "more");
    fx.publish("refs/heads/feature");
    let before = patch_ids("git", &fx.repo, &base, &head).unwrap();
    assert_eq!(before.len(), 2);

    git(&fx.work, &["checkout", "--quiet", "--detach", &base]);
    let moved = commit(&fx.work, "other.txt", "other\n", "unrelated");
    fx.publish("refs/heads/main");
    commit(&fx.work, "feature.txt", "feature\n", "feature reworded");
    let rebased = commit(&fx.work, "more.txt", "more\n", "more");
    fx.publish("refs/heads/feature");
    assert_ne!(rebased, head);
    assert_ne!(
        patch_ids("git", &fx.repo, &moved, &rebased).unwrap(),
        before,
        "a new base and message require review"
    );

    let edited = commit(&fx.work, "more.txt", "more and more\n", "more again");
    fx.publish("refs/heads/feature");
    let after = patch_ids("git", &fx.repo, &moved, &edited).unwrap();
    assert_ne!(after, before);
    assert_ne!(after[0], before[0], "the base changed");
    fx.cleanup();
}

/// An empty range has no diff identity, and Core reads that as unknown rather
/// than as "the same diff".
#[test]
fn a_range_with_no_commits_has_no_patch_ids() {
    if !common::git_available() {
        return;
    }
    let fx = seed("jeryu-patch-ids-empty");
    let main = fx.main_oid.clone();
    assert!(patch_ids("git", &fx.repo, &main, &main).unwrap().is_empty());
    fx.cleanup();
}

#[test]
fn only_full_commit_ids_of_this_repository_reach_git() {
    if !common::git_available() {
        return;
    }
    let fx = seed("jeryu-patch-ids-input");
    let main = fx.main_oid.clone();
    for bad in [
        "--all",
        "HEAD",
        &main[..12],
        "0000000000000000000000000000000000000000",
    ] {
        let error = patch_ids("git", &fx.repo, bad, &main).unwrap_err();
        assert!(
            matches!(error, GitdError::InvalidInput(_)),
            "{bad}: {error}"
        );
    }
    fx.cleanup();
}

/// A failing git is an error, never an empty diff identity.
#[test]
fn a_failing_git_is_an_error_not_an_empty_diff_identity() {
    if !common::git_available() {
        return;
    }
    let fx = seed("jeryu-patch-ids-broken");
    let head = commit(&fx.work, "feature.txt", "feature\n", "feature");
    fx.publish("refs/heads/feature");
    let fake = fx.work.join("broken-git");
    std::fs::write(
        &fake,
        "#!/bin/sh\nfor arg; do [ \"$arg\" = diff-tree ] && exit 128; done\nexec git \"$@\"\n",
    )
    .unwrap();
    let status = Command::new("chmod").arg("+x").arg(&fake).status().unwrap();
    assert!(status.success());
    let result = patch_ids(fake.to_str().unwrap(), &fx.repo, &fx.main_oid, &head);
    assert!(
        matches!(
            result,
            Err(GitdError::GitCommandFailed {
                code: Some(128),
                ..
            })
        ),
        "{result:?}"
    );
    fx.cleanup();
}

/// A merge commit's resolution is no single diff, so a range holding one has
/// no identity: an approval can never carry over a hand-edited merge.
#[test]
fn a_range_with_a_merge_has_no_diff_identity() {
    if !common::git_available() {
        return;
    }
    let fx = seed("jeryu-patch-ids-merge");
    let base = fx.main_oid.clone();
    commit(&fx.work, "feature.txt", "feature\n", "feature");
    git(&fx.work, &["checkout", "--quiet", "-b", "side", &base]);
    commit(&fx.work, "side.txt", "side\n", "side");
    git(&fx.work, &["checkout", "--quiet", "-"]);
    git(
        &fx.work,
        &["merge", "--quiet", "--no-edit", "--no-ff", "side"],
    );
    let merged = git(&fx.work, &["rev-parse", "HEAD"]);
    fx.publish("refs/heads/feature");
    assert!(
        patch_ids("git", &fx.repo, &base, &merged)
            .unwrap()
            .is_empty()
    );
    fx.cleanup();
}

/// Whitespace is content: re-indenting a line changes the identity (git
/// patch-id would call the two the same).
#[test]
fn a_whitespace_only_change_changes_the_diff_identity() {
    if !common::git_available() {
        return;
    }
    let fx = seed("jeryu-patch-ids-whitespace");
    let base = fx.main_oid.clone();
    let spaced = commit(&fx.work, "job.py", "if ok:\n    run()\n", "job");
    fx.publish("refs/heads/feature");
    let before = patch_ids("git", &fx.repo, &base, &spaced).unwrap();
    git(&fx.work, &["checkout", "--quiet", "--detach", &base]);
    let tabbed = commit(&fx.work, "job.py", "if ok:\nrun()\n", "job");
    fx.publish("refs/heads/feature");
    let after = patch_ids("git", &fx.repo, &base, &tabbed).unwrap();
    assert_eq!(before.len(), 1);
    assert_eq!(after.len(), 1);
    assert_ne!(before, after);
    fx.cleanup();
}

/// A commit with no diff has no content to compare, so the range has none.
#[test]
fn a_range_with_an_empty_commit_has_no_diff_identity() {
    if !common::git_available() {
        return;
    }
    let fx = seed("jeryu-patch-ids-empty-commit");
    let base = fx.main_oid.clone();
    commit(&fx.work, "feature.txt", "feature\n", "feature");
    git(
        &fx.work,
        &["commit", "--quiet", "--allow-empty", "-m", "nothing"],
    );
    let head = git(&fx.work, &["rev-parse", "HEAD"]);
    fx.publish("refs/heads/feature");
    assert!(patch_ids("git", &fx.repo, &base, &head).unwrap().is_empty());
    fx.cleanup();
}

/// Repeated context must not make edits at different occurrences equivalent.
#[test]
fn repeated_blocks_at_different_positions_have_distinct_identities() {
    let fx = seed("jeryu-patch-ids-positions");
    let block = "before\ncontext\nunchanged\ntarget\nafter\ncontext\nunchanged\nseparator\n";
    let body = block.repeat(4);
    let base = commit(&fx.work, "list", &body, "repeated blocks");
    let first = body.replacen("target", "edited", 1);
    let first_head = commit(&fx.work, "list", &first, "edit");
    fx.publish("refs/heads/feature");
    let first_ids = patch_ids("git", &fx.repo, &base, &first_head).unwrap();
    git(&fx.work, &["checkout", "-q", "--detach", &base]);
    let offset = block.len();
    let second = format!(
        "{}{}",
        &body[..offset],
        body[offset..].replacen("target", "edited", 1)
    );
    let second_head = commit(&fx.work, "list", &second, "edit");
    fx.publish("refs/heads/feature");
    assert_ne!(
        first_ids,
        patch_ids("git", &fx.repo, &base, &second_head).unwrap()
    );
    fx.cleanup();
}

#[test]
fn base_alone_and_message_alone_change_identity() {
    let fx = seed("jeryu-patch-ids-bindings");
    let base = fx.main_oid.clone();
    let head = commit(&fx.work, "feature", "feature\n", "feature");
    fx.publish("refs/heads/feature");
    let before = patch_ids("git", &fx.repo, &base, &head).unwrap();
    git(&fx.work, &["commit", "-q", "--amend", "-m", "reword"]);
    let reword = git(&fx.work, &["rev-parse", "HEAD"]);
    fx.publish("refs/heads/feature");
    assert_ne!(before, patch_ids("git", &fx.repo, &base, &reword).unwrap());
    git(&fx.work, &["checkout", "-q", "--detach", &base]);
    let moved = commit(&fx.work, "other", "base moves\n", "base moves");
    git(&fx.work, &["cherry-pick", &head]);
    let rebased = git(&fx.work, &["rev-parse", "HEAD"]);
    fx.publish("refs/heads/feature");
    assert_ne!(
        before,
        patch_ids("git", &fx.repo, &moved, &rebased).unwrap()
    );
    fx.cleanup();
}

#[test]
fn the_producer_accepts_256_commits_and_refuses_257() {
    let fx = seed("jeryu-patch-ids-limit");
    let base_tree = git(&fx.work, &["rev-parse", "HEAD^{tree}"]);
    commit(&fx.work, "feature", "feature\n", "feature");
    let feature_tree = git(&fx.work, &["rev-parse", "HEAD^{tree}"]);
    let mut parent = fx.main_oid.clone();
    for index in 0..257 {
        let tree = if index % 2 == 0 {
            &feature_tree
        } else {
            &base_tree
        };
        parent = git(
            &fx.work,
            &["commit-tree", tree, "-p", &parent, "-m", "change"],
        );
        if index == 255 {
            git(&fx.work, &["checkout", "-q", "--detach", &parent]);
            fx.publish("refs/heads/feature");
            assert_eq!(
                patch_ids("git", &fx.repo, &fx.main_oid, &parent)
                    .unwrap()
                    .len(),
                256
            );
        }
    }
    git(&fx.work, &["checkout", "-q", "--detach", &parent]);
    fx.publish("refs/heads/feature");
    assert!(
        patch_ids("git", &fx.repo, &fx.main_oid, &parent)
            .unwrap()
            .is_empty()
    );
    assert!(jeryu_gitd::patch_id::review_commits("git", &fx.repo, &fx.main_oid, &parent).is_err());
    fx.cleanup();
}

#[test]
fn replace_refs_cannot_substitute_reviewed_objects() {
    let fx = seed("jeryu-patch-ids-replace");
    let reviewed = commit(&fx.work, "feature", "reviewed\n", "feature");
    fx.publish("refs/heads/reviewed");
    let approved = patch_ids("git", &fx.repo, &fx.main_oid, &reviewed).unwrap();
    git(&fx.work, &["checkout", "-q", "--detach", &fx.main_oid]);
    let changed = commit(&fx.work, "feature", "unreviewed\n", "feature");
    fx.publish("refs/heads/feature");
    let before = patch_ids("git", &fx.repo, &fx.main_oid, &changed).unwrap();
    assert_ne!(approved, before);
    git(&fx.repo.path, &["replace", &changed, &reviewed]);
    assert_eq!(
        before,
        patch_ids("git", &fx.repo, &fx.main_oid, &changed).unwrap()
    );
    fx.cleanup();
}
