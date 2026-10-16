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

/// A rebase onto a moved base, and a reworded message, rewrite every commit id
/// and leave the diff identity alone. A changed line does not.
#[test]
fn a_rebase_keeps_the_diff_identity_and_an_edit_changes_it() {
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
    assert_eq!(
        patch_ids("git", &fx.repo, &moved, &rebased).unwrap(),
        before,
        "the rebase changed no content"
    );

    let edited = commit(&fx.work, "more.txt", "more and more\n", "more again");
    fx.publish("refs/heads/feature");
    let after = patch_ids("git", &fx.repo, &moved, &edited).unwrap();
    assert_ne!(after, before);
    assert_eq!(after[0], before[0], "the untouched commit keeps its id");
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
        "#!/bin/sh\nfor arg; do [ \"$arg\" = patch-id ] && exit 128; done\nexec git \"$@\"\n",
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
