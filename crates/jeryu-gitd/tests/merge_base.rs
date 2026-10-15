mod common;

use jeryu_gitd::error::GitdError;
use jeryu_gitd::merge_base;
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

/// After a rebase onto a moved main, the merge base is the moved main, not
/// the tip the pull request was opened against.
#[test]
fn the_merge_base_of_a_rebased_head_is_the_moved_base() {
    if !common::git_available() {
        return;
    }
    let fx = seed("jeryu-merge-base-rebase");
    let base = fx.main_oid.clone();
    let head = commit(&fx.work, "feature.txt", "feature\n", "feature");
    fx.publish("refs/heads/feature");
    assert_eq!(
        merge_base("git", &fx.repo, &base, &head)
            .unwrap()
            .as_deref(),
        Some(base.as_str())
    );

    git(&fx.work, &["checkout", "--quiet", "--detach", &base]);
    let moved = commit(&fx.work, "other.txt", "other\n", "unrelated");
    fx.publish("refs/heads/main");
    let rebased = commit(&fx.work, "feature.txt", "feature\n", "feature");
    fx.publish("refs/heads/feature");
    assert_eq!(
        merge_base("git", &fx.repo, &moved, &rebased)
            .unwrap()
            .as_deref(),
        Some(moved.as_str())
    );
    fx.cleanup();
}

#[test]
fn unrelated_histories_have_no_merge_base() {
    if !common::git_available() {
        return;
    }
    let fx = seed("jeryu-merge-base-unrelated");
    git(&fx.work, &["checkout", "--quiet", "--orphan", "other"]);
    let orphan = commit(&fx.work, "other.txt", "other\n", "orphan");
    fx.publish("refs/heads/other");
    assert_eq!(
        merge_base("git", &fx.repo, &fx.main_oid, &orphan).unwrap(),
        None
    );
    fx.cleanup();
}

#[test]
fn only_full_commit_ids_of_this_repository_reach_git() {
    if !common::git_available() {
        return;
    }
    let fx = seed("jeryu-merge-base-input");
    let main = fx.main_oid.clone();
    for bad in [
        "--all",
        "HEAD",
        &main[..12],
        "0000000000000000000000000000000000000000",
    ] {
        let error = merge_base("git", &fx.repo, bad, &main).unwrap_err();
        assert!(
            matches!(error, GitdError::InvalidInput(_)),
            "{bad}: {error}"
        );
    }
    fx.cleanup();
}

/// A git failure other than "no shared history" is an error, never `None`.
#[test]
fn a_failing_git_is_an_error_not_unrelated_histories() {
    if !common::git_available() {
        return;
    }
    let fx = seed("jeryu-merge-base-broken");
    let fake = fx.work.join("broken-git");
    std::fs::write(
        &fake,
        "#!/bin/sh\nfor arg; do [ \"$arg\" = merge-base ] && exit 128; done\nexit 0\n",
    )
    .unwrap();
    let status = Command::new("chmod").arg("+x").arg(&fake).status().unwrap();
    assert!(status.success());
    let result = merge_base(fake.to_str().unwrap(), &fx.repo, &fx.main_oid, &fx.main_oid);
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
