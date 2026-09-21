//! Clone, fetch and push by a renamed repository's old name.

use super::SmartHttpServer;
use super::tests::{
    git_output, run_command, run_git, seed_repository, start_test_server, temp_dir,
};
use crate::repo::RepoRedirects;
use crate::{GitdConfig, GitdError, RepoId, RepoManager};
use std::collections::HashMap;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// Fixed old-slug → current-slug table standing in for the forge aliases.
#[derive(Debug, Default)]
struct StaticRedirects(HashMap<(String, String), RepoId>);

impl StaticRedirects {
    fn with(mut self, owner: &str, name: &str, target: &RepoId) -> Self {
        self.0
            .insert((owner.to_string(), name.to_string()), target.clone());
        self
    }
}

impl RepoRedirects for StaticRedirects {
    fn redirect(&self, owner: &str, name: &str) -> Option<RepoId> {
        self.0.get(&(owner.to_string(), name.to_string())).cloned()
    }
}

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn id(owner: &str, name: &str) -> RepoId {
    RepoId::new(owner, name).expect("valid repo id")
}

#[test]
fn relocate_bare_moves_the_directory_and_refuses_collisions() {
    let root = temp_dir("jeryu-relocate-bare");
    let manager = RepoManager::new(GitdConfig::new(&root));
    if !git_available() {
        return;
    }
    manager.create_bare(&id("acme", "old")).expect("create old");
    manager
        .create_bare(&id("veox", "taken"))
        .expect("create taken");

    let err = manager
        .relocate_bare(&id("acme", "old"), &id("veox", "taken"))
        .expect_err("existing target refused");
    assert!(matches!(err, GitdError::InvalidInput(_)), "{err}");
    let err = manager
        .relocate_bare(&id("acme", "missing"), &id("veox", "new"))
        .expect_err("missing source refused");
    assert!(matches!(err, GitdError::RepoNotFound(_)), "{err}");

    let moved = manager
        .relocate_bare(&id("acme", "old"), &id("veox", "new"))
        .expect("relocate");
    assert!(moved.path.join("HEAD").is_file());
    assert!(!root.join("acme").join("old.git").exists());
    assert_eq!(
        std::fs::read_to_string(moved.path.join("jeryu").join("repo-id")).expect("repo-id"),
        "veox/new"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn old_name_clones_fetches_and_pushes_the_moved_repository() {
    if !git_available() {
        return;
    }
    let root = temp_dir("jeryu-redirect-root");
    let seed = temp_dir("jeryu-redirect-seed");
    let clone = temp_dir("jeryu-redirect-clone");
    let plain = RepoManager::new(GitdConfig::new(&root));
    let repo = plain.create_bare(&id("acme", "old")).expect("create bare");
    seed_repository(&seed, &repo.path);
    let current = id("veox", "new");
    let moved = plain
        .relocate_bare(&id("acme", "old"), &current)
        .expect("relocate");

    let redirects = StaticRedirects::default().with("acme", "old", &current);
    let manager = RepoManager::new(GitdConfig::new(&root)).with_redirects(Arc::new(redirects));
    assert_eq!(
        manager
            .canonical_parts("acme", "old.git")
            .expect("canonical"),
        current
    );
    let (base_url, stop, server_thread) = start_test_server(SmartHttpServer::new(manager.clone()));
    let old_url = format!("{base_url}/acme/old.git");
    run_command(
        Command::new("git")
            .args(["clone", "--branch", "main"])
            .arg(&old_url)
            .arg(&clone),
        "clone by old name",
    );
    run_git(
        &clone,
        &["config", "user.email", "r@example.invalid"],
        "email",
    );
    run_git(&clone, &["config", "user.name", "Redirect Test"], "name");
    std::fs::write(clone.join("topic.txt"), "redirected push\n").expect("write topic");
    run_git(&clone, &["add", "topic.txt"], "add");
    run_git(&clone, &["commit", "-m", "topic"], "commit");
    run_git(
        &clone,
        &["push", "origin", "HEAD:refs/heads/topic"],
        "push by old name",
    );
    run_git(&clone, &["fetch", "origin", "topic"], "fetch by old name");
    let head = git_output(&clone, &["rev-parse", "HEAD"]);
    assert_eq!(git_output(&clone, &["rev-parse", "FETCH_HEAD"]), head);
    assert_eq!(
        git_output(&moved.path, &["rev-parse", "refs/heads/topic"]),
        head,
        "the push landed in the moved repository"
    );

    // A repository created later at the old name takes precedence.
    plain
        .create_bare(&id("acme", "old"))
        .expect("re-create old name");
    assert_eq!(
        manager.canonical_parts("acme", "old").expect("canonical"),
        id("acme", "old")
    );
    let fresh = Command::new("git")
        .args(["ls-remote", &old_url])
        .output()
        .expect("ls-remote runs");
    assert!(fresh.status.success());
    assert!(
        String::from_utf8_lossy(&fresh.stdout).trim().is_empty(),
        "the new empty repository answers, not the alias"
    );

    stop.store(true, Ordering::Release);
    server_thread.join().expect("server thread joins");
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(seed);
    let _ = std::fs::remove_dir_all(clone);
}
