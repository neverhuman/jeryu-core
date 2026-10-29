//! Guards on deleting branch protection rules and on the `%2F` re-key repair:
//! the default-branch invariant, archived repositories, the audit trail, and
//! re-validation of the re-key plan under the write lock.

use std::sync::atomic::{AtomicBool, Ordering};

use jeryu_core::{
    CreateRepositoryRequest, ForgeCore, ForgeError, RepoBranches, Result,
    SetBranchProtectionRequest, UserRole,
};

const ADMIN: &str = "root";

fn rule(checks: &[&str]) -> SetBranchProtectionRequest {
    SetBranchProtectionRequest {
        required_status_checks: checks.iter().map(|c| c.to_string()).collect(),
        strict: false,
        required_approving_review_count: 1,
        allow_merge_override: false,
        allow_admin_review_dismissal: false,
        merge_override_status_checks: Vec::new(),
        merge_override_status_creators: Vec::new(),
        enforce_admins: false,
        required_linear_history: false,
        allow_force_pushes: false,
        allow_deletions: false,
        require_signed_commits: false,
        require_jankurai_proof: false,
        dismiss_stale_approvals: false,
        require_exact_sha_approval: false,
    }
}

fn forge(dir: &tempfile::TempDir) -> ForgeCore {
    let core = ForgeCore::open_sqlite(dir.path().join("forge.sqlite")).unwrap();
    core.create_account(ADMIN, "correct horse battery", UserRole::Admin)
        .unwrap();
    core
}

fn create_repo(core: &ForgeCore, name: &str, default_branch: &str) {
    core.create_repository(
        "jeryu",
        CreateRepositoryRequest {
            name: name.to_string(),
            private: true,
            description: None,
            default_branch: Some(default_branch.to_string()),
        },
    )
    .unwrap();
}

fn key(repo: &str, branch: &str) -> (String, String, String) {
    ("jeryu".to_string(), repo.to_string(), branch.to_string())
}

fn kept(repo: &str, branch: &str, reason: &str) -> ((String, String, String), String) {
    (key(repo, branch), reason.to_string())
}

fn audit(core: &ForgeCore, repo: &str) -> Vec<(String, String)> {
    core.list_audit(&format!("jeryu/{repo}"))
        .unwrap()
        .into_iter()
        .map(|entry| (entry.action, entry.phase))
        .collect()
}

#[derive(Debug)]
struct Branches(Vec<&'static str>);

impl RepoBranches for Branches {
    fn branch_exists(&self, _owner: &str, _name: &str, branch: &str) -> Result<bool> {
        Ok(self.0.contains(&branch))
    }
}

/// An opted-out repository whose rules require a status context may not
/// drop its default-branch rule; once no rule requires one, it may. Both
/// outcomes are audited with the acting login.
#[test]
fn delete_default_branch_rule_honours_status_context_invariant() {
    let dir = tempfile::tempdir().unwrap();
    let core = forge(&dir);
    create_repo(&core, "app", "main");
    core.set_default_branch_protection_opt_out(ADMIN, "jeryu", "app", true)
        .unwrap();
    core.set_branch_protection("jeryu", "app", "main", rule(&[]))
        .unwrap();
    core.set_branch_protection("jeryu", "app", "release", rule(&["ci/fast"]))
        .unwrap();

    assert!(matches!(
        core.delete_branch_protection(ADMIN, "jeryu", "app", "main"),
        Err(ForgeError::Validation(_))
    ));
    assert!(core.get_branch_protection("jeryu", "app", "main").is_ok());

    core.delete_branch_protection(ADMIN, "jeryu", "app", "release")
        .unwrap();
    let removed = core
        .delete_branch_protection(ADMIN, "jeryu", "app", "main")
        .unwrap();
    assert_eq!(removed.branch, "main");

    let deleted = "branch_protection.deleted".to_string();
    let trail: Vec<_> = audit(&core, "app")
        .into_iter()
        .filter(|(action, _)| *action == deleted)
        .map(|(_, phase)| phase)
        .collect();
    assert_eq!(trail, ["failed", "completed", "completed"]);
    let entries = core.list_audit("jeryu/app").unwrap();
    let last = entries.last().unwrap();
    assert_eq!(last.actor, ADMIN);
    assert_eq!(last.detail["rule"]["branch"], "main");
}

/// Without an opt-out the default branch's rule is never deletable.
#[test]
fn delete_default_branch_rule_refused_without_opt_out() {
    let dir = tempfile::tempdir().unwrap();
    let core = forge(&dir);
    create_repo(&core, "app", "main");
    assert!(matches!(
        core.delete_branch_protection(ADMIN, "jeryu", "app", "main"),
        Err(ForgeError::Validation(_))
    ));
    assert!(core.get_branch_protection("jeryu", "app", "main").is_ok());
}

#[test]
fn delete_branch_protection_refuses_archived_repository() {
    let dir = tempfile::tempdir().unwrap();
    let core = forge(&dir);
    create_repo(&core, "app", "main");
    core.set_branch_protection("jeryu", "app", "release", rule(&[]))
        .unwrap();
    core.set_repository_archived(ADMIN, "jeryu", "app", true)
        .unwrap();
    assert!(matches!(
        core.delete_branch_protection(ADMIN, "jeryu", "app", "release"),
        Err(ForgeError::RepositoryArchived(_))
    ));
    assert!(
        core.get_branch_protection("jeryu", "app", "release")
            .is_ok()
    );
}

/// The re-key repair touches only rules no real branch carries, never the
/// default branch's rule, never an archived repository, never a duplicate
/// that requires status checks, and keeps rules armed ahead of their branch.
#[test]
fn rekey_keeps_guarded_rules_and_audits_changes() {
    let dir = tempfile::tempdir().unwrap();
    let core = forge(&dir);
    create_repo(&core, "app", "main");
    create_repo(&core, "odd", "release%2Fv0");
    create_repo(&core, "frozen", "main");
    for branch in [
        "release%2Fv1",
        "literal%2Fname",
        "armed%2Fv2",
        "dup%2Fa",
        "dup/a",
        "gated%2Fb",
        "gated/b",
    ] {
        let checks: &[&str] = if branch == "gated%2Fb" {
            &["ci/fast"]
        } else {
            &[]
        };
        core.set_branch_protection("jeryu", "app", branch, rule(checks))
            .unwrap();
    }
    core.set_branch_protection("jeryu", "frozen", "old%2Fv1", rule(&[]))
        .unwrap();
    core.set_repository_archived(ADMIN, "jeryu", "frozen", true)
        .unwrap();
    let branches = Branches(vec![
        "release/v1",
        "literal%2Fname",
        "literal/name",
        "dup/a",
        "gated/b",
        "release/v0",
        "old/v1",
    ]);

    assert!(matches!(
        core.rekey_encoded_branch_protections("nobody", &branches),
        Err(ForgeError::BranchProtection(_))
    ));
    let mut report = core
        .rekey_encoded_branch_protections(ADMIN, &branches)
        .unwrap();
    report.kept.sort();
    assert_eq!(report.rekeyed, [key("app", "release%2Fv1")]);
    assert_eq!(report.removed, [key("app", "dup%2Fa")]);
    assert_eq!(
        report.kept,
        [
            kept("app", "armed%2Fv2", "decoded branch does not exist"),
            kept("app", "gated%2Fb", "duplicate requires status checks"),
            kept("app", "literal%2Fname", "encoded name is a real branch"),
            kept("frozen", "old%2Fv1", "repository archived"),
            kept("odd", "release%2Fv0", "default branch"),
        ]
    );
    assert!(
        core.get_branch_protection("jeryu", "app", "release/v1")
            .is_ok()
    );
    assert!(
        core.get_branch_protection("jeryu", "odd", "release%2Fv0")
            .is_ok()
    );
    let rekey = "branch_protection.encoded_rekey".to_string();
    let changes = audit(&core, "app")
        .into_iter()
        .filter(|(action, _)| *action == rekey)
        .count();
    assert_eq!(changes, 2);
    assert!(
        audit(&core, "odd")
            .iter()
            .all(|(action, _)| *action != rekey)
    );

    let again = core
        .rekey_encoded_branch_protections(ADMIN, &branches)
        .unwrap();
    assert!(again.rekeyed.is_empty() && again.removed.is_empty());
    assert_eq!(again.kept.len(), 5);
}

/// Changes a planned rule while the repair is doing its git lookups.
#[derive(Debug)]
struct RacingBranches<'a> {
    core: &'a ForgeCore,
    raced: AtomicBool,
}

impl RepoBranches for RacingBranches<'_> {
    fn branch_exists(&self, _owner: &str, _name: &str, branch: &str) -> Result<bool> {
        if !self.raced.swap(true, Ordering::SeqCst) {
            let mut stricter = rule(&[]);
            stricter.required_approving_review_count = 4;
            self.core
                .set_branch_protection("jeryu", "app", "release%2Fv1", stricter)?;
        }
        Ok(branch == "release/v1")
    }
}

#[test]
fn rekey_revalidates_plan_under_write_lock() {
    let dir = tempfile::tempdir().unwrap();
    let core = forge(&dir);
    create_repo(&core, "app", "main");
    core.set_branch_protection("jeryu", "app", "release%2Fv1", rule(&[]))
        .unwrap();
    let branches = RacingBranches {
        core: &core,
        raced: AtomicBool::new(false),
    };
    let report = core
        .rekey_encoded_branch_protections(ADMIN, &branches)
        .unwrap();
    assert!(report.rekeyed.is_empty() && report.removed.is_empty());
    assert_eq!(
        report.kept,
        [kept("app", "release%2Fv1", "rule changed since planning")]
    );
    let live = core
        .get_branch_protection("jeryu", "app", "release%2Fv1")
        .unwrap();
    assert_eq!(live.required_approving_review_count, 4);
}
