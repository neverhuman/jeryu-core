//! Organizations with owners, and the teams they run (record 0009).

use super::ForgeCore;
use crate::errors::ForgeError;
use crate::model::*;

const PASSWORD: &str = "correct-horse-battery";

/// root is a forge administrator; alice, bob, carol and dave are people.
fn fixture() -> ForgeCore {
    let core = ForgeCore::new();
    core.create_account("root", PASSWORD, UserRole::Admin)
        .unwrap();
    for login in ["alice", "bob", "carol", "dave"] {
        core.create_account(login, PASSWORD, UserRole::User)
            .unwrap();
    }
    core
}

fn names(logins: &[&str]) -> Vec<String> {
    logins.iter().map(|login| (*login).to_string()).collect()
}

/// acme, owned by alice, with team `ops` holding bob.
fn acme(core: &ForgeCore) {
    core.create_organization_as("root", "acme", Some("Acme"), &names(&["alice"]))
        .unwrap();
    core.create_team_as("alice", "acme", "Ops", None, &names(&["bob"]))
        .unwrap();
}

#[test]
fn only_an_administrator_creates_an_organization_and_it_needs_an_owner() {
    let core = fixture();
    let error = core
        .create_organization_as("alice", "acme", None, &names(&["alice"]))
        .unwrap_err();
    assert!(matches!(error, ForgeError::Forbidden(_)), "{error:?}");
    let error = core
        .create_organization_as("root", "acme", None, &[])
        .unwrap_err();
    assert!(matches!(error, ForgeError::Validation(_)), "{error:?}");
    let error = core
        .create_organization_as("root", "acme", None, &names(&["nobody"]))
        .unwrap_err();
    assert!(matches!(error, ForgeError::Validation(_)), "{error:?}");
    let org = core
        .create_organization_as("root", "acme", None, &names(&[" Alice ", "alice", "bob"]))
        .unwrap();
    assert_eq!(org.owners, names(&["alice", "bob"]));
    assert_eq!(org.created_by.as_deref(), Some("root"));
}

#[test]
fn account_and_organization_logins_never_collide() {
    let core = fixture();
    let error = core
        .create_organization_as("root", "alice", None, &names(&["alice"]))
        .unwrap_err();
    assert!(matches!(error, ForgeError::Conflict(_)), "{error:?}");
    acme(&core);
    let error = core
        .create_account("acme", PASSWORD, UserRole::User)
        .unwrap_err();
    assert!(matches!(error, ForgeError::Conflict(_)), "{error:?}");
    let error = core
        .create_organization_as("root", "Not-Canonical", None, &names(&["alice"]))
        .unwrap_err();
    assert!(matches!(error, ForgeError::Validation(_)), "{error:?}");
}

#[test]
fn owners_run_teams_and_the_last_owner_stays() {
    let core = fixture();
    acme(&core);
    core.add_team_member("alice", "acme", "ops", "carol")
        .unwrap();
    let team = core
        .remove_team_member("alice", "acme", "ops", "bob")
        .unwrap();
    assert_eq!(team.members, names(&["carol"]));
    let org = core
        .add_organization_owner("alice", "acme", "dave")
        .unwrap();
    assert_eq!(org.owners, names(&["alice", "dave"]));
    core.remove_organization_owner("dave", "acme", "alice")
        .unwrap();
    let error = core
        .remove_organization_owner("dave", "acme", "dave")
        .unwrap_err();
    assert!(error.to_string().contains("last_owner"), "{error}");
    // An administrator may run any organization.
    core.create_team_as("root", "acme", "Release", Some("release"), &[])
        .unwrap();
    // Removing someone who is not there changes nothing.
    let team = core
        .remove_team_member("root", "acme", "release", "alice")
        .unwrap();
    assert!(team.members.is_empty());
}

#[test]
fn members_see_but_do_not_run_and_strangers_see_nothing() {
    let core = fixture();
    acme(&core);
    let view = core.organization_for("bob", "acme").unwrap();
    assert!(!view.can_manage);
    assert_eq!(view.teams.len(), 1);
    let error = core
        .add_team_member("bob", "acme", "ops", "carol")
        .unwrap_err();
    assert!(matches!(error, ForgeError::Forbidden(_)), "{error:?}");
    let error = core.organization_for("carol", "acme").unwrap_err();
    assert!(matches!(error, ForgeError::NotFound(_)), "{error:?}");
    let error = core
        .add_team_member("carol", "acme", "ops", "carol")
        .unwrap_err();
    assert!(matches!(error, ForgeError::NotFound(_)), "{error:?}");
    assert!(core.list_organizations_for("carol").unwrap().is_empty());
    assert_eq!(core.list_organizations_for("bob").unwrap().len(), 1);
    assert_eq!(core.list_organizations_for("root").unwrap().len(), 1);
    assert!(core.organization_for("alice", "acme").unwrap().can_manage);
}

#[test]
fn only_active_accounts_join_and_a_disabled_owner_runs_nothing() {
    let core = fixture();
    acme(&core);
    core.disable_account("carol").unwrap();
    let error = core
        .add_team_member("alice", "acme", "ops", "carol")
        .unwrap_err();
    assert!(matches!(error, ForgeError::Validation(_)), "{error:?}");
    let error = core
        .create_team_as("alice", "acme", "Dupe", Some("ops"), &[])
        .unwrap_err();
    assert!(matches!(error, ForgeError::Conflict(_)), "{error:?}");
    core.disable_account("alice").unwrap();
    assert!(
        core.add_team_member("alice", "acme", "ops", "dave")
            .is_err()
    );
}

#[test]
fn an_organization_without_owners_is_run_by_administrators() {
    let core = fixture();
    core.create_organization(CreateOrganizationRequest {
        login: "legacy".to_string(),
        display_name: None,
    })
    .unwrap();
    assert!(core.organization_for("alice", "legacy").is_err());
    core.add_organization_owner("root", "legacy", "alice")
        .unwrap();
    assert!(core.organization_for("alice", "legacy").unwrap().can_manage);
}

#[test]
fn owners_and_members_survive_sqlite_reopen_and_changes_are_audited() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("forge.sqlite");
    {
        let core = ForgeCore::open_sqlite(&path).unwrap();
        core.create_account("root", PASSWORD, UserRole::Admin)
            .unwrap();
        core.create_account("alice", PASSWORD, UserRole::User)
            .unwrap();
        core.create_account("bob", PASSWORD, UserRole::User)
            .unwrap();
        acme(&core);
    }
    let core = ForgeCore::open_sqlite(&path).unwrap();
    let view = core.organization_for("alice", "acme").unwrap();
    assert_eq!(view.organization.owners, names(&["alice"]));
    assert_eq!(view.teams[0].members, names(&["bob"]));
    let actions: Vec<_> = core
        .list_audit("team:acme/ops")
        .unwrap()
        .into_iter()
        .map(|entry| (entry.actor, entry.action))
        .collect();
    assert_eq!(
        actions,
        vec![("alice".to_string(), "team.create".to_string())]
    );
    assert_eq!(core.list_audit("org:acme").unwrap()[0].actor, "root");
}
