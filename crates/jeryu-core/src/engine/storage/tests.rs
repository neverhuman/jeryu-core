use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use chrono::{Duration, Utc};
use rusqlite::{Connection, params};
use tempfile::TempDir;
use uuid::Uuid;

use super::{load_state, snapshot, stage_state};
use crate::{AccountInvitationReceipt, ForgeCore, ForgeError, InvitationBindings, UserRole};

struct InvitationFixture {
    _directory: TempDir,
    database: PathBuf,
    core: ForgeCore,
    id: Uuid,
    original_row: (i64, Vec<u8>),
}

fn private_directory() -> TempDir {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn invite(core: &ForgeCore, login: &str) -> AccountInvitationReceipt {
    core.create_account_invitation(
        "owner",
        login,
        "Invited user",
        InvitationBindings {
            role: UserRole::User,
            teams: Vec::new(),
        },
        Utc::now() + Duration::hours(1),
    )
    .unwrap()
}

fn invitation_row(connection: &Connection, id: Uuid) -> (i64, Vec<u8>) {
    connection
        .query_row(
            "SELECT rowid, future_opaque FROM main.account_invitations WHERE id = ?1",
            [id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

fn fixture(expired: bool) -> InvitationFixture {
    let directory = private_directory();
    let database = directory.path().join("forge.sqlite");
    let core = ForgeCore::open_sqlite(&database).unwrap();
    let id = invite(&core, "invited").invitation.id;
    drop(core);
    let connection = Connection::open(&database).unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             ALTER TABLE account_invitations ADD COLUMN future_opaque BLOB;
             CREATE TABLE future_invitation_receipts (
                 invitation_id TEXT PRIMARY KEY REFERENCES account_invitations(id) ON DELETE CASCADE,
                 payload TEXT NOT NULL
             );",
        )
        .unwrap();
    connection
        .execute(
            "UPDATE account_invitations SET future_opaque = X'001180ff' WHERE id = ?1",
            [id.to_string()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO future_invitation_receipts VALUES (?1, 'retain this receipt')",
            [id.to_string()],
        )
        .unwrap();
    if expired {
        connection
            .execute(
                "UPDATE account_invitations SET expires_at = '2020-01-01T00:00:00Z' WHERE id = ?1",
                [id.to_string()],
            )
            .unwrap();
    }
    let original_row = invitation_row(&connection, id);
    drop(connection);
    let core = ForgeCore::open_sqlite(&database).unwrap();
    InvitationFixture {
        _directory: directory,
        database,
        core,
        id,
        original_row,
    }
}

fn assert_evidence(connection: &Connection, id: Uuid, original: &(i64, Vec<u8>)) {
    assert_eq!(&invitation_row(connection, id), original);
    let payload: String = connection
        .query_row(
            "SELECT payload FROM main.future_invitation_receipts WHERE invitation_id = ?1",
            [id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(payload, "retain this receipt");
    let violations: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(violations, 0);
}

#[test]
fn serialized_successor_before_expired_row_preserves_live_login_constraint() {
    let fixture = fixture(true);
    let mut desired = fixture.core.state.read().clone();
    let now = Utc::now();
    let previous = desired.invitations.get_mut(&fixture.id).unwrap();
    assert!(previous.expires_at < now);
    previous.revoked_at = Some(now);
    let mut successor = previous.clone();
    successor.id = Uuid::new_v4();
    successor.activation_secret_hash = "f".repeat(64);
    successor.created_at = now;
    successor.expires_at = now + Duration::hours(1);
    successor.revoked_at = None;
    let successor_id = successor.id;
    desired.invitations.insert(successor.id, successor);
    drop(fixture.core);

    let mut connection = Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap();
    let transaction = connection.transaction().unwrap();
    snapshot::create_tables(&transaction).unwrap();
    stage_state(&transaction, &desired).unwrap();
    // Reorder the real serializer output, rather than depending on randomized
    // HashMap traversal. The new active invitation must occupy the first row.
    transaction
        .execute_batch(
            "CREATE TEMP TABLE ordered_invitations AS SELECT * FROM temp.account_invitations;
             DELETE FROM temp.account_invitations;
             INSERT INTO temp.account_invitations
                 SELECT * FROM temp.ordered_invitations
                 ORDER BY revoked_at IS NOT NULL, id;",
        )
        .unwrap();
    let first_id: String = transaction
        .query_row(
            "SELECT id FROM temp.account_invitations ORDER BY rowid LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(first_id, successor_id.to_string());
    snapshot::apply(&transaction).unwrap();
    transaction.commit().unwrap();
    assert_evidence(&connection, fixture.id, &fixture.original_row);
    let live_id: String = connection
        .query_row(
            "SELECT id FROM main.account_invitations WHERE canonical_login = 'invited'
             AND consumed_at IS NULL AND revoked_at IS NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(live_id, successor_id.to_string());
    drop(connection);

    let reopened = ForgeCore::open_sqlite(&fixture.database).unwrap();
    assert_eq!(reopened.state.read().invitations, desired.invitations);
    assert_evidence(
        &Connection::open(&fixture.database).unwrap(),
        fixture.id,
        &fixture.original_row,
    );
}

#[test]
fn public_expired_invitation_reissue_reopens_with_both_receipts() {
    let fixture = fixture(true);
    let successor = invite(&fixture.core, "invited");
    let expected = fixture.core.list_account_invitations();
    assert_eq!(expected.len(), 2);
    assert!(
        expected
            .iter()
            .find(|invitation| invitation.id == fixture.id)
            .unwrap()
            .revoked_at
            .is_some()
    );
    assert!(successor.invitation.revoked_at.is_none());
    assert_evidence(
        &Connection::open(&fixture.database).unwrap(),
        fixture.id,
        &fixture.original_row,
    );
    drop(fixture.core);
    let reopened = ForgeCore::open_sqlite(&fixture.database).unwrap();
    assert_eq!(reopened.list_account_invitations(), expected);
    assert_evidence(
        &Connection::open(&fixture.database).unwrap(),
        fixture.id,
        &fixture.original_row,
    );
}

#[test]
fn invalid_final_invitation_uniqueness_rolls_back_existing_updates_and_shared_state() {
    let fixture = fixture(false);
    let other_handle = fixture.core.clone();
    let previous = fixture.core.list_account_invitations();
    let result = {
        let mut state = fixture.core.state.write();
        let previous_state = state.clone();
        let existing = state.invitations.get_mut(&fixture.id).unwrap();
        existing.display_name = "This update must roll back".into();
        let mut conflicting = existing.clone();
        conflicting.id = Uuid::new_v4();
        conflicting.activation_secret_hash = "e".repeat(64);
        // Keep both rows active with the same login: this final state is invalid.
        state.invitations.insert(conflicting.id, conflicting);
        fixture
            .core
            .persist_after_mutation(&mut state, previous_state)
    };
    assert!(matches!(
        result,
        Err(ForgeError::Storage(ref message))
            if message.contains("UNIQUE constraint failed: account_invitations.canonical_login")
    ));
    assert_eq!(other_handle.list_account_invitations(), previous);
    let connection = Connection::open(&fixture.database).unwrap();
    let durable = load_state(&connection).unwrap();
    assert_eq!(durable.invitations, fixture.core.state.read().invitations);
    assert_evidence(&connection, fixture.id, &fixture.original_row);
    drop(connection);
    drop(other_handle);
    drop(fixture.core);
    let reopened = ForgeCore::open_sqlite(&fixture.database).unwrap();
    assert_eq!(reopened.list_account_invitations(), previous);
    assert_evidence(
        &Connection::open(&fixture.database).unwrap(),
        fixture.id,
        &fixture.original_row,
    );
}

#[test]
fn changed_existing_row_preserves_future_not_null_column_without_default() {
    let directory = private_directory();
    let database = directory.path().join("forge.sqlite");
    drop(ForgeCore::open_sqlite(&database).unwrap());
    let source = ForgeCore::new();
    let invitation = invite(&source, "invited");
    let state = source.state.read().clone();
    let connection = Connection::open(&database).unwrap();
    // This future schema is created while the table is empty. Its independent
    // owner supplies the initial value; old Core must preserve it on UPDATE.
    connection
        .execute_batch("ALTER TABLE account_invitations ADD COLUMN future_required BLOB NOT NULL;")
        .unwrap();
    snapshot::create_tables(&connection).unwrap();
    stage_state(&connection, &state).unwrap();
    connection
        .execute_batch(
            "INSERT INTO main.account_invitations
             SELECT desired.*, X'001180ff' FROM temp.account_invitations AS desired;",
        )
        .unwrap();
    let original_rowid: i64 = connection
        .query_row("SELECT rowid FROM main.account_invitations", [], |row| {
            row.get(0)
        })
        .unwrap();
    drop(connection);
    drop(source);

    let core = ForgeCore::open_sqlite(&database).unwrap();
    assert!(
        core.revoke_account_invitation(invitation.invitation.id)
            .unwrap()
    );
    let previous = core.list_account_invitations();
    assert!(matches!(
        core.create_account_invitation(
            "owner",
            "new-user",
            "New user",
            InvitationBindings { role: UserRole::User, teams: Vec::new() },
            Utc::now() + Duration::hours(1),
        ),
        Err(ForgeError::Storage(ref message))
            if message.contains("NOT NULL constraint failed: account_invitations.future_required")
    ));
    assert_eq!(core.list_account_invitations(), previous);
    drop(core);

    let reopened = ForgeCore::open_sqlite(&database).unwrap();
    assert_eq!(reopened.list_account_invitations(), previous);
    let connection = Connection::open(&database).unwrap();
    let retained: (i64, Vec<u8>) = connection
        .query_row(
            "SELECT rowid, future_required FROM main.account_invitations WHERE id = ?1",
            params![invitation.invitation.id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(retained, (original_rowid, vec![0_u8, 17, 128, 255]));
}

/// The separate process `a_store_this_process_has_open_refuses_another_process`
/// starts. With `JERYU_STORE_LOCK_PROBE` naming a store, it opens that store
/// through the production constructor and asserts the open is refused with
/// `JERYU_STORE_LOCK_PROBE_CODE`; any other outcome fails this test, and so the
/// child process. Without the variable it checks the probe's own premise: a
/// store nobody holds opens.
#[test]
fn store_lock_probe_in_a_separate_process() {
    let Some(path) = std::env::var_os("JERYU_STORE_LOCK_PROBE") else {
        let root = private_directory();
        ForgeCore::open_sqlite(root.path().join("forge.sqlite"))
            .expect("a store nobody holds opens");
        return;
    };
    let expected = std::env::var("JERYU_STORE_LOCK_PROBE_CODE").expect("expected code");
    let refused = ForgeCore::open_sqlite(PathBuf::from(path))
        .err()
        .map(|error| error.to_string());
    assert!(
        refused
            .as_deref()
            .is_some_and(|message| message.contains(&expected)),
        "the separate process was not refused with {expected}: {refused:?}"
    );
}

/// Run `store_lock_probe_in_a_separate_process` in a new process of this test
/// binary against `path`, and require that it ran that one test and passed. A
/// child that ran no test (a filter that matched nothing) is a failure, not a
/// pass.
fn probe_in_another_process(path: &std::path::Path, expected: &str) {
    let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "core::storage::tests::store_lock_probe_in_a_separate_process",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("JERYU_STORE_LOCK_PROBE", path)
        .env("JERYU_STORE_LOCK_PROBE_CODE", expected)
        .output()
        .expect("probe process");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed"),
        "the separate process was not refused with {expected}: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// One process writes a store, and one store in it: each open has its own
/// in-memory state and refresh locks, so a second open while the first lives
/// is refused like another process (share a store by cloning its ForgeCore).
///
/// The lock names the database, not the path an open was given
/// (STORE-LOCK-ALIAS): a separate process opening it through a symlink is
/// refused and makes no lock of its own, a second hard link refuses every
/// name, and a file swapped under a live store is refused, not written. The
/// holder keeps the lock and its rows through all of it. A lock taken through
/// another open file description conflicts as another process's would, and
/// flock(1) checks the sidecar from a real child too.
#[test]
fn a_store_this_process_has_open_refuses_another_process() {
    let root = private_directory();
    let path = root.path().join("forge.sqlite");
    let lock_path = root.path().join("forge.sqlite.lock");
    let core = ForgeCore::open_sqlite(&path).expect("open");
    core.create_account("alice", "alice-password-1", UserRole::User)
        .expect("alice");
    let shared = core.clone();
    let second = ForgeCore::open_sqlite(&path).unwrap_err();
    assert!(
        second
            .to_string()
            .contains("store_locked: this process already has"),
        "{second}"
    );

    // Another name for the same database, from another directory.
    let elsewhere = private_directory();
    let symlink = elsewhere.path().join("alias.sqlite");
    std::os::unix::fs::symlink(&path, &symlink).expect("symlink");
    let refused = ForgeCore::open_sqlite(&symlink).unwrap_err();
    assert!(refused.to_string().contains("store_locked"), "{refused}");
    // A separate process opening the symlink is refused.
    probe_in_another_process(&symlink, "store_locked: another process has");
    assert!(
        !elsewhere.path().join("alias.sqlite.lock").exists(),
        "an alias never takes a lock of its own"
    );
    let child = std::process::Command::new("flock")
        .args(["--nonblock", "--conflict-exit-code", "75"])
        .arg(&lock_path)
        .arg("true")
        .status()
        .expect("flock(1)");
    assert_eq!(
        child.code(),
        Some(75),
        "the sidecar is held against a child"
    );

    let hard_link = elsewhere.path().join("hard.sqlite");
    std::fs::hard_link(&path, &hard_link).expect("hard link");
    // A separate process opening a hard link is refused.
    probe_in_another_process(&hard_link, "store_aliased");
    let refused = ForgeCore::open_sqlite(&path).unwrap_err();
    assert!(refused.to_string().contains("store_aliased"), "{refused}");
    assert!(
        shared
            .create_account("mallory", "mallory-password", UserRole::User)
            .is_err(),
        "the holder writes nothing while its file has a second name"
    );
    std::fs::remove_file(&hard_link).expect("unlink");
    assert!(!elsewhere.path().join("hard.sqlite.lock").exists());
    shared
        .create_account("bob", "bob-password-12", UserRole::User)
        .expect("the holder still writes");

    let other = std::fs::OpenOptions::new()
        .write(true)
        .open(&lock_path)
        .expect("lock file");
    assert!(
        matches!(other.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
        "another process cannot take the store"
    );
    drop(core);
    assert!(
        matches!(other.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
        "the lock lasts while any handle lives"
    );
    drop(shared);
    other
        .try_lock()
        .expect("the lock goes with the last handle");
    let refused = ForgeCore::open_sqlite(&path).unwrap_err();
    assert!(refused.to_string().contains("store_locked"), "{refused}");
    drop(other);

    let reopened = ForgeCore::open_sqlite(&path).expect("free again");
    let logins: Vec<String> = reopened
        .list_accounts()
        .into_iter()
        .map(|account| account.login)
        .collect();
    assert!(
        logins.contains(&"alice".to_string())
            && logins.contains(&"bob".to_string())
            && !logins.contains(&"mallory".to_string()),
        "the holder's writes survive, and only those: {logins:?}"
    );
    // A file swapped in under the path takes no write from this store.
    let impostor = root.path().join("impostor.sqlite");
    std::fs::copy(&path, &impostor).expect("copy");
    std::fs::rename(&impostor, &path).expect("swap");
    let swapped = reopened
        .create_account("carol", "carol-password-1", UserRole::User)
        .unwrap_err();
    assert!(swapped.to_string().contains("store_replaced"), "{swapped}");
    // So does a directory in its place: replaced, not misread as hard links.
    std::fs::remove_file(&path).expect("remove");
    std::fs::create_dir(&path).expect("directory");
    let directory = reopened
        .create_account("dave", "dave-password-12", UserRole::User)
        .unwrap_err();
    assert!(
        directory.to_string().starts_with("store_replaced:"),
        "{directory}"
    );

    // A file swapped in just before the one open and swapped back just after
    // it (CONNECTION-IDENTITY-ABA): the name reads right on both sides, and an
    // independent descriptor on the real file is newly open across the check,
    // but the connection SQLite holds is the impostor's, so the open is
    // refused and nothing of the impostor is loaded.
    let race = private_directory();
    let real = race.path().join("forge.sqlite");
    let impostor = race.path().join("impostor.sqlite");
    let held = race.path().join("held.sqlite");
    {
        let real_core = ForgeCore::open_sqlite(&real).expect("real");
        real_core
            .create_account("erin", "erin-password-123", UserRole::User)
            .expect("erin");
    }
    {
        let other = ForgeCore::open_sqlite(&impostor).expect("impostor");
        other
            .create_account("mallory", "mallory-password", UserRole::User)
            .expect("mallory");
    }
    let real_bytes = std::fs::read(&real).expect("real bytes");
    let (hook_real, hook_impostor, hook_held) = (real.clone(), impostor.clone(), held.clone());
    let decoy: std::sync::Arc<parking_lot::Mutex<Option<std::fs::File>>> = Default::default();
    let hook_decoy = decoy.clone();
    *super::OPEN_HOOK.lock() = Some(Box::new(move |opening, before| {
        if opening != hook_real.as_path() {
            return;
        }
        if before {
            std::fs::rename(&hook_real, &hook_held).expect("hold the real file");
            std::fs::rename(&hook_impostor, &hook_real).expect("swap the impostor in");
        } else {
            std::fs::rename(&hook_real, &hook_impostor).expect("swap the impostor out");
            std::fs::rename(&hook_held, &hook_real).expect("put the real file back");
            // A plain reader on the real file, newly open across the check.
            *hook_decoy.lock() = Some(std::fs::File::open(&hook_real).expect("decoy"));
        }
    }));
    let raced = ForgeCore::open_sqlite(&real).unwrap_err();
    *super::OPEN_HOOK.lock() = None;
    assert!(
        decoy.lock().is_some(),
        "the decoy was open across the check"
    );
    drop(decoy.lock().take());
    assert!(raced.to_string().starts_with("store_replaced:"), "{raced}");
    assert_eq!(
        std::fs::read(&real).expect("real bytes"),
        real_bytes,
        "the real database is untouched"
    );
    let logins: Vec<String> = ForgeCore::open_sqlite(&real)
        .expect("the real store opens once the race is gone")
        .list_accounts()
        .into_iter()
        .map(|account| account.login)
        .collect();
    assert!(
        logins.contains(&"erin".to_string()) && !logins.contains(&"mallory".to_string()),
        "only the real store's rows: {logins:?}"
    );
}

/// A holder that is letting go is waited for, not reported as another
/// process: the last handle closing on another thread, or a child that
/// another thread is forking, which keeps a copy of the lock's descriptor
/// until it executes. Seen as `store_locked` on a reopen right after the
/// last writer dropped, under a fully parallel test run.
#[test]
fn an_open_waits_for_a_holder_that_is_letting_go() {
    let root = private_directory();
    let path = root.path().join("forge.sqlite");
    let lock_path = root.path().join("forge.sqlite.lock");
    drop(ForgeCore::open_sqlite(&path).expect("create"));
    let holder = std::fs::OpenOptions::new()
        .write(true)
        .open(&lock_path)
        .expect("lock file");
    holder.try_lock().expect("held");
    let release = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(300));
        drop(holder);
    });
    let started = std::time::Instant::now();
    ForgeCore::open_sqlite(&path).expect("opened once the holder let go");
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(250),
        "the open waited for the holder"
    );
    release.join().expect("release");
}
