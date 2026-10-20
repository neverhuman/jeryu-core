use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};

use rusqlite::{Connection, params};

use super::audit::AuditEntry;
use super::{Counters, State};
use crate::errors::{ForgeError, Result};

mod bot_tokens;
mod codec;
mod deployments;
mod load;
mod migrations;
mod provider_connections;
mod snapshot;
mod stage;
mod team_bots;
#[cfg(test)]
mod tests;

use self::codec::*;
use self::load::load_state;
use self::migrations::apply_migrations;
use self::stage::stage_state;

#[derive(Debug, Clone)]
pub(super) struct SqliteStore {
    path: PathBuf,
    /// The database file's device and inode when the store opened: the file
    /// SQLite's one connection was proven to write.
    identity: FileIdentity,
    /// The store's one connection, opened once and proven to write `identity`
    /// (see `open_bound`). Nothing reopens the database by its path, so a name
    /// swapped later cannot redirect a write.
    conn: Arc<parking_lot::Mutex<Connection>>,
    _lock: Arc<StoreLock>,
    /// Our own descriptor on the database file, holding an exclusive lock on
    /// the file itself for as long as the store lives (see `lock_database`),
    /// and any other descriptor this process opened on it since: none is
    /// closed before the connection (see `HeldDatabase`). Declared after
    /// `conn`, so it is dropped after it.
    _held: Arc<HeldDatabase>,
}

/// A file's device and inode.
type FileIdentity = (u64, u64);

/// The identity of the one file `path` names now. When the store already
/// pinned its file (`expected`), anything else at the path is `store_replaced`;
/// so is something that is not a regular file, a symlink included. Only then is a second hard link
/// `store_aliased`, because another name for the file would take another lock.
fn file_identity(path: &Path, expected: Option<FileIdentity>) -> Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    // Every caller passes the database's canonical path, which names the file
    // itself, so a link found there later is something else at that name, not
    // the file: it is not followed.
    let meta = std::fs::symlink_metadata(path).map_err(storage_error)?;
    let identity = (meta.dev(), meta.ino());
    if expected.is_some_and(|expected| expected != identity) {
        return Err(ForgeError::StoreCustody(format!(
            "store_replaced: {} no longer names the database this store opened",
            path.display()
        )));
    }
    if !meta.is_file() {
        return Err(ForgeError::StoreCustody(format!(
            "store_replaced: {} is not a regular file",
            path.display()
        )));
    }
    if meta.nlink() > 1 {
        return Err(ForgeError::StoreCustody(format!(
            "store_aliased: {} has {} hard links; open a store by its one name",
            path.display(),
            meta.nlink()
        )));
    }
    Ok(identity)
}

/// A test-only hook around the store's one `Connection::open`, called with
/// the path and `true` just before it and `false` just after, so a case can
/// move files across that interval deterministically.
#[cfg(test)]
pub(super) type OpenHook = Box<dyn Fn(&Path, bool) + Send>;
#[cfg(test)]
pub(super) static OPEN_HOOK: parking_lot::Mutex<Option<OpenHook>> = parking_lot::Mutex::new(None);

/// Our own descriptor on the database file, opened without following a link
/// and checked to be the one file `expected` pinned (if given): a regular file
/// with one link.
fn open_pinned(path: &Path, expected: Option<FileIdentity>) -> Result<Pinned> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::MetadataExt;
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| storage_error(std::io::Error::from(error)))?;
    let file = std::fs::File::from(fd);
    let meta = file.metadata().map_err(storage_error)?;
    let identity = (meta.dev(), meta.ino());
    // From here the descriptor is a `Pinned`: if it reached a file a store in
    // this process has open, dropping it parks it with that store.
    let file = Pinned {
        file: Some(file),
        identity,
    };
    if live_store(identity).is_some() {
        return Err(already_open_here(path));
    }
    if !meta.is_file() || expected.is_some_and(|expected| expected != identity) {
        return Err(ForgeError::StoreCustody(format!(
            "store_replaced: {} named another file while it was being opened",
            path.display()
        )));
    }
    if meta.nlink() > 1 {
        return Err(ForgeError::StoreCustody(format!(
            "store_aliased: {} has {} hard links; open a store by its one name",
            path.display(),
            meta.nlink()
        )));
    }
    Ok(file)
}

/// The files the stores in this process have open, by device and inode, with
/// their held descriptors.
static LIVE_DATABASES: std::sync::LazyLock<
    parking_lot::Mutex<HashMap<FileIdentity, Weak<HeldDatabase>>>,
> = std::sync::LazyLock::new(Default::default);

/// A store's own descriptors on its database file. SQLite's locks are `fcntl`
/// locks, which belong to the process, and the kernel drops all of them when
/// the process closes any descriptor on the file, SQLite's own or not. So no
/// descriptor this code opens on a file a store has open is closed while that
/// store lives: the store's own is held here, and any other that reaches the
/// file (a refused open by another name) is parked here, all closed only
/// after the store's connection is.
#[derive(Debug)]
struct HeldDatabase {
    files: parking_lot::Mutex<Vec<std::fs::File>>,
}

/// The live store's held descriptors on `identity`, if a store in this
/// process has that file open.
fn live_store(identity: FileIdentity) -> Option<Arc<HeldDatabase>> {
    LIVE_DATABASES.lock().get(&identity).and_then(Weak::upgrade)
}

fn already_open_here(path: &Path) -> ForgeError {
    ForgeError::StoreCustody(format!(
        "store_locked: this process already has the database {} names open, under another \
         name; one store writes a database, so share it by cloning its ForgeCore",
        path.display()
    ))
}

/// A descriptor this code opened on a database file. Dropped while a store
/// in this process has that file open, it is parked with that store instead
/// of closed (see `HeldDatabase`).
#[derive(Debug)]
struct Pinned {
    file: Option<std::fs::File>,
    identity: FileIdentity,
}

impl std::ops::Deref for Pinned {
    type Target = std::fs::File;
    fn deref(&self) -> &std::fs::File {
        self.file
            .as_ref()
            .expect("a pinned descriptor is held until it is dropped")
    }
}

impl Drop for Pinned {
    fn drop(&mut self) {
        if let Some(file) = self.file.take()
            && let Some(held) = live_store(self.identity)
        {
            held.files.lock().push(file);
        }
    }
}

impl Pinned {
    /// Become the store's own held descriptor on its file, registered so that
    /// no other descriptor on that file in this process is closed while the
    /// store lives.
    fn hold(mut self) -> Arc<HeldDatabase> {
        let file = self
            .file
            .take()
            .expect("a pinned descriptor is held until it is dropped");
        let held = Arc::new(HeldDatabase {
            files: parking_lot::Mutex::new(vec![file]),
        });
        let mut live = LIVE_DATABASES.lock();
        live.retain(|_, store| store.strong_count() > 0);
        live.insert(self.identity, Arc::downgrade(&held));
        held
    }
}

/// The lock on `<store>.lock` follows the name the database had when a store
/// opened it. Renamed while that store lives, the database would be reached
/// by a new name with a lock of its own, so the store also locks the
/// database file through its own descriptor: an exclusive `flock`, held as
/// long as the store, which another descriptor on the same file cannot take,
/// from this process or another, whatever name it came through. It is a
/// `flock`, separate from SQLite's `fcntl` locks; but opening and closing a
/// descriptor on the file is not, which is why a refused open in this process
/// never closes one (see `HeldDatabase`). A holder that is letting go is
/// waited for as in `lock_store`.
fn lock_database(file: &std::fs::File, path: &Path) -> Result<()> {
    let deadline = std::time::Instant::now() + LOCK_WAIT;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(error)) => return Err(storage_error(error)),
        }
        if std::time::Instant::now() >= deadline {
            return Err(ForgeError::StoreCustody(format!(
                "store_locked: another store has the database {} names open, under another \
                 name; one store writes a database, so share it by cloning its ForgeCore",
                path.display()
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// The store keeps a rollback journal. Its own opens never set WAL, but the
/// mode persists in the file, so a store another tool left in WAL mode is
/// refused rather than converted on open: see `open_bound`.
fn journal_refused(path: &Path) -> ForgeError {
    ForgeError::StoreCustody(format!(
        "store_journal: {} is in WAL mode, and this store keeps a rollback journal; with the \
         forge stopped, run `PRAGMA journal_mode = DELETE;` on it once, then start the forge",
        path.display()
    ))
}

/// Refuse a WAL-mode database by its header, read through the pinned
/// descriptor before SQLite opens anything: bytes 18 and 19 (the file
/// format's write and read versions) are 2 in WAL mode and 1 otherwise. A
/// file too short to have a header is left to SQLite.
fn refuse_wal(file: &std::fs::File, path: &Path) -> Result<()> {
    use std::os::unix::fs::FileExt;
    let mut versions = [0_u8; 2];
    if file.read_exact_at(&mut versions, 18).is_ok() && versions.contains(&2) {
        return Err(journal_refused(path));
    }
    Ok(())
}

/// Open the store's one SQLite connection and prove it writes the pinned
/// database file. Checking the path around the open is not enough (both
/// checks read the name, not the file SQLite opened), and finding some new
/// descriptor on the file is not enough either (another could have opened
/// it). So the proof goes through the connection itself: a fresh random value
/// written into the database header's `user_version` field through the
/// connection must be read back from our own descriptor on the pinned file.
/// The field is then put back.
fn open_bound(
    path: &Path,
    expected: Option<FileIdentity>,
) -> Result<(Connection, FileIdentity, Arc<HeldDatabase>)> {
    use std::os::unix::fs::{FileExt, MetadataExt};
    // A file a store in this process has open is refused before any
    // descriptor is opened on it, by its identity as the name showed it.
    if expected.is_some_and(|identity| live_store(identity).is_some()) {
        return Err(already_open_here(path));
    }
    // An existing store is pinned before the open; a new one only once SQLite
    // has created its file.
    let pinned_before = match expected {
        Some(_) => Some(open_pinned(path, expected)?),
        None => None,
    };
    if let Some(file) = &pinned_before {
        refuse_wal(file, path)?;
    }
    #[cfg(test)]
    if let Some(hook) = OPEN_HOOK.lock().as_ref() {
        hook(path, true);
    }
    let conn = Connection::open(path).map_err(storage_error)?;
    // Until the binding is proven, this connection only reads: if it turns
    // out to be bound to another file, closing it must not checkpoint that
    // file's WAL into it either.
    conn.set_db_config(
        rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
        true,
    )
    .map_err(storage_error)?;
    let original: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(storage_error)?;
    #[cfg(test)]
    if let Some(hook) = OPEN_HOOK.lock().as_ref() {
        hook(path, false);
    }
    let pinned = match pinned_before {
        Some(file) => file,
        None => open_pinned(path, None)?,
    };
    // Before anything writes: the database file itself, whatever name it is
    // reached by now.
    lock_database(&pinned, path)?;
    let held = pinned.hold();
    let meta = held.files.lock()[0].metadata().map_err(storage_error)?;
    let identity = (meta.dev(), meta.ino());
    let replaced = || {
        ForgeError::StoreCustody(format!(
            "store_replaced: {} named another file while it was being opened",
            path.display()
        ))
    };
    let nonce = loop {
        let candidate = i64::from(uuid::Uuid::new_v4().as_u128() as i32);
        if candidate != 0 && candidate != original {
            break candidate;
        }
    };
    // SQLite itself refuses to write a file that was moved since it opened it
    // (SQLITE_READONLY_DBMOVED): that is the swap, too.
    let moved = |error: rusqlite::Error| match &error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.extended_code == rusqlite::ffi::SQLITE_READONLY_DBMOVED =>
        {
            replaced()
        }
        _ => storage_error(error),
    };
    // The store keeps a rollback journal, so the nonce's commit reaches the
    // database file itself, where the check below reads it; in WAL mode it
    // would reach only the `-wal` file. A WAL-mode store was refused before
    // the open (`refuse_wal`); a WAL-mode file swapped in since then is
    // refused here. Nothing changes the journal before the binding is
    // proven: SQLite finds `-wal` by the path, not by the file it opened, so
    // moving a journal through an unproven connection could checkpoint one
    // file's commits into another.
    let journal: String = conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(storage_error)?;
    if journal.eq_ignore_ascii_case("wal") {
        return Err(journal_refused(path));
    }
    conn.execute_batch(&format!("PRAGMA user_version = {nonce};"))
        .map_err(moved)?;
    // The header's user_version: four big-endian bytes at offset 60.
    let mut field = [0_u8; 4];
    let written = held.files.lock()[0].read_exact_at(&mut field, 60).is_ok()
        && i64::from(i32::from_be_bytes(field)) == nonce;
    conn.execute_batch(&format!("PRAGMA user_version = {original};"))
        .map_err(storage_error)?;
    if !written {
        return Err(replaced());
    }
    // And the name still names that file, with one link.
    file_identity(path, Some(identity))?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .map_err(storage_error)?;
    Ok((conn, identity, held))
}

/// One process writes a store. Its in-memory state is the truth and every
/// write replaces the snapshot, so a second process on the same file would
/// undo the first one's writes, and could refresh a provider connection the
/// first is refreshing (connection-v1 §3). The first open in a process takes
/// an exclusive lock on `<store>.lock` for as long as any handle to the store
/// lives; an open from another process is refused with `store_locked`. So is
/// a second open in this process while the first store lives: each open has
/// its own in-memory state and refresh locks, so two would undo each other as
/// two processes would. Share one store by cloning its `ForgeCore`.
///
/// The lock names the database, not the path an open was given: `<store>` is
/// the database's canonical path, so a symlink to it takes the same lock. A
/// hard link has no one canonical name, so a database file with more than one
/// link is refused with `store_aliased`.
#[derive(Debug)]
struct StoreLock {
    /// The OS releases the lock when this file is closed.
    _file: std::fs::File,
}

/// The locks this process holds, by the database's canonical path.
static OPEN_STORES: std::sync::LazyLock<parking_lot::Mutex<HashMap<PathBuf, Weak<StoreLock>>>> =
    std::sync::LazyLock::new(Default::default);

/// How long an open waits for the store's lock before calling it held. A
/// holder that is about to let go is common inside one process: the last
/// handle closing on another thread, or a child another thread is forking,
/// which holds a copy of the lock's descriptor until it executes. Another
/// process that has the store open holds the lock for its whole life, so it
/// is still refused, after this wait.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// The database a store path names: its canonical path when it exists, or
/// its canonical directory and file name before the first open creates it.
/// A database file with more than one hard link is refused, because another
/// name for it would take another lock.
fn store_identity(path: &Path) -> Result<(PathBuf, Option<FileIdentity>)> {
    match std::fs::canonicalize(path) {
        Ok(canonical) => {
            let identity = file_identity(&canonical, None)?;
            Ok((canonical, Some(identity)))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // A dangling symlink would let SQLite create its target elsewhere.
            if std::fs::symlink_metadata(path).is_ok() {
                return Err(ForgeError::StoreCustody(format!(
                    "store_aliased: {} is a link to a database that does not exist",
                    path.display()
                )));
            }
            let name = path.file_name().ok_or_else(|| {
                ForgeError::Storage(format!("store path {} names no file", path.display()))
            })?;
            let parent = match path.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => parent,
                _ => Path::new("."),
            };
            Ok((
                std::fs::canonicalize(parent)
                    .map_err(storage_error)?
                    .join(name),
                None,
            ))
        }
        Err(error) => Err(storage_error(error)),
    }
}

/// Lock the database `path` names, and return the lock with that database's
/// canonical path, which every connection then opens, and the file identity
/// seen before the lock was taken, if the database existed.
fn lock_store(path: &Path) -> Result<(Arc<StoreLock>, PathBuf, Option<FileIdentity>)> {
    use std::os::unix::fs::OpenOptionsExt;
    let (key, seen) = store_identity(path)?;
    let lock_path = PathBuf::from(format!("{}.lock", key.display()));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(&lock_path)
        .map_err(storage_error)?;
    let deadline = std::time::Instant::now() + LOCK_WAIT;
    loop {
        // The registry is held only for one look, never while waiting. A store
        // this process still has open is waited for like another process's:
        // its last handle may be closing on another thread.
        let open_here = {
            let mut stores = OPEN_STORES.lock();
            if stores.get(&key).and_then(Weak::upgrade).is_some() {
                true
            } else {
                match file.try_lock() {
                    Ok(()) => {
                        let lock = Arc::new(StoreLock { _file: file });
                        stores.insert(key.clone(), Arc::downgrade(&lock));
                        return Ok((lock, key, seen));
                    }
                    Err(std::fs::TryLockError::WouldBlock) => false,
                    Err(std::fs::TryLockError::Error(error)) => return Err(storage_error(error)),
                }
            }
        };
        if std::time::Instant::now() >= deadline {
            let holder = if open_here {
                "this process already has"
            } else {
                "another process has"
            };
            return Err(ForgeError::StoreCustody(format!(
                "store_locked: {holder} {} open; one store writes a database, so share it by \
                 cloning its ForgeCore",
                path.display()
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

impl SqliteStore {
    pub(super) fn open(path: impl AsRef<Path>) -> Result<(Self, State)> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(storage_error)?;
        }
        let (lock, path, seen) = lock_store(&path)?;
        // Under the lock: open the store's one connection, creating the file
        // for a new store, and pin the file it is bound to. A file swapped in
        // since the identity was decided, or around the open, is refused.
        let (conn, identity, held) = open_bound(&path, seen)?;
        let store = Self {
            path,
            identity,
            conn: Arc::new(parking_lot::Mutex::new(conn)),
            _lock: lock,
            _held: held,
        };
        let conn = store.connect()?;
        apply_migrations(&conn)?;
        let mut state = load_state(&conn)?;
        // The deploy history is not part of the snapshot `load_state` reads; it
        // has its own append-only tables (see `storage::deployments`).
        deployments::load_deployments(&conn, &mut state)?;
        // Deploy rows keep the slug they were appended under; a later rename
        // or transfer re-keys only the repository, so follow its UUID.
        super::refresh_deployment_slugs(&mut state);
        let mut backfilled = backfill_missing_counters(&mut state);
        backfilled += super::backfill_default_branch_protections(&mut state);
        // A rotation recorded and never committed belongs to a process that is
        // gone; the provider may have consumed the secret (connection-v1 §3).
        backfilled += super::provider_connections::fence_unfinished_rotations(&mut state);
        drop(conn);
        if backfilled > 0 {
            store.persist(&state)?;
        }
        Ok((store, state))
    }

    pub(super) fn persist(&self, state: &State) -> Result<()> {
        let mut conn = self.connect()?;
        // Staged account/session data stays private to this connection's memory.
        conn.execute_batch("PRAGMA temp_store = MEMORY;")
            .map_err(storage_error)?;
        let tx = conn.transaction().map_err(storage_error)?;
        snapshot::create_tables(&tx)?;
        stage_state(&tx, state)?;
        snapshot::apply(&tx)?;
        tx.commit().map_err(storage_error)?;
        snapshot::drop_tables(&conn)?;
        Ok(())
    }

    /// Commit the merge snapshot and completed audit receipt in one transaction.
    pub(super) fn persist_with_audit(&self, state: &State, entry: &AuditEntry) -> Result<()> {
        let mut conn = self.connect()?;
        conn.execute_batch("PRAGMA temp_store = MEMORY;")
            .map_err(storage_error)?;
        let tx = conn.transaction().map_err(storage_error)?;
        snapshot::create_tables(&tx)?;
        stage_state(&tx, state)?;
        snapshot::apply(&tx)?;
        tx.execute("INSERT INTO forge_audit_log (id, occurred_at, actor, action, subject, phase, detail_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![entry.id, entry.occurred_at, entry.actor, entry.action, entry.subject, entry.phase, json(&entry.detail)?]).map_err(storage_error)?;
        snapshot::drop_tables(&tx)?;
        tx.commit().map_err(storage_error)?;
        Ok(())
    }

    /// Append one audit receipt through the store's connection.
    ///
    /// `forge_audit_log` is outside the explicitly State-owned table set. Its
    /// rows use this dedicated path and survive ordinary snapshot persistence.
    pub(super) fn append_audit(&self, entry: &AuditEntry) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            r#"
            INSERT INTO forge_audit_log (
              id, occurred_at, actor, action, subject, phase, detail_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                entry.id,
                entry.occurred_at,
                entry.actor,
                entry.action,
                entry.subject,
                entry.phase,
                json(&entry.detail)?,
            ],
        )
        .map_err(storage_error)?;
        Ok(())
    }

    /// All audit entries for one subject, oldest first.
    pub(super) fn list_audit(&self, subject: &str) -> Result<Vec<AuditEntry>> {
        let conn = self.connect()?;
        let mut stmt = conn
            .prepare(
                r#"
                SELECT id, occurred_at, actor, action, subject, phase, detail_json
                FROM forge_audit_log
                WHERE subject = ?1
                ORDER BY occurred_at, rowid
                "#,
            )
            .map_err(storage_error)?;
        let mut rows = stmt.query(params![subject]).map_err(storage_error)?;
        let mut entries = Vec::new();
        while let Some(row) = rows.next().map_err(storage_error)? {
            entries.push(AuditEntry {
                id: row.get(0).map_err(storage_error)?,
                occurred_at: row.get(1).map_err(storage_error)?,
                actor: row.get(2).map_err(storage_error)?,
                action: row.get(3).map_err(storage_error)?,
                subject: row.get(4).map_err(storage_error)?,
                phase: row.get(5).map_err(storage_error)?,
                detail: parse_json(row.get(6).map_err(storage_error)?)?,
            });
        }
        Ok(entries)
    }

    /// The store's one connection. Its path must still name the file the
    /// connection is bound to, with one link: writing on to a file no longer
    /// at its name would be lost at the next open.
    fn connect(&self) -> Result<parking_lot::MutexGuard<'_, Connection>> {
        let conn = self.conn.lock();
        file_identity(&self.path, Some(self.identity))?;
        Ok(conn)
    }
}

fn backfill_missing_counters(state: &mut State) -> usize {
    let repos: Vec<_> = state
        .repos
        .values()
        .map(|repo| (repo.owner.clone(), repo.name.clone()))
        .collect();
    let mut inserted = 0;
    for (owner, repo) in repos {
        let key = (owner.clone(), repo.clone());
        if state.counters.contains_key(&key) {
            continue;
        }
        state.counters.insert(
            key,
            Counters {
                issue: state
                    .issues
                    .keys()
                    .filter(|(issue_owner, issue_repo, _)| {
                        issue_owner == &owner && issue_repo == &repo
                    })
                    .map(|(_, _, number)| *number)
                    .max()
                    .unwrap_or(0),
                pull: state
                    .pulls
                    .keys()
                    .filter(|(pull_owner, pull_repo, _)| pull_owner == &owner && pull_repo == &repo)
                    .map(|(_, _, number)| *number)
                    .max()
                    .unwrap_or(0),
            },
        );
        inserted += 1;
    }
    inserted
}

pub(super) fn repo_id(
    repo_ids: &HashMap<(String, String), String>,
    owner: &str,
    repo: &str,
) -> Result<String> {
    repo_ids
        .get(&(owner.to_string(), repo.to_string()))
        .cloned()
        .ok_or_else(|| ForgeError::Storage(format!("missing repository row for {owner}/{repo}")))
}

fn storage_error(error: impl std::fmt::Display) -> ForgeError {
    ForgeError::Storage(error.to_string())
}
