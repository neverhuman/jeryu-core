//! Registration, old-schema upgrade, and rollback coverage for the SQLite
//! migration chain in `migrations.rs`.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

use super::*;

const MIGRATIONS_SOURCE: &str = include_str!("migrations.rs");

const ROLLBACKS: &[(&str, &str)] = &[
    (
        "0005_repository_family.sql",
        include_str!("../../../../../db/rollbacks/0005_repository_family.sql"),
    ),
    (
        "0006_forge_audit_log.sql",
        include_str!("../../../../../db/rollbacks/0006_forge_audit_log.sql"),
    ),
    (
        "0007_jankurai_scores.sql",
        include_str!("../../../../../db/rollbacks/0007_jankurai_scores.sql"),
    ),
    (
        "0008_user_auth_access.sql",
        include_str!("../../../../../db/rollbacks/0008_user_auth_access.sql"),
    ),
    (
        "0009_repository_transfers.sql",
        include_str!("../../../../../db/rollbacks/0009_repository_transfers.sql"),
    ),
    (
        "0011_review_head_sha.sql",
        include_str!("../../../../../db/rollbacks/0011_review_head_sha.sql"),
    ),
    (
        "0012_deployments.sql",
        include_str!("../../../../../db/rollbacks/0012_deployments.sql"),
    ),
    (
        "0013_repository_pushed_at.sql",
        include_str!("../../../../../db/rollbacks/0013_repository_pushed_at.sql"),
    ),
    (
        "0014_repository_default_branch_protection_opt_out.sql",
        include_str!(
            "../../../../../db/rollbacks/0014_repository_default_branch_protection_opt_out.sql"
        ),
    ),
    (
        "0015_repository_alias_origin.sql",
        include_str!("../../../../../db/rollbacks/0015_repository_alias_origin.sql"),
    ),
    (
        "0016_review_dismissal_target.sql",
        include_str!("../../../../../db/rollbacks/0016_review_dismissal_target.sql"),
    ),
];

fn db_dir(kind: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../db")
        .join(kind)
}

fn sql_files(kind: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(db_dir(kind))
        .expect("read db dir")
        .map(|entry| {
            entry
                .expect("dir entry")
                .file_name()
                .into_string()
                .expect("utf-8 name")
        })
        .filter(|name| name.ends_with(".sql"))
        .collect();
    names.sort();
    names
}

/// A migration file that exists on disk but is not embedded with
/// `include_str!` never runs; fail loudly instead.
#[test]
fn every_migration_file_is_registered() {
    let files = sql_files("migrations");
    assert!(!files.is_empty(), "no migrations found");
    for name in &files {
        let needle = format!("db/migrations/{name}\"");
        assert!(
            MIGRATIONS_SOURCE.contains(&needle),
            "db/migrations/{name} is not registered with include_str! in migrations.rs"
        );
    }
    let registered = MIGRATIONS_SOURCE.matches("include_str!(").count()
        - MIGRATIONS_SOURCE
            .matches("include_str!(\"migrations.rs\")")
            .count();
    assert_eq!(
        registered,
        files.len(),
        "migrations.rs embeds a migration that is not on disk"
    );
}

/// Each registered constant is also executed by `apply_migrations`.
#[test]
fn every_registered_migration_is_applied() {
    let body_start = MIGRATIONS_SOURCE
        .find("pub(super) fn apply_migrations(")
        .expect("apply_migrations");
    let body_end = MIGRATIONS_SOURCE
        .find("fn add_column_if_missing(")
        .expect("add_column_if_missing");
    let body = &MIGRATIONS_SOURCE[body_start..body_end];
    for name in sql_files("migrations") {
        let number = &name[..4];
        let constant = format!("MIGRATION_{number})");
        let guarded = format!("apply_migration_{number}(");
        assert!(
            body.contains(&constant) || body.contains(&guarded),
            "{name} is embedded but never applied"
        );
    }
}

#[test]
fn every_rollback_file_is_exercised() {
    let listed: Vec<&str> = ROLLBACKS.iter().map(|(name, _)| *name).collect();
    assert_eq!(sql_files("rollbacks"), listed);
}

fn run_script(conn: &Connection, sql: &str) {
    // Non-destructive rollbacks end in a notice SELECT, which
    // `execute_batch` rejects; step each statement instead.
    for statement in split_statements(sql) {
        let mut stmt = conn
            .prepare(&statement)
            .unwrap_or_else(|err| panic!("prepare `{statement}`: {err}"));
        let mut rows = stmt.raw_query();
        while rows.next().expect("step rollback statement").is_some() {}
    }
}

/// Splits on `;` outside single-quoted literals, dropping `--` comment lines.
fn split_statements(sql: &str) -> Vec<String> {
    let body: String = sql
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for ch in body.chars() {
        match ch {
            '\'' => {
                quoted = !quoted;
                current.push(ch);
            }
            ';' if !quoted => statements.push(std::mem::take(&mut current)),
            _ => current.push(ch),
        }
    }
    statements.push(current);
    statements
        .into_iter()
        .map(|statement| statement.trim().to_string())
        .filter(|statement| !statement.is_empty())
        .collect()
}

fn table_exists(conn: &Connection, table: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |row| row.get::<_, i64>(0),
    )
    .expect("inspect sqlite_master")
        == 1
}

fn schema_snapshot(conn: &Connection) -> Vec<(String, Option<String>)> {
    let mut stmt = conn
        .prepare("SELECT name, sql FROM sqlite_master ORDER BY type, name")
        .expect("prepare snapshot");
    stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("snapshot")
        .map(|row| row.expect("snapshot row"))
        .collect()
}

fn migrated() -> Connection {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    apply_migrations(&conn).expect("migrate");
    conn
}

/// Every rollback script executes against the current schema, has the
/// documented effect, and the chain rolls forward again afterwards.
#[test]
fn rollback_scripts_execute_and_roll_forward() {
    for (name, sql) in ROLLBACKS {
        let conn = migrated();
        let before = schema_snapshot(&conn);
        run_script(&conn, sql);
        match *name {
            "0005_repository_family.sql" => {
                assert!(!column_exists(&conn, "repositories", "family").expect("inspect"));
            }
            "0006_forge_audit_log.sql" => assert!(!table_exists(&conn, "forge_audit_log")),
            "0007_jankurai_scores.sql" => assert!(!table_exists(&conn, "jankurai_scores")),
            "0012_deployments.sql" => {
                assert!(!table_exists(&conn, "deployments"));
                assert!(!table_exists(&conn, "deployment_statuses"));
            }
            _ => assert_eq!(
                schema_snapshot(&conn),
                before,
                "{name} is documented as non-destructive"
            ),
        }
        apply_migrations(&conn).unwrap_or_else(|err| panic!("roll forward after {name}: {err}"));
        assert_eq!(
            schema_snapshot(&conn).len(),
            before.len(),
            "roll forward after {name} restores the schema objects"
        );
    }
}

/// Upgrading a pre-0005 database through the full chain keeps its rows and
/// seeds the family column.
#[test]
fn upgrade_from_pre_0005_schema() {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch(MIGRATION_0001).expect("0001");
    conn.execute_batch(MIGRATION_0002).expect("0002");
    conn.execute_batch(MIGRATION_0003).expect("0003");
    apply_migration_0004(&conn).expect("0004");
    conn.execute_batch(
        r#"
        INSERT INTO repositories (
          id, owner, name, full_name, private, default_branch, created_at, updated_at
        ) VALUES (
          '00000000-0000-0000-0000-000000000001', 'jeryu', 'veox-nht', 'jeryu/veox-nht', 1,
          'main', '2026-06-01T00:00:00Z', '2026-06-01T00:00:00Z'
        );
        "#,
    )
    .expect("insert repo");

    apply_migrations(&conn).expect("upgrade");
    let (family, protection_opt_out): (Option<String>, i64) = conn
        .query_row(
            "SELECT family, default_branch_protection_opt_out FROM repositories",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read upgraded repo");
    assert_eq!(family.as_deref(), Some("veox-split"));
    assert_eq!(protection_opt_out, 0);
}

/// The first 0008 shape had no `must_change_password` or `csrf_token`;
/// upgrading adds both with safe defaults and keeps existing credentials.
#[test]
fn upgrade_from_pre_0008_auth_schema() {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch(MIGRATION_0001).expect("0001");
    conn.execute_batch(MIGRATION_0002).expect("0002");
    conn.execute_batch(MIGRATION_0003).expect("0003");
    apply_migration_0004(&conn).expect("0004");
    apply_migration_0005(&conn).expect("0005");
    conn.execute_batch(MIGRATION_0006).expect("0006");
    conn.execute_batch(MIGRATION_0007).expect("0007");
    conn.execute_batch(
        r#"
        CREATE TABLE user_accounts (
          login TEXT PRIMARY KEY REFERENCES users(login) ON DELETE CASCADE,
          password_hash TEXT NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
          role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE web_sessions (
          id TEXT PRIMARY KEY,
          login TEXT NOT NULL REFERENCES user_accounts(login) ON DELETE CASCADE,
          token_hash TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
          created_at TEXT NOT NULL,
          expires_at TEXT NOT NULL
        );
        INSERT INTO users (login, user_json) VALUES ('alice', '{}');
        INSERT INTO user_accounts (login, password_hash, role, created_at, updated_at)
        VALUES ('alice', '$argon2id$v=19$stub', 'admin',
                '2026-06-01T00:00:00Z', '2026-06-01T00:00:00Z');
        INSERT INTO web_sessions (id, login, token_hash, created_at, expires_at)
        VALUES ('s1', 'alice', printf('%064d', 1),
                '2026-06-01T00:00:00Z', '2026-07-01T00:00:00Z');
        "#,
    )
    .expect("build pre-0008 auth shape");

    apply_migrations(&conn).expect("upgrade");
    let (must_change, password_hash): (i64, String) = conn
        .query_row(
            "SELECT must_change_password, password_hash FROM user_accounts WHERE login = 'alice'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read account");
    assert_eq!(must_change, 0);
    assert_eq!(password_hash, "$argon2id$v=19$stub");
    let csrf: String = conn
        .query_row(
            "SELECT csrf_token FROM web_sessions WHERE id = 's1'",
            [],
            |row| row.get(0),
        )
        .expect("read session");
    assert_eq!(csrf, "");
}

fn pre_0010_connection() -> Connection {
    let conn = Connection::open_in_memory().expect("open in-memory db");
    conn.execute_batch(MIGRATION_0001).expect("0001");
    conn.execute_batch(MIGRATION_0002).expect("0002");
    conn.execute_batch(MIGRATION_0003).expect("0003");
    apply_migration_0004(&conn).expect("0004");
    apply_migration_0005(&conn).expect("0005");
    conn.execute_batch(MIGRATION_0006).expect("0006");
    conn.execute_batch(MIGRATION_0007).expect("0007");
    apply_migration_0008(&conn).expect("0008");
    conn.execute_batch(MIGRATION_0009).expect("0009");
    conn
}

fn insert_account(conn: &Connection, login: &str) {
    conn.execute(
        "INSERT INTO users (login, user_json) VALUES (?1, '{}')",
        [login],
    )
    .expect("insert user");
    conn.execute(
        r#"
        INSERT INTO user_accounts (login, password_hash, role, created_at, updated_at)
        VALUES (?1, '$argon2id$v=19$stub', 'user',
                '2026-06-01T00:00:00Z', '2026-06-01T00:00:00Z')
        "#,
        [login],
    )
    .expect("insert account");
}

/// Pre-0010 accounts gain a display name equal to their login, an active
/// status, and a zero auth epoch.
#[test]
fn upgrade_from_pre_0010_account_schema() {
    let conn = pre_0010_connection();
    insert_account(&conn, "alice");

    apply_migrations(&conn).expect("upgrade");
    apply_migrations(&conn).expect("reapply");
    let (display_name, status, epoch): (String, String, i64) = conn
        .query_row(
            "SELECT display_name, status, auth_epoch FROM user_accounts WHERE login = 'alice'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read account");
    assert_eq!(display_name, "alice");
    assert_eq!(status, "active");
    assert_eq!(epoch, 0);
    assert!(table_exists(&conn, "account_invitations"));
}

/// 0010 refuses to upgrade a database holding a non-canonical login rather
/// than silently folding it.
#[test]
fn upgrade_from_pre_0010_rejects_non_canonical_login() {
    let conn = pre_0010_connection();
    insert_account(&conn, "Alice");

    let err = apply_migrations(&conn).expect_err("non-canonical login must block 0010");
    assert!(err.to_string().contains("not canonical"), "{err}");
    assert!(!column_exists(&conn, "user_accounts", "display_name").expect("inspect"));
}
