//! Password recovery tokens (migration 0025): State-owned rows holding only
//! the SHA-256 of each recovery secret.

use rusqlite::{Connection, params};

use super::codec::{optional_time, parse_optional_time, parse_time, time};
use super::{State, storage_error};
use crate::core::password_recovery::PasswordRecoveryRecord;
use crate::errors::Result;

pub(super) fn stage_password_recovery_tokens(conn: &Connection, state: &State) -> Result<()> {
    for record in state.password_recoveries.values() {
        conn.execute(
            r#"
            INSERT INTO temp.password_recovery_tokens (
              token_id, login, secret_hash, auth_epoch, created_at, expires_at,
              consumed_at, attempt_count
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                record.token_id,
                record.login,
                record.secret_hash,
                i64::try_from(record.auth_epoch).map_err(storage_error)?,
                time(record.created_at),
                time(record.expires_at),
                optional_time(record.consumed_at),
                i64::from(record.attempt_count),
            ],
        )
        .map_err(storage_error)?;
    }
    Ok(())
}

pub(super) fn load_password_recovery_tokens(conn: &Connection, state: &mut State) -> Result<()> {
    let mut stmt = conn
        .prepare(
            "SELECT token_id, login, secret_hash, auth_epoch, created_at, expires_at, \
             consumed_at, attempt_count FROM password_recovery_tokens",
        )
        .map_err(storage_error)?;
    let mut rows = stmt.query([]).map_err(storage_error)?;
    while let Some(row) = rows.next().map_err(storage_error)? {
        let auth_epoch: i64 = row.get(3).map_err(storage_error)?;
        let attempt_count: i64 = row.get(7).map_err(storage_error)?;
        let record = PasswordRecoveryRecord {
            token_id: row.get(0).map_err(storage_error)?,
            login: row.get(1).map_err(storage_error)?,
            secret_hash: row.get(2).map_err(storage_error)?,
            auth_epoch: u64::try_from(auth_epoch).map_err(storage_error)?,
            created_at: parse_time(row.get(4).map_err(storage_error)?)?,
            expires_at: parse_time(row.get(5).map_err(storage_error)?)?,
            consumed_at: parse_optional_time(row.get(6).map_err(storage_error)?)?,
            attempt_count: u32::try_from(attempt_count).map_err(storage_error)?,
        };
        state
            .password_recoveries
            .insert(record.token_id.clone(), record);
    }
    Ok(())
}
