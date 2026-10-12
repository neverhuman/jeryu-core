//! Agent tokens (migration 0020): State-owned rows holding only the SHA-256 of
//! each token.

use rusqlite::{Connection, params};

use super::codec::{optional_time, parse_optional_time, parse_time, parse_uuid, time};
use super::{State, storage_error};
use crate::core::bot_tokens::BotAccessTokenRecord;
use crate::errors::Result;

pub(super) fn stage_bot_access_tokens(conn: &Connection, state: &State) -> Result<()> {
    for record in state.bot_access_tokens.values() {
        conn.execute(
            r#"
            INSERT INTO temp.bot_access_tokens (
              token_hash, token_id, bot_id, key_id, generation, label, created_at,
              expires_at, last_used_at, revoked_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            params![
                record.token_hash,
                record.token_id,
                record.bot_id.to_string(),
                record.key_id,
                i64::try_from(record.generation).map_err(storage_error)?,
                record.label,
                time(record.created_at),
                time(record.expires_at),
                optional_time(record.last_used_at),
                optional_time(record.revoked_at),
            ],
        )
        .map_err(storage_error)?;
    }
    Ok(())
}

pub(super) fn load_bot_access_tokens(conn: &Connection, state: &mut State) -> Result<()> {
    let mut stmt = conn
        .prepare(
            "SELECT token_hash, token_id, bot_id, key_id, generation, label, created_at, \
             expires_at, last_used_at, revoked_at FROM bot_access_tokens",
        )
        .map_err(storage_error)?;
    let mut rows = stmt.query([]).map_err(storage_error)?;
    while let Some(row) = rows.next().map_err(storage_error)? {
        let generation: i64 = row.get(4).map_err(storage_error)?;
        let record = BotAccessTokenRecord {
            token_hash: row.get(0).map_err(storage_error)?,
            token_id: row.get(1).map_err(storage_error)?,
            bot_id: parse_uuid(row.get(2).map_err(storage_error)?)?,
            key_id: row.get(3).map_err(storage_error)?,
            generation: u64::try_from(generation).map_err(storage_error)?,
            label: row.get(5).map_err(storage_error)?,
            created_at: parse_time(row.get(6).map_err(storage_error)?)?,
            expires_at: parse_time(row.get(7).map_err(storage_error)?)?,
            last_used_at: parse_optional_time(row.get(8).map_err(storage_error)?)?,
            revoked_at: parse_optional_time(row.get(9).map_err(storage_error)?)?,
        };
        state
            .bot_access_tokens
            .insert(record.token_hash.clone(), record);
    }
    Ok(())
}
