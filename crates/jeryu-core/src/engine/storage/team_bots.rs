//! Team bots' own repository grants (migration 0023): State-owned rows keyed
//! by bot id and repository id.

use rusqlite::{Connection, params};

use super::codec::{from_text, parse_time, parse_uuid, text, time};
use super::{State, storage_error};
use crate::core::team_bots::BotRepoGrantRecord;
use crate::errors::Result;

pub(super) fn stage_bot_repo_grants(conn: &Connection, state: &State) -> Result<()> {
    for grant in state.bot_repo_grants.values() {
        conn.execute(
            r#"
            INSERT INTO temp.bot_repo_grants (
              bot_id, repo_id, access, granted_by, granted_at
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![
                grant.bot_id.to_string(),
                grant.repo_id.to_string(),
                text(&grant.access)?,
                grant.granted_by,
                time(grant.granted_at),
            ],
        )
        .map_err(storage_error)?;
    }
    Ok(())
}

pub(super) fn load_bot_repo_grants(conn: &Connection, state: &mut State) -> Result<()> {
    let mut stmt = conn
        .prepare("SELECT bot_id, repo_id, access, granted_by, granted_at FROM bot_repo_grants")
        .map_err(storage_error)?;
    let mut rows = stmt.query([]).map_err(storage_error)?;
    while let Some(row) = rows.next().map_err(storage_error)? {
        let grant = BotRepoGrantRecord {
            bot_id: parse_uuid(row.get(0).map_err(storage_error)?)?,
            repo_id: parse_uuid(row.get(1).map_err(storage_error)?)?,
            access: from_text(row.get(2).map_err(storage_error)?)?,
            granted_by: row.get(3).map_err(storage_error)?,
            granted_at: parse_time(row.get(4).map_err(storage_error)?)?,
        };
        state
            .bot_repo_grants
            .insert((grant.bot_id, grant.repo_id), grant);
    }
    Ok(())
}
